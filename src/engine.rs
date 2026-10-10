//! Per-worker TCP engine: connection slots, their deadlines, the free list, the lifecycle
//! and the statistics the worker reports.
//!
//! This is the aggregate the worker loop drives. It owns no native resource: every
//! decision is returned as a `Step` that the loop carries out through RIO, which keeps
//! the whole echo progression testable without a network.

use crate::connection::{Connection, ConnectionStep};
use crate::types::{EngineOperation, Statistics, WorkerLifecycle, WorkerPhase, worker_may_exit};
use crate::worker::timer::TimerHeap;

/// One decision the native layer has to carry out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Receive {
        index: u32,
        deadline: u64,
    },
    Send {
        index: u32,
        offset: u32,
        length: u32,
        deadline: u64,
    },
    /// Close the socket; the slot still waits for the operations in flight.
    Close {
        index: u32,
    },
    /// Close the socket if needed and recycle the slot.
    Release {
        index: u32,
    },
}

pub struct TcpEngine {
    connections: Vec<Connection>,
    timers: TimerHeap,
    /// Free slot stack: a released index is pushed here and popped by the next handoff.
    free_indices: Vec<u32>,
    timeout_milliseconds: u64,
    active_connections: u32,
    rio_outstanding: u32,
    pub statistics: Statistics,
    pub phase: WorkerPhase,
    pub stopping: bool,
    pub admission_closed: bool,
    pub notification_armed: bool,
    /// Set when a deadline could not be scheduled. Dropping a deadline would turn a
    /// timeout into a hang, so the worker fails fast instead.
    pub fatal: bool,
}

impl TcpEngine {
    pub fn new(slot_count: u32, timeout_milliseconds: u64) -> Self {
        let count = slot_count as usize;
        // The baseline fills the stack so that the lowest free slot is handed out first.
        let free_indices: Vec<u32> = (0..slot_count).rev().collect();
        Self {
            connections: (0..slot_count).map(Connection::new).collect(),
            timers: TimerHeap::new(count),
            free_indices,
            timeout_milliseconds,
            active_connections: 0,
            rio_outstanding: 0,
            statistics: Statistics::default(),
            phase: WorkerPhase::Starting,
            stopping: false,
            admission_closed: false,
            notification_armed: false,
            fatal: false,
        }
    }

    pub fn slot_count(&self) -> u32 {
        self.connections.len() as u32
    }

    pub fn free_count(&self) -> u32 {
        self.free_indices.len() as u32
    }

    pub fn active_count(&self) -> u32 {
        self.active_connections
    }

    pub fn outstanding(&self) -> u32 {
        self.rio_outstanding
    }

    pub fn connection(&self, index: u32) -> Option<&Connection> {
        self.connections.get(index as usize)
    }

    pub fn timers(&self) -> &TimerHeap {
        &self.timers
    }

    pub fn waiting_milliseconds(&self, now: u64) -> u32 {
        self.timers.wait_milliseconds(now)
    }

    /// Takes the next free slot for an accepted socket. A stopping worker refuses new
    /// sockets, which is how admission is drained without racing the acceptor.
    pub fn take_slot(&mut self) -> Option<u32> {
        if self.stopping {
            return None;
        }
        self.free_indices.pop()
    }

    /// True while the worker is draining. A socket withdrawn then is a shutdown, not a capacity
    /// refusal, which is the distinction the reference makes when it counts rejected handoffs.
    pub fn is_stopping(&self) -> bool {
        self.stopping
    }

    /// Takes the next free slot and adopts it in one step. The worker takes and adopts
    /// separately because the request queue has to exist between the two, but tests and
    /// simple callers use the combined form.
    pub fn adopt_next(&mut self, now: u64) -> Option<Step> {
        let index = self.take_slot()?;
        self.admit(index, now)
    }

    /// Gives a taken slot back without adopting it (the request queue could not be made).
    pub fn return_slot(&mut self, index: u32) {
        if let Some(connection) = self.connections.get_mut(index as usize) {
            connection.state = crate::connection::ConnectionState::Idle;
        }
        self.free_indices.push(index);
    }

    /// Adopts a taken slot and arms its first receive.
    pub fn admit(&mut self, index: u32, now: u64) -> Option<Step> {
        let timeout = self.timeout_milliseconds;
        let deadline = {
            let connection = self.connections.get_mut(index as usize)?;
            connection.admit(now, timeout);
            connection.outstanding = connection.outstanding.saturating_add(1);
            connection.deadline
        };
        self.statistics.accepted = self.statistics.accepted.wrapping_add(1);
        self.active_connections += 1;
        self.rio_outstanding += 1;
        self.schedule(index, deadline);
        Some(Step::Receive { index, deadline })
    }

    /// A posted operation completed.
    pub fn on_completion(
        &mut self,
        index: u32,
        operation: EngineOperation,
        status: i32,
        bytes: u32,
        now: u64,
    ) -> Option<Step> {
        let timeout = self.timeout_milliseconds;
        if index as usize >= self.connections.len() {
            self.fatal = true;
            return None;
        }
        if !self.connections[index as usize].is_active() {
            // A completion for a slot that is not in flight means the completion queue and
            // the connection table disagree; the baseline fails fast on exactly this.
            self.fatal = true;
            return None;
        }
        let connection = &self.connections[index as usize];
        if connection.outstanding == 0 || self.rio_outstanding == 0 {
            self.fatal = true;
            return None;
        }
        let closing = connection.is_closing();
        self.rio_outstanding -= 1;
        self.statistics.completions = self.statistics.completions.wrapping_add(1);
        if status == crate::types::ERROR_SUCCESS {
            // Count the native transfer, including successful completions that arrive
            // during the final drain. `bytes` is successful echo sends.
            let transferred = u64::from(bytes);
            match operation {
                EngineOperation::Receive => {
                    self.statistics.receives = self.statistics.receives.wrapping_add(1);
                    self.statistics.received_bytes =
                        self.statistics.received_bytes.wrapping_add(transferred);
                }
                EngineOperation::Send => {
                    self.statistics.sends = self.statistics.sends.wrapping_add(1);
                    self.statistics.sent_bytes =
                        self.statistics.sent_bytes.wrapping_add(transferred);
                    self.statistics.bytes = self.statistics.bytes.wrapping_add(transferred);
                }
            }
        } else if !closing {
            // A failed completion is a connection failure. Counting it here is what makes a peer
            // that resets report one error per established connection, exactly as the reference
            // does: that many receives were outstanding when the connection went away.
            self.statistics.network_errors = self.statistics.network_errors.wrapping_add(1);
        }
        if !closing
            && status == crate::types::ERROR_SUCCESS
            && operation == EngineOperation::Send
            && (bytes == 0
                || connection.send_offset > connection.echo_bytes
                || bytes > connection.echo_bytes - connection.send_offset)
        {
            self.statistics.network_errors = self.statistics.network_errors.wrapping_add(1);
        }
        let step = {
            let connection = self.connections.get_mut(index as usize)?;
            connection.on_completion(operation, status, bytes, now, timeout)
        };
        self.apply(index, step)
    }

    /// A post was refused. Nothing was queued, so no completion will arrive and the
    /// connection can only be closed; this is the baseline's "failed post is a session
    /// failure, not a process failure" rule.
    pub fn on_post_failure(&mut self, index: u32) -> Option<Step> {
        // A post the queue refused is a connection failure, exactly as the reference counts it on
        // this path: the session ends, but the server itself stays healthy.
        self.statistics.network_errors = self.statistics.network_errors.wrapping_add(1);
        if self.rio_outstanding == 0 {
            self.fatal = true;
            return None;
        }
        self.rio_outstanding -= 1;
        let step = {
            let connection = self.connections.get_mut(index as usize)?;
            // The step that asked for this post already counted the operation, but RIO
            // never queued it, so the count has to come back down before the close.
            connection.outstanding = connection.outstanding.saturating_sub(1);
            connection.close()
        };
        self.apply(index, step)
    }

    /// Closes every connection whose deadline passed. Returns the releases that were
    /// possible immediately; the rest arrive with their completions.
    pub fn on_timeout(&mut self, now: u64, expired: &mut Vec<u32>) -> Vec<Step> {
        expired.clear();
        let count = self.timers.pop_expired(now, expired);
        let mut steps = Vec::new();
        for position in 0..count {
            let index = expired[position];
            let Some(connection) = self.connections.get_mut(index as usize) else {
                self.fatal = true;
                continue;
            };
            if !connection.is_active() || connection.is_closing() {
                continue;
            }
            let step = connection.close();
            if let Some(step) = self.apply(index, step) {
                steps.push(step);
            }
        }
        steps
    }

    /// Closes admission for this worker: no new socket is adopted and every live
    /// connection starts closing.
    pub fn begin_stop(&mut self) -> Vec<Step> {
        if self.stopping {
            return Vec::new();
        }
        self.stopping = true;
        self.phase = WorkerPhase::Draining;
        let mut steps = Vec::new();
        for index in 0..self.connections.len() as u32 {
            let is_active = self.connections[index as usize].is_active();
            if !is_active {
                continue;
            }
            let step = self.connections[index as usize].close();
            if let Some(step) = self.apply(index, step) {
                steps.push(step);
            }
        }
        steps
    }

    /// The admission barrier reached this worker.
    pub fn close_admission(&mut self) {
        self.admission_closed = true;
        if self.phase < WorkerPhase::AdmissionClosed {
            self.phase = WorkerPhase::AdmissionClosed;
        }
    }

    pub fn lifecycle(&self) -> WorkerLifecycle {
        WorkerLifecycle {
            phase: self.phase,
            active_connections: self.active_count(),
            pending_handoffs: 0,
            rio_outstanding: self.outstanding(),
            notification_armed: self.notification_armed,
        }
    }

    /// A worker exits only after the admission barrier and a full drain, and only when its
    /// timer heap is empty: a leftover deadline would mean an unclosed connection.
    pub fn may_exit(&self) -> bool {
        worker_may_exit(&self.lifecycle()) && self.timers.is_empty()
    }

    fn apply(&mut self, index: u32, step: ConnectionStep) -> Option<Step> {
        match step {
            ConnectionStep::None => {
                // The operation in flight keeps its deadline.
                None
            }
            ConnectionStep::Receive => {
                let deadline = {
                    let connection = self.connections.get_mut(index as usize)?;
                    connection.outstanding = connection.outstanding.saturating_add(1);
                    connection.deadline
                };
                self.rio_outstanding += 1;
                self.schedule(index, deadline);
                Some(Step::Receive { index, deadline })
            }
            ConnectionStep::Send { offset, length } => {
                let deadline = {
                    let connection = self.connections.get_mut(index as usize)?;
                    connection.outstanding = connection.outstanding.saturating_add(1);
                    connection.deadline
                };
                self.rio_outstanding += 1;
                self.schedule(index, deadline);
                Some(Step::Send {
                    index,
                    offset,
                    length,
                    deadline,
                })
            }
            ConnectionStep::Close => {
                self.timers.remove(index);
                Some(Step::Close { index })
            }
            ConnectionStep::CloseAndRelease => {
                self.timers.remove(index);
                if let Some(connection) = self.connections.get_mut(index as usize) {
                    connection.state = crate::connection::ConnectionState::Idle;
                }
                self.free_indices.push(index);
                self.active_connections -= 1;
                Some(Step::Release { index })
            }
        }
    }

    fn schedule(&mut self, index: u32, deadline: u64) {
        if !self.timers.insert_or_update(deadline, index) {
            self.fatal = true;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnectionState;
    use crate::types::Protocol;

    fn engine(slots: u32) -> TcpEngine {
        let mut engine = TcpEngine::new(slots, 5_000);
        engine.close_admission();
        engine.phase = WorkerPhase::Running;
        engine
    }

    #[test]
    fn an_accepted_connection_echoes_and_returns_to_receive() {
        let mut engine = engine(2);
        let index = engine.take_slot().expect("a free slot");
        assert_eq!(index, 0);
        assert_eq!(
            engine.admit(index, 0),
            Some(Step::Receive {
                index: 0,
                deadline: 5_000
            })
        );
        assert_eq!(engine.active_count(), 1);
        assert_eq!(engine.free_count(), 1);
        assert_eq!(engine.statistics.accepted, 1);
        assert_eq!(engine.connection(0).unwrap().outstanding, 1);

        assert_eq!(
            engine.on_completion(0, EngineOperation::Receive, 0, 512, 10),
            Some(Step::Send {
                index: 0,
                offset: 0,
                length: 512,
                deadline: 5_010
            })
        );
        assert_eq!(
            engine.connection(0).unwrap().state,
            ConnectionState::Sending
        );

        assert_eq!(
            engine.on_completion(0, EngineOperation::Send, 0, 512, 20),
            Some(Step::Receive {
                index: 0,
                deadline: 5_020
            })
        );
        assert_eq!(
            engine.connection(0).unwrap().state,
            ConnectionState::Receiving
        );
        assert_eq!(engine.statistics.completions, 2);
        assert_eq!(engine.statistics.receives, 1);
        assert_eq!(engine.statistics.sends, 1);
        assert_eq!(engine.statistics.bytes, 512);
        assert_eq!(engine.statistics.accepted, 1);
    }

    #[test]
    fn timeouts_close_and_the_drain_releases_the_slot() {
        let mut engine = engine(2);
        engine.adopt_next(0).unwrap();
        engine.adopt_next(1_000).unwrap();
        // Slot 0 expires at 5_000, slot 1 at 6_000.
        assert_eq!(engine.waiting_milliseconds(0), 5_000);

        let mut expired = Vec::new();
        assert!(engine.on_timeout(4_999, &mut expired).is_empty());
        // The socket closes as soon as the deadline passes, even though the receive that
        // is still in flight keeps the slot busy.
        assert_eq!(
            engine.on_timeout(5_000, &mut expired),
            vec![Step::Close { index: 0 }]
        );
        assert_eq!(expired, vec![0]);
        // The connection is closing, but its receive is still in flight.
        assert_eq!(
            engine.connection(0).unwrap().state,
            ConnectionState::Closing
        );
        assert_eq!(engine.active_count(), 2);
        assert!(!engine.timers().contains(0));

        // The cancelled receive completes; only then is the slot released.
        assert_eq!(
            engine.on_completion(0, EngineOperation::Receive, 1_234, 0, 5_000),
            Some(Step::Release { index: 0 })
        );
        assert_eq!(engine.connection(0).unwrap().state, ConnectionState::Idle);
        assert_eq!(engine.free_count(), 1);
        assert_eq!(engine.active_count(), 1);
        // A second completion for the released connection is refused.
        assert_eq!(
            engine.on_completion(0, EngineOperation::Receive, 0, 8, 5_100),
            None
        );
    }

    #[test]
    fn stopping_drains_every_connection_and_closes_admission() {
        let mut engine = engine(2);
        engine.adopt_next(0).unwrap();
        engine.adopt_next(0).unwrap();
        assert_eq!(engine.active_count(), 2);
        assert_eq!(engine.lifecycle().rio_outstanding, 2);
        assert!(!engine.may_exit());

        assert_eq!(
            engine.begin_stop(),
            vec![Step::Close { index: 0 }, Step::Close { index: 1 }]
        );
        assert!(engine.take_slot().is_none());
        assert_eq!(
            engine.connection(0).unwrap().state,
            ConnectionState::Closing
        );
        assert_eq!(
            engine.connection(1).unwrap().state,
            ConnectionState::Closing
        );

        engine.close_admission();
        assert!(!engine.may_exit());
        engine.on_completion(0, EngineOperation::Receive, 1_234, 0, 10);
        assert_eq!(engine.lifecycle().rio_outstanding, 1);
        assert!(!worker_may_exit(&engine.lifecycle()));
        engine.on_completion(1, EngineOperation::Receive, 1_234, 0, 10);
        assert_eq!(engine.active_count(), 0);
        assert_eq!(engine.lifecycle().rio_outstanding, 0);
        assert_eq!(engine.free_count(), 2);
        assert!(engine.may_exit());
        assert!(engine.timers().is_empty());
    }

    #[test]
    fn slots_are_handed_out_lowest_first_and_reused_after_release() {
        let mut engine = engine(3);
        assert_eq!(engine.take_slot(), Some(0));
        assert_eq!(engine.take_slot(), Some(1));
        engine.admit(0, 0);
        engine.admit(1, 0);
        assert_eq!(engine.take_slot(), Some(2));
        assert_eq!(engine.take_slot(), None);

        // Releasing the lowest slot makes it the next one handed out.
        engine.on_completion(0, EngineOperation::Receive, 1_234, 0, 0);
        assert_eq!(engine.take_slot(), Some(0));
        assert_eq!(
            engine.admit(0, 0),
            Some(Step::Receive {
                index: 0,
                deadline: 5_000
            })
        );
        assert_eq!(engine.statistics.accepted, 3);
    }

    #[test]
    fn a_refused_post_closes_without_waiting_for_a_completion() {
        let mut engine = engine(1);
        engine.adopt_next(0).unwrap();
        assert_eq!(engine.on_post_failure(0), Some(Step::Release { index: 0 }));
        assert_eq!(engine.active_count(), 0);
        assert_eq!(engine.free_count(), 1);
        // A completion for the released slot is an invariant violation, not a crash.
        assert_eq!(
            engine.on_completion(0, EngineOperation::Receive, 0, 64, 1),
            None
        );
        assert!(engine.fatal);
        // The slot is still reusable once the record was reset.
        let mut fresh = TcpEngine::new(1, 5_000);
        fresh.close_admission();
        fresh.phase = WorkerPhase::Running;
        let index = fresh.take_slot().unwrap();
        fresh.admit(index, 0);
        assert!(
            fresh
                .on_completion(index, EngineOperation::Receive, 0, 64, 1)
                .is_some()
        );
    }

    #[test]
    fn cancellation_errors_are_ignored_only_after_closing() {
        let mut stopped = engine(1);
        stopped.adopt_next(0).unwrap();
        stopped.begin_stop();
        stopped.on_completion(0, EngineOperation::Receive, 10_054, 0, 1);
        assert_eq!(stopped.statistics.network_errors, 0);
        let mut live = engine(1);
        live.adopt_next(0).unwrap();
        live.on_completion(0, EngineOperation::Receive, 995, 0, 1);
        assert_eq!(live.statistics.network_errors, 1);
    }

    #[test]
    fn invalid_send_progress_counts_a_network_error_and_releases() {
        let mut engine = engine(1);
        engine.adopt_next(0).unwrap();
        engine.on_completion(0, EngineOperation::Receive, 0, 4, 1);
        assert_eq!(
            engine.on_completion(0, EngineOperation::Send, 0, 5, 2),
            Some(Step::Release { index: 0 })
        );
        assert_eq!(engine.statistics.network_errors, 1);
        assert_eq!(engine.statistics.sent_bytes, 5);
        assert_eq!(engine.outstanding(), 0);
    }

    #[test]
    fn the_final_line_matches_the_worker_counters() {
        let mut engine = engine(1);
        engine.adopt_next(0).unwrap();
        engine.on_completion(0, EngineOperation::Receive, 0, 8, 0);
        engine.on_completion(0, EngineOperation::Send, 0, 8, 0);
        let final_line =
            engine
                .statistics
                .final_line(Protocol::Tcp, 1_000, 1, engine.active_count());
        assert!(final_line.starts_with(
            "final protocol=tcp elapsed_ms=1000 workers=1 accepted=1 active=0 outstanding=1 "
        ));
        // One 8-byte receive and one 8-byte send: native direction counters and echo-send total
        // all advance by the transfer the test posted.
        assert!(final_line.contains(
            " received_bytes=8 sent_bytes=8 bytes=8 network_errors=0 rejected=0 MiB_per_sec="
        ));
    }
}
