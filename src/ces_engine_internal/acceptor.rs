//! Acceptor state machine: the AcceptEx operation table and the handoff policy.
//!
//! AcceptEx operations are pre-posted and recycled. A successful accept transfers its
//! socket to a worker (round robin) and waits for that worker's acknowledgement before the
//! slot is posted again, so the operation table is a fixed-size resource that never grows
//! and never hands the same socket to two workers.

use core::sync::atomic::{AtomicUsize, Ordering};

use windows::Win32::minwinbase::OVERLAPPED;
use windows::Win32::winsock2::{INVALID_SOCKET, SOCKET};

use crate::types::{ACCEPT_OPERATION_BYTES, ERROR_INVALID_DATA, ERROR_NETNAME_DELETED};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptState {
    /// Free and not posted.
    Idle,
    /// AcceptEx is in flight on this slot.
    Posted,
    /// The socket was handed to a worker and is waiting to be acknowledged.
    Transit,
}

/// What the acceptor thread must do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptAction {
    /// AcceptEx completed: transfer the socket and post the handoff to this worker.
    Handoff { index: u32, worker: u32 },
    /// Post AcceptEx on this slot.
    Repost { index: u32 },
    /// Admission is broken and the acceptor stops.
    Fatal { index: u32, error: u32 },
    /// Nothing to do; the slot stays idle.
    None,
}

/// A peer that resets before AcceptEx completes aborts that single incoming connection;
/// ERROR_NETNAME_DELETED is the documented outcome for it. Everything else keeps the
/// baseline's fatal classification so real listener or IOCP damage stops admission instead
/// of being retried forever.
pub fn accept_error_is_recoverable(error: u32) -> bool {
    error == ERROR_NETNAME_DELETED
}

pub struct AcceptorCore {
    states: Vec<AcceptState>,
    worker_count: u32,
    next_worker: u32,
    pub stopping: bool,
}

impl AcceptorCore {
    pub fn new(operation_count: u32, worker_count: u32) -> Self {
        Self {
            states: vec![AcceptState::Idle; operation_count as usize],
            worker_count,
            next_worker: 0,
            stopping: false,
        }
    }

    pub fn operation_count(&self) -> u32 {
        self.states.len() as u32
    }

    pub fn state(&self, index: u32) -> Option<AcceptState> {
        self.states.get(index as usize).copied()
    }

    /// True while at least one operation is posted or in transit; the acceptor thread runs
    /// until this is false.
    pub fn has_live(&self) -> bool {
        self.states.iter().any(|state| *state != AcceptState::Idle)
    }

    pub fn transiting(&self) -> u32 {
        self.states.iter().filter(|state| **state == AcceptState::Transit).count() as u32
    }

    /// Every slot that must be posted when the acceptor starts.
    pub fn initial_posts(&self) -> Vec<u32> {
        (0..self.states.len() as u32).collect()
    }

    /// The socket is on its way to a worker.
    pub fn mark_posted(&mut self, index: u32) {
        if let Some(state) = self.states.get_mut(index as usize) {
            *state = AcceptState::Posted;
        }
    }

    /// An AcceptEx completion. `completed` is what GetQueuedCompletionStatus reported;
    /// `error` is the last error of the port when it failed.
    pub fn on_completion(&mut self, index: u32, completed: bool, error: u32) -> AcceptAction {
        let Some(state) = self.states.get_mut(index as usize) else {
            return AcceptAction::Fatal { index, error: ERROR_INVALID_DATA as u32 };
        };
        if *state != AcceptState::Posted {
            // A completion for a slot that was never posted means the port is delivering
            // packets this acceptor does not own.
            return AcceptAction::Fatal { index, error: ERROR_INVALID_DATA as u32 };
        }
        if !completed {
            *state = AcceptState::Idle;
            if self.stopping {
                return AcceptAction::None;
            }
            if accept_error_is_recoverable(error) {
                // Connection-level abort: the listener is healthy, so this slot is reused.
                return AcceptAction::Repost { index };
            }
            return AcceptAction::Fatal { index, error };
        }
        if self.worker_count == 0 {
            return AcceptAction::Fatal { index, error: ERROR_INVALID_DATA as u32 };
        }
        let worker = self.next_worker % self.worker_count;
        self.next_worker = self.next_worker.wrapping_add(1);
        *state = AcceptState::Transit;
        AcceptAction::Handoff { index, worker }
    }

    /// The worker acknowledged the handoff. Whatever socket is left in the slot belongs to
    /// the acceptor again and must be closed before the slot is reused.
    pub fn on_ack(&mut self, index: u32) -> AcceptAction {
        let Some(state) = self.states.get_mut(index as usize) else {
            return AcceptAction::Fatal { index, error: ERROR_INVALID_DATA as u32 };
        };
        if *state != AcceptState::Transit {
            return AcceptAction::Fatal { index, error: ERROR_INVALID_DATA as u32 };
        }
        *state = AcceptState::Idle;
        if self.stopping {
            return AcceptAction::None;
        }
        AcceptAction::Repost { index }
    }

    /// Stops admission. Posted operations are unposted by the caller (their sockets are
    /// closed), and handoffs already in transit are awaited so no worker is left with a
    /// socket whose owner disappeared.
    pub fn stop(&mut self) {
        self.stopping = true;
    }

    /// Returns a slot to Idle after a handoff could not be completed. Without this a slot
    /// whose socket disappeared before the handoff would stay in transit forever, and the
    /// acceptor would wait for an acknowledgement that no worker can send.
    pub fn abort_handoff(&mut self, index: u32) -> bool {
        match self.states.get_mut(index as usize) {
            Some(state) if *state != AcceptState::Idle => {
                *state = AcceptState::Idle;
                true
            }
            _ => false,
        }
    }
}


/// The native record AcceptEx completes into. The OVERLAPPED must stay first: the IOCP
/// hands its address back and the acceptor recovers the record from that address alone.
/// The socket field is atomic because ownership crosses threads: the acceptor posts it,
/// a worker takes it with a single swap, and whoever still holds it closes it.
#[repr(C)]
pub struct AcceptOperation {
    pub overlapped: OVERLAPPED,
    pub socket: AtomicUsize,
    pub index: u32,
    pub owner: usize,
}

/// The operation table shared between the acceptor thread (which posts and recycles slots)
/// and the workers (which take the transferred socket and acknowledge the handoff).
///
/// The table itself is never mutated: only the per-slot socket field is, through an atomic
/// swap. The acceptor stores a socket before the handoff packet and clears any socket that
/// a worker left behind; the worker takes the socket it was handed.
pub struct AcceptTable {
    operations: Box<[AcceptOperation]>,
    addresses: Box<[u8]>,
    identity: usize,
    port: crate::native::SendHandle,
}

// SAFETY: the table's records are allocated once and never move or grow; the only field two
// threads touch concurrently is the atomic socket. Everything else is written by the
// acceptor thread before it publishes the slot through an IOCP packet, and the IOCP packet
// pair (handoff, acknowledgement) orders those writes with the worker's reads.
unsafe impl Send for AcceptTable {}
unsafe impl Sync for AcceptTable {}

impl AcceptTable {
    pub fn new(operation_count: u32, port: crate::native::SendHandle) -> Self {
        let count = operation_count as usize;
        let mut operations: Box<[AcceptOperation]> = (0..operation_count)
            .map(|index| AcceptOperation {
                overlapped: OVERLAPPED::default(),
                socket: AtomicUsize::new(INVALID_SOCKET),
                index,
                owner: 0,
            })
            .collect();
        let identity = operations.as_ptr() as usize;
        for operation in operations.iter_mut() {
            operation.owner = identity;
        }
        let addresses = vec![0u8; count * ACCEPT_OPERATION_BYTES].into_boxed_slice();
        Self { operations, addresses, identity, port }
    }

    /// The acceptor's IOCP handle: the worker acknowledges a handoff by posting to it.
    pub fn port(&self) -> crate::native::SendHandle {
        self.port
    }

    pub fn count(&self) -> u32 {
        self.operations.len() as u32
    }

    pub fn operation(&self, index: u32) -> Option<&AcceptOperation> {
        self.operations.get(index as usize)
    }

    /// The completion identity of a slot: the address AcceptEx was given.
    pub fn overlapped_ptr(&self, index: u32) -> *mut OVERLAPPED {
        match self.operations.get(index as usize) {
            Some(operation) => &operation.overlapped as *const OVERLAPPED as *mut OVERLAPPED,
            None => core::ptr::null_mut(),
        }
    }

    /// The output buffer AcceptEx writes the two addresses into.
    pub fn address_ptr(&self, index: u32) -> *mut core::ffi::c_void {
        let offset = index as usize * ACCEPT_OPERATION_BYTES;
        match self.addresses.get(offset..offset + ACCEPT_OPERATION_BYTES) {
            Some(_) => unsafe { self.addresses.as_ptr().add(offset) as *mut core::ffi::c_void },
            None => core::ptr::null_mut(),
        }
    }

    /// Recovers a slot from an address the IOCP handed back. The address has to fall inside
    /// this table, be aligned to a record and carry the table's own identity marker;
    /// anything else is a packet this table does not own.
    pub fn find(&self, address: usize) -> Option<&AcceptOperation> {
        let base = self.operations.as_ptr() as usize;
        let stride = core::mem::size_of::<AcceptOperation>();
        let extent = stride.checked_mul(self.operations.len())?;
        let end = base.checked_add(extent)?;
        if stride == 0 || address < base || address >= end || (address - base) % stride != 0 {
            return None;
        }
        let index = (address - base) / stride;
        let operation = self.operations.get(index)?;
        if operation.owner != self.identity || operation.index != index as u32 {
            return None;
        }
        Some(operation)
    }

    /// Takes the socket a handoff left in the slot. Returns None when the acceptor closed
    /// or reclaimed it first, which the worker treats as a handoff that was withdrawn.
    pub fn take_socket(&self, index: u32) -> Option<SOCKET> {
        let operation = self.operations.get(index as usize)?;
        let raw = operation.socket.swap(INVALID_SOCKET, Ordering::AcqRel);
        if raw == INVALID_SOCKET { None } else { Some(raw) }
    }

    /// Publishes the socket the acceptor just created for a posted operation.
    pub fn store_socket(&self, index: u32, socket: SOCKET) {
        if let Some(operation) = self.operations.get(index as usize) {
            operation.socket.store(socket, Ordering::Release);
        }
    }

    /// Clears a socket the acceptor reclaimed (a handoff the worker refused, or a peer that
    /// reset). The caller owns the returned value and closes it.
    pub fn clear_socket(&self, index: u32) -> Option<SOCKET> {
        let operation = self.operations.get(index as usize)?;
        let raw = operation.socket.swap(INVALID_SOCKET, Ordering::AcqRel);
        if raw == INVALID_SOCKET { None } else { Some(raw) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_is_posted_at_startup() {
        let core = AcceptorCore::new(4, 2);
        assert_eq!(core.operation_count(), 4);
        assert_eq!(core.initial_posts(), vec![0, 1, 2, 3]);
        assert!(!core.has_live());
    }

    #[test]
    fn accepted_sockets_are_handed_out_round_robin() {
        let mut core = AcceptorCore::new(2, 3);
        for index in 0..2 {
            core.mark_posted(index);
        }
        assert_eq!(core.on_completion(0, true, 0), AcceptAction::Handoff { index: 0, worker: 0 });
        assert_eq!(core.state(0), Some(AcceptState::Transit));
        assert_eq!(core.transiting(), 1);
        assert_eq!(core.on_completion(1, true, 0), AcceptAction::Handoff { index: 1, worker: 1 });
        // An acknowledged handoff is reposted and continues the rotation.
        assert_eq!(core.on_ack(0), AcceptAction::Repost { index: 0 });
        core.mark_posted(0);
        assert_eq!(core.on_completion(0, true, 0), AcceptAction::Handoff { index: 0, worker: 2 });
        assert!(core.has_live());
    }

    #[test]
    fn a_reset_peer_is_recoverable_and_a_real_error_is_not() {
        let mut core = AcceptorCore::new(1, 1);
        core.mark_posted(0);
        assert_eq!(
            core.on_completion(0, false, ERROR_NETNAME_DELETED),
            AcceptAction::Repost { index: 0 }
        );
        assert_eq!(core.state(0), Some(AcceptState::Idle));

        core.mark_posted(0);
        assert_eq!(core.on_completion(0, false, 87), AcceptAction::Fatal { index: 0, error: 87 });
        assert!(!accept_error_is_recoverable(87));
        assert!(accept_error_is_recoverable(ERROR_NETNAME_DELETED));
    }

    #[test]
    fn a_completion_for_an_unposted_slot_is_an_invariant_violation() {
        let mut core = AcceptorCore::new(2, 1);
        assert_eq!(
            core.on_completion(0, true, 0),
            AcceptAction::Fatal { index: 0, error: ERROR_INVALID_DATA as u32 }
        );
        assert_eq!(
            core.on_completion(9, true, 0),
            AcceptAction::Fatal { index: 9, error: ERROR_INVALID_DATA as u32 }
        );
        // An acknowledgement without a handoff is refused too.
        assert_eq!(
            core.on_ack(1),
            AcceptAction::Fatal { index: 1, error: ERROR_INVALID_DATA as u32 }
        );
    }

    #[test]
    fn an_aborted_handoff_returns_the_slot_and_clears_the_live_count() {
        let mut core = AcceptorCore::new(2, 1);
        core.mark_posted(0);
        assert_eq!(core.on_completion(0, true, 0), AcceptAction::Handoff { index: 0, worker: 0 });
        assert!(core.has_live());
        // The socket disappeared before the handoff completed: the slot must not stay in
        // transit waiting for an acknowledgement that cannot come.
        assert!(core.abort_handoff(0));
        assert!(!core.has_live());
        assert_eq!(core.state(0), Some(AcceptState::Idle));
        // Aborting an idle slot changes nothing.
        assert!(!core.abort_handoff(0));
        assert!(!core.abort_handoff(9));
    }

    #[test]
    fn stopping_waits_for_transiting_handoffs_and_posts_nothing_new() {
        let mut core = AcceptorCore::new(2, 1);
        core.mark_posted(0);
        core.mark_posted(1);
        assert_eq!(core.on_completion(0, true, 0), AcceptAction::Handoff { index: 0, worker: 0 });
        core.stop();
        assert!(core.has_live());
        assert_eq!(core.on_ack(0), AcceptAction::None);
        assert_eq!(core.state(0), Some(AcceptState::Idle));
        // A reset peer that completes after the stop is not reposted.
        assert_eq!(core.on_completion(1, false, ERROR_NETNAME_DELETED), AcceptAction::None);
        assert!(!core.has_live());
    }
}
