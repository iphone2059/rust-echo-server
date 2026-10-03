//! UDP engine core: the fixed-depth slot table that keeps a receive posted per slot,
//! turns each received datagram into a send back to its sender, and restores the receive
//! afterwards.
//!
//! Like the C++ baseline (ces_engine_run_udp) and the Swift port, a stop closes the socket
//! first to cancel the outstanding requests, keeps draining completions, and only then
//! releases the registered arena. The slot machine is native-free so the accounting is
//! unit-testable.

use crate::types::{
    udp_may_release, EngineOperation, Statistics, UdpPhase, ERROR_INVALID_DATA, ERROR_SUCCESS,
    WSAECONNRESET,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpSlot {
    pub index: u32,
    pub operation: EngineOperation,
    /// False while the completion for this slot is being handled.
    pub outstanding: bool,
    /// Length the next posted RIO_BUF must carry: the received byte count for a send, the
    /// configured datagram buffer size for a receive.
    pub payload_length: u32,
}

/// What the engine must do after a completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpAction {
    /// Post this slot again, using `slot.operation` and `slot.payload_length`.
    Post { index: u32 },
    /// The engine must stop: close the socket and drain the remaining requests.
    Fatal { index: u32, error: i32 },
    /// Nothing to post; the completion only drained the slot.
    None,
}

pub struct UdpEngine {
    slots: Vec<UdpSlot>,
    payload_bytes: u32,
    pub outstanding: u32,
    pub phase: UdpPhase,
    pub statistics: Statistics,
    pub closing: bool,
    pub failed: bool,
}

impl UdpEngine {
    pub fn new(depth: u32, payload_bytes: u32) -> Self {
        Self {
            slots: (0..depth)
                .map(|index| UdpSlot {
                    index,
                    operation: EngineOperation::Receive,
                    outstanding: false,
                    payload_length: payload_bytes,
                })
                .collect(),
            payload_bytes,
            outstanding: 0,
            phase: UdpPhase::Running,
            statistics: Statistics::default(),
            closing: false,
            failed: false,
        }
    }

    pub fn depth(&self) -> u32 {
        self.slots.len() as u32
    }

    pub fn slot(&self, index: u32) -> Option<&UdpSlot> {
        self.slots.get(index as usize)
    }

    /// Records that the initial receive (or a repost) was accepted by RIO.
    pub fn mark_posted(&mut self, index: u32) {
        if let Some(slot) = self.slots.get_mut(index as usize) {
            if !slot.outstanding {
                slot.outstanding = true;
                self.outstanding = self.outstanding.saturating_add(1);
            }
        }
    }

    /// A completion arrived for a slot. `status` is the RIO status and `bytes` the
    /// transferred byte count.
    pub fn on_completion(&mut self, index: u32, status: i32, bytes: u32) -> UdpAction {
        let Some(slot) = self.slots.get_mut(index as usize) else {
            return UdpAction::Fatal { index, error: ERROR_INVALID_DATA };
        };
        if !slot.outstanding || self.outstanding == 0 {
            return UdpAction::Fatal { index, error: ERROR_INVALID_DATA };
        }
        slot.outstanding = false;
        self.outstanding -= 1;
        self.statistics.completions = self.statistics.completions.wrapping_add(1);
        match slot.operation {
            EngineOperation::Receive => {
                self.statistics.receives = self.statistics.receives.wrapping_add(1);
            }
            EngineOperation::Send => {
                self.statistics.sends = self.statistics.sends.wrapping_add(1);
                if status == ERROR_SUCCESS {
                    self.statistics.bytes = self.statistics.bytes.wrapping_add(u64::from(bytes));
                }
            }
        }
        if self.closing {
            return UdpAction::None;
        }
        if status != ERROR_SUCCESS {
            if status == WSAECONNRESET {
                // A previous send produced an ICMP port-unreachable. The socket is still
                // usable, so the slot goes back to receiving.
                slot.operation = EngineOperation::Receive;
                slot.payload_length = self.payload_bytes;
            } else {
                self.failed = true;
                self.closing = true;
                self.phase = UdpPhase::Draining;
                return UdpAction::Fatal { index, error: status };
            }
        } else if slot.operation == EngineOperation::Receive {
            // Echo exactly what arrived, from the same slot.
            slot.payload_length = bytes;
            slot.operation = EngineOperation::Send;
        } else {
            // The echo is complete; the slot returns to its full datagram capacity.
            slot.payload_length = self.payload_bytes;
            slot.operation = EngineOperation::Receive;
        }
        UdpAction::Post { index }
    }

    /// The post for a slot was refused. The request never entered the queue, so the engine
    /// gives up on the socket and drains what is still in flight.
    pub fn on_post_failure(&mut self, index: u32) {
        if let Some(slot) = self.slots.get_mut(index as usize) {
            if slot.outstanding {
                // Defensive: a post that was counted and then refused must not stay counted.
                slot.outstanding = false;
                self.outstanding = self.outstanding.saturating_sub(1);
            }
        }
        self.failed = true;
        self.closing = true;
        self.phase = UdpPhase::Draining;
        let _ = index;
    }

    /// Stop: close the socket so the outstanding requests are cancelled, and keep draining.
    pub fn begin_drain(&mut self) {
        if !self.closing {
            self.closing = true;
        }
        if self.phase == UdpPhase::Running {
            self.phase = UdpPhase::Draining;
        }
    }

    pub fn stopped(&mut self) {
        self.phase = UdpPhase::Stopped;
    }

    /// Registered storage may be released once the engine stopped and every posted request
    /// has completed.
    pub fn may_release(&self) -> bool {
        udp_may_release(self.phase, self.outstanding)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn started(depth: u32) -> UdpEngine {
        let mut engine = UdpEngine::new(depth, 65_507);
        for index in 0..depth {
            engine.mark_posted(index);
        }
        engine
    }

    #[test]
    fn a_receive_becomes_a_send_of_exactly_the_received_bytes() {
        let mut engine = started(2);
        assert_eq!(engine.outstanding, 2);
        assert_eq!(engine.slot(0).unwrap().operation, EngineOperation::Receive);
        assert_eq!(engine.slot(0).unwrap().payload_length, 65_507);

        assert_eq!(engine.on_completion(0, 0, 1_200), UdpAction::Post { index: 0 });
        let slot = engine.slot(0).unwrap();
        assert_eq!(slot.operation, EngineOperation::Send);
        assert_eq!(slot.payload_length, 1_200);
        assert!(!slot.outstanding);
        assert_eq!(engine.outstanding, 1);
        assert_eq!(engine.statistics.receives, 1);
        engine.mark_posted(0);

        // The send completes; the slot returns to a full-capacity receive.
        assert_eq!(engine.on_completion(0, 0, 1_200), UdpAction::Post { index: 0 });
        let slot = engine.slot(0).unwrap();
        assert_eq!(slot.operation, EngineOperation::Receive);
        assert_eq!(slot.payload_length, 65_507);
        assert_eq!(engine.statistics.sends, 1);
        assert_eq!(engine.statistics.bytes, 1_200);
        assert_eq!(engine.statistics.completions, 2);
        assert_eq!(engine.outstanding, 1);
    }

    #[test]
    fn a_zero_length_datagram_is_echoed_as_a_zero_length_send() {
        let mut engine = started(1);
        assert_eq!(engine.on_completion(0, 0, 0), UdpAction::Post { index: 0 });
        assert_eq!(engine.slot(0).unwrap().operation, EngineOperation::Send);
        assert_eq!(engine.slot(0).unwrap().payload_length, 0);
    }

    #[test]
    fn a_connection_reset_returns_the_slot_to_receiving() {
        let mut engine = started(1);
        // A send failed with ICMP port-unreachable: the socket survives.
        engine.on_completion(0, 0, 64);
        engine.mark_posted(0);
        assert_eq!(
            engine.on_completion(0, WSAECONNRESET, 0),
            UdpAction::Post { index: 0 }
        );
        assert_eq!(engine.slot(0).unwrap().operation, EngineOperation::Receive);
        assert_eq!(engine.slot(0).unwrap().payload_length, 65_507);
        assert!(!engine.failed);
        assert!(!engine.closing);
        assert_eq!(engine.statistics.sends, 1);
    }

    #[test]
    fn a_fatal_status_starts_the_drain() {
        let mut engine = started(2);
        assert_eq!(
            engine.on_completion(0, 1_234, 0),
            UdpAction::Fatal { index: 0, error: 1_234 }
        );
        assert!(engine.failed);
        assert!(engine.closing);
        assert_eq!(engine.phase, UdpPhase::Draining);
        // The remaining completion only drains; nothing is reposted.
        assert_eq!(engine.on_completion(1, 0, 16), UdpAction::None);
    }

    #[test]
    fn storage_is_released_only_after_the_last_completion() {
        let mut engine = started(2);
        engine.begin_drain();
        assert!(!engine.may_release());
        engine.on_completion(0, 0, 8);
        engine.on_completion(1, 0, 8);
        assert_eq!(engine.outstanding, 0);
        assert!(!engine.may_release());
        engine.stopped();
        assert!(engine.may_release());
    }

    #[test]
    fn unknown_or_duplicate_completions_are_refused() {
        let mut engine = started(1);
        // A completion for a slot that is not outstanding.
        assert_eq!(
            engine.on_completion(0, 0, 8),
            UdpAction::Post { index: 0 }
        );
        assert_eq!(
            engine.on_completion(0, 0, 8),
            UdpAction::Fatal { index: 0, error: ERROR_INVALID_DATA }
        );
        // A completion for a slot that does not exist.
        assert_eq!(
            engine.on_completion(7, 0, 8),
            UdpAction::Fatal { index: 7, error: ERROR_INVALID_DATA }
        );
    }

    #[test]
    fn a_refused_post_gives_up_on_the_socket() {
        let mut engine = started(2);
        engine.on_post_failure(0);
        assert!(engine.failed);
        assert!(engine.closing);
        assert!(!engine.slot(0).unwrap().outstanding);
        assert_eq!(engine.outstanding, 1);
        // The outstanding request still has to complete before release.
        assert!(!engine.may_release());
        engine.on_completion(1, 0, 8);
        assert_eq!(engine.outstanding, 0);
        engine.stopped();
        assert!(engine.may_release());
    }
}

