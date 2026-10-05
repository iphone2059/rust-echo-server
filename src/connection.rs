//! Per-connection TCP echo state machine.
//!
//! The machine is deliberately free of Win32 types so its transitions and the echo
//! progression are unit-testable; the worker loop only translates its decisions into RIO
//! calls. It is the direct counterpart of the connection record handled by
//! `ces_engine_process_result` in the C++ baseline and `processResult` in the Swift port.

use crate::ces_contract::advance_offset_u32;
use crate::types::{EngineOperation, ERROR_SUCCESS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// The slot is free; nothing owns it.
    Idle,
    /// Adopted by the acceptor, waiting for the echo of the last receive.
    Receiving,
    /// A receive completed and its bytes are being sent back.
    Sending,
    /// The socket is gone; the slot waits for the operations still in flight.
    Closing,
    /// The slot has been returned to the free list.
    Released,
}

/// What the native layer must do for one connection. The engine adds the slot index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionStep {
    None,
    Receive,
    Send { offset: u32, length: u32 },
    /// Close the socket now. The slot is not reusable yet: the operations that were in
    /// flight still have to complete, and the peer must see the connection go away
    /// immediately (this is what makes an idle /t connection time out).
    Close,
    /// Close the socket if it is still open and return the slot to the free list.
    CloseAndRelease,
}

#[derive(Debug)]
pub struct Connection {
    pub index: u32,
    pub state: ConnectionState,
    /// RIO operations posted and not yet completed. Never exceeds two: one receive or one
    /// send at a time.
    pub outstanding: u32,
    /// Bytes the last receive produced; the echo must return exactly these.
    pub echo_bytes: u32,
    /// Bytes of the echo already accepted by the socket.
    pub send_offset: u32,
    /// Absolute deadline of the operation in flight, when one is armed.
    pub deadline: u64,
}

impl Connection {
    pub fn new(index: u32) -> Self {
        Self {
            index,
            state: ConnectionState::Idle,
            outstanding: 0,
            echo_bytes: 0,
            send_offset: 0,
            deadline: 0,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Receiving | ConnectionState::Sending | ConnectionState::Closing
        )
    }

    pub fn is_closing(&self) -> bool {
        self.state == ConnectionState::Closing
    }

    pub fn is_idle(&self) -> bool {
        self.state == ConnectionState::Idle
    }

    /// Adopts the slot for a freshly accepted socket: the first receive is armed with the
    /// connection timeout.
    pub fn admit(&mut self, now: u64, timeout_milliseconds: u64) -> ConnectionStep {
        self.state = ConnectionState::Receiving;
        self.outstanding = 0;
        self.echo_bytes = 0;
        self.send_offset = 0;
        self.deadline = now + timeout_milliseconds;
        ConnectionStep::Receive
    }

    /// A posted operation completed. `status` is the RIO status of the completion and
    /// `bytes` the transferred byte count.
    pub fn on_completion(
        &mut self,
        operation: EngineOperation,
        status: i32,
        bytes: u32,
        now: u64,
        timeout_milliseconds: u64,
    ) -> ConnectionStep {
        debug_assert!(self.outstanding > 0, "completion without a posted operation");
        self.outstanding = self.outstanding.saturating_sub(1);
        if self.state == ConnectionState::Closing {
            // A socket closed with work in flight still has to be drained before the slot
            // can be handed to a new connection. The socket is already closed, so the
            // release simply closes it again (a no-op) and recycles the index.
            return if self.outstanding == 0 { self.release() } else { ConnectionStep::None };
        }
        if status != ERROR_SUCCESS {
            return self.close();
        }
        match operation {
            EngineOperation::Receive => {
                // A zero-byte receive is an orderly shutdown from the peer.
                if bytes == 0 {
                    return self.close();
                }
                self.echo_bytes = bytes;
                self.send_offset = 0;
                self.deadline = now + timeout_milliseconds;
                self.state = ConnectionState::Sending;
                ConnectionStep::Send { offset: 0, length: bytes }
            }
            EngineOperation::Send => {
                self.deadline = now + timeout_milliseconds;
                if !advance_offset_u32(self.echo_bytes, bytes, &mut self.send_offset) {
                    // A send that transferred nothing, or more than the echo, is a
                    // protocol failure: the echo cannot be completed.
                    return self.close();
                }
                if self.send_offset < self.echo_bytes {
                    ConnectionStep::Send {
                        offset: self.send_offset,
                        length: self.echo_bytes - self.send_offset,
                    }
                } else {
                    self.state = ConnectionState::Receiving;
                    ConnectionStep::Receive
                }
            }
        }
    }

    /// Closes the socket and, when nothing is in flight, releases the slot as well.
    pub fn close(&mut self) -> ConnectionStep {
        if self.state == ConnectionState::Closing
            || self.state == ConnectionState::Released
            || self.state == ConnectionState::Idle
        {
            return ConnectionStep::None;
        }
        self.state = ConnectionState::Closing;
        self.deadline = 0;
        if self.outstanding == 0 { self.release() } else { ConnectionStep::Close }
    }

    fn release(&mut self) -> ConnectionStep {
        self.state = ConnectionState::Released;
        self.outstanding = 0;
        self.echo_bytes = 0;
        self.send_offset = 0;
        self.deadline = 0;
        ConnectionStep::CloseAndRelease
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_adopted_connection_arms_its_first_receive() {
        let mut connection = Connection::new(3);
        assert!(connection.is_idle());
        assert_eq!(connection.admit(1_000, 5_000), ConnectionStep::Receive);
        assert_eq!(connection.state, ConnectionState::Receiving);
        assert_eq!(connection.deadline, 6_000);
        assert!(connection.is_active());
    }

    #[test]
    fn a_completed_receive_echoes_exactly_its_bytes() {
        let mut connection = Connection::new(0);
        connection.admit(0, 5_000);
        connection.outstanding = 1;
        assert_eq!(
            connection.on_completion(EngineOperation::Receive, 0, 1_024, 10, 5_000),
            ConnectionStep::Send { offset: 0, length: 1_024 }
        );
        assert_eq!(connection.state, ConnectionState::Sending);
        assert_eq!(connection.echo_bytes, 1_024);
        assert_eq!(connection.send_offset, 0);
        assert_eq!(connection.deadline, 5_010);
    }

    #[test]
    fn partial_sends_continue_where_they_stopped() {
        let mut connection = Connection::new(1);
        connection.admit(0, 5_000);
        connection.outstanding = 1;
        connection.on_completion(EngineOperation::Receive, 0, 1_000, 0, 5_000);
        connection.outstanding = 1;
        assert_eq!(
            connection.on_completion(EngineOperation::Send, 0, 400, 0, 5_000),
            ConnectionStep::Send { offset: 400, length: 600 }
        );
        connection.outstanding = 1;
        assert_eq!(
            connection.on_completion(EngineOperation::Send, 0, 600, 0, 5_000),
            ConnectionStep::Receive
        );
        assert_eq!(connection.state, ConnectionState::Receiving);
        assert_eq!(connection.send_offset, 1_000);
    }

    #[test]
    fn terminal_completions_close_and_then_release() {
        // A failed completion with nothing else in flight releases immediately.
        let mut failed = Connection::new(0);
        failed.admit(0, 5_000);
        failed.outstanding = 1;
        assert_eq!(
            failed.on_completion(EngineOperation::Receive, 1234, 0, 0, 5_000),
            ConnectionStep::CloseAndRelease
        );
        assert_eq!(failed.state, ConnectionState::Released);
        assert!(!failed.is_active());

        // A peer shutdown (zero-byte receive) is not an error.
        let mut shutdown = Connection::new(1);
        shutdown.admit(0, 5_000);
        shutdown.outstanding = 1;
        assert_eq!(
            shutdown.on_completion(EngineOperation::Receive, 0, 0, 0, 5_000),
            ConnectionStep::CloseAndRelease
        );

        // A send that cannot advance is a terminal protocol failure.
        let mut stuck = Connection::new(2);
        stuck.admit(0, 5_000);
        stuck.outstanding = 1;
        stuck.on_completion(EngineOperation::Receive, 0, 16, 0, 5_000);
        stuck.outstanding = 1;
        assert_eq!(
            stuck.on_completion(EngineOperation::Send, 0, 0, 0, 5_000),
            ConnectionStep::CloseAndRelease
        );
    }

    #[test]
    fn a_close_with_work_in_flight_waits_for_the_completion() {
        let mut connection = Connection::new(4);
        connection.admit(0, 5_000);
        connection.outstanding = 2;
        // The socket has to go now; only the slot waits for the two completions.
        assert_eq!(connection.close(), ConnectionStep::Close);
        assert!(connection.is_closing());
        assert_eq!(
            connection.on_completion(EngineOperation::Receive, 0, 128, 0, 5_000),
            ConnectionStep::None
        );
        assert_eq!(
            connection.on_completion(EngineOperation::Send, 0, 128, 0, 5_000),
            ConnectionStep::CloseAndRelease
        );
        // Closing twice is not an error and never double releases.
        assert_eq!(connection.close(), ConnectionStep::None);
    }
}

