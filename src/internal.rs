//! Worker threads, their business state and the datagram runtime.
//!
//! This is the reference's cec_engine_internal.cpp: the accept table, the connection progression,
//! the datagram slots and the timers that drive them. Native object lifetime stays in `engine`.

pub mod acceptor {
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
}

pub mod connection {
    //! Per-connection TCP echo state machine.
    //!
    //! The machine is deliberately free of Win32 types so its transitions and the echo
    //! progression are unit-testable; the worker loop only translates its decisions into RIO
    //! calls. It is the direct counterpart of the connection record handled by
    //! `ces_engine_process_result` in the C++ baseline and `processResult` in the Swift port.

    use crate::contract::advance_offset_u32;
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
}

pub mod udp {
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

    // The datagram path owns its own runtime thread.

pub mod runtime {
    //! Native UDP engine: a fixed depth of addressed receives, each of which echoes exactly
    //! the datagram it received and then restores the receive.
    //!
    //! This mirrors `ces_engine_run_udp` in the C++ baseline and the Swift port: one
    //! completion queue, one registered arena, and a socket that is closed before the final
    //! drain so the outstanding requests are cancelled without leaking storage.

    use core::ffi::c_void;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use windows::Win32::minwinbase::OVERLAPPED;
    use windows::Win32::mswsockdef::{RIO_BUF, RIORESULT};

    use crate::native::arena::{udp_stride, Arena};
    use crate::contract::checked_arena_bytes;
    use crate::native::{fail_fast, now_milliseconds, report, RioFunctions, SocketOwner};
    use crate::native::rio::{
        empty_result, get_queued_completion_status, post_completion, CompletionPort, CompletionQueue,
        RequestQueue,
    };
    use crate::types::{
        EngineOperation, ExitCode, Options, Protocol, UDP_ADDRESS_BYTES, COMPLETION_BATCH_SIZE,
        COMPLETION_DRAIN_BATCHES, ERROR_INVALID_DATA, ERROR_IO_INCOMPLETE, ERROR_NOT_ENOUGH_MEMORY,
        WAIT_TIMEOUT,
    };
    use crate::udp::{UdpAction, UdpEngine};

    /// The RIO request context for one datagram slot. It is the record's first field, so the
    /// address RIO hands back is the record address.
    #[repr(C)]
    pub struct UdpRequest {
        pub slot_index: u32,
    }

    /// One slot's native state: the datagram buffer and the sender address RIOReceiveEx fills.
    #[repr(C)]
    struct UdpSlotRuntime {
        request: UdpRequest,
        payload: RIO_BUF,
        remote_address: RIO_BUF,
    }

    impl UdpSlotRuntime {
        fn request_context(&self) -> *const c_void {
            &self.request as *const UdpRequest as *const c_void
        }
    }

    /// Identity marker whose address is this engine's completion key.
    struct UdpKey {
        /// Never read: the key's address is the identity. The field gives the marker a real
        /// allocation, which is what makes that address unique inside the process.
        #[allow(dead_code)]
        marker: u64,
    }

    struct UdpRuntime {
        rio: RioFunctions,
        socket: SocketOwner,
        port: CompletionPort,
        queue: CompletionQueue,
        arena: Arena,
        request_queue: RequestQueue,
        slots: Box<[UdpSlotRuntime]>,
        notification: Box<OVERLAPPED>,
        key: Box<UdpKey>,
        engine: UdpEngine,
        results: Vec<RIORESULT>,
    }

    impl UdpRuntime {
        fn notification_address(&self) -> usize {
            &*self.notification as *const OVERLAPPED as usize
        }

        fn key_address(&self) -> usize {
            &*self.key as *const UdpKey as usize
        }

        /// Maps a request context back to its slot, refusing anything this engine does not own.
        fn slot_index(&self, address: usize) -> u32 {
            let base = self.slots.as_ptr() as usize;
            let stride = core::mem::size_of::<UdpSlotRuntime>();
            let extent = stride * self.slots.len();
            let end = base.saturating_add(extent);
            if stride == 0 || address < base || address >= end || (address - base) % stride != 0 {
                fail_fast("server UDP RequestContext range", ERROR_INVALID_DATA);
            }
            let index = ((address - base) / stride) as u32;
            let request = unsafe { &*(address as *const UdpRequest) };
            if request.slot_index != index {
                fail_fast("server UDP RequestContext metadata", ERROR_INVALID_DATA);
            }
            index
        }

        /// Arms the completion queue. Every registration is paired with one delivery.
        fn arm(&mut self, armed: &mut bool) {
            if self.queue.is_armed() {
                fail_fast("server duplicate UDP RIONotify", ERROR_INVALID_DATA);
            }
            let rio = self.rio;
            if let Err(error) = self.queue.arm(&rio) {
                fail_fast("RIONotify(UDP)", error.code);
            }
            if !crate::contract::notification_mark_rearmed(armed) {
                fail_fast("server UDP notification rearm transition", ERROR_INVALID_DATA);
            }
        }

        /// Posts the operation the slot currently holds: the echo of the datagram it received,
        /// or the next addressed receive.
        fn post_slot(&mut self, index: u32) {
            let rio = self.rio;
            let outcome = {
                let Some(slot) = self.slots.get_mut(index as usize) else {
                    return;
                };
                let length = match self.engine.slot(index) {
                    Some(state) => state.payload_length,
                    None => 0,
                };
                slot.payload.Length = length;
                let context = slot.request_context();
                let send = matches!(
                    self.engine.slot(index).map(|state| state.operation),
                    Some(EngineOperation::Send)
                );
                let queue = &self.request_queue;
                if send {
                    queue.send_ex(&rio, &mut slot.payload, &mut slot.remote_address, context)
                } else {
                    queue.receive_ex(&rio, &mut slot.payload, &mut slot.remote_address, context)
                }
            };
            match outcome {
                Ok(()) => self.engine.mark_posted(index),
                Err(error) => {
                    report(error.stage, error.code);
                    self.engine.on_post_failure(index);
                }
            }
        }
    }
    /// Runs the UDP echo engine until the stop flag is set or a run deadline passes.
    pub fn run_udp(rio: RioFunctions, options: &Options, stop: &Arc<AtomicBool>) -> ExitCode {
        let Some(stride) = udp_stride(options.rio_buffer_bytes, UDP_ADDRESS_BYTES) else {
            report("UDP slot stride", ERROR_NOT_ENOUGH_MEMORY);
            return ExitCode::Network;
        };
        let depth = options.udp_depth;
        let arena_bytes = match checked_arena_bytes(
            u64::from(depth),
            u64::from(stride),
            options.memory_bytes,
        ) {
            Some(bytes) if bytes > 0 && bytes <= u64::from(u32::MAX) && depth <= options.cq_capacity / 2 => {
                bytes
            }
            _ => {
                report("UDP queue/arena capacity", ERROR_NOT_ENOUGH_MEMORY);
                return ExitCode::Network;
            }
        };

        let socket = match crate::native::registered_socket(Protocol::Udp) {
            Ok(socket) => socket,
            Err(error) => {
                report(error.stage, error.code);
                return ExitCode::Network;
            }
        };
        if let Err(error) = crate::native::configure_socket(socket.raw(), false, options.socket_buffer_bytes) {
            report(error.stage, error.code);
            return ExitCode::Network;
        }
        if let Err(error) = crate::native::endpoint::bind_endpoint(socket.raw(), options.port) {
            report(error.stage, error.code);
            return ExitCode::Network;
        }
        let port = match CompletionPort::create() {
            Ok(port) => port,
            Err(error) => {
                report(error.stage, error.code);
                return ExitCode::Network;
            }
        };
        let arena = match Arena::create(&rio, arena_bytes as usize) {
            Ok(arena) => arena,
            Err(error) => {
                report(error.stage, error.code);
                return ExitCode::Network;
            }
        };
        let notification = Box::new(OVERLAPPED::default());
        let key = Box::new(UdpKey { marker: 0x5544_5000_0000_0001 });
        let queue = match CompletionQueue::create(
            &rio,
            &port,
            options.cq_capacity,
            &*key as *const UdpKey as *mut c_void,
            &*notification as *const OVERLAPPED as *mut c_void,
        ) {
            Ok(queue) => queue,
            Err(error) => {
                report(error.stage, error.code);
                return ExitCode::Network;
            }
        };
        let slots: Box<[UdpSlotRuntime]> = (0..depth)
            .map(|index| UdpSlotRuntime {
                request: UdpRequest { slot_index: index },
                payload: RIO_BUF::default(),
                remote_address: RIO_BUF::default(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let slots_context = slots.as_ptr() as *mut c_void;
        let request_queue = match RequestQueue::create(
            &rio,
            socket.raw(),
            depth,
            1,
            depth,
            1,
            queue.raw(),
            queue.raw(),
            slots_context,
        ) {
            Ok(request_queue) => request_queue,
            Err(error) => {
                report(error.stage, error.code);
                return ExitCode::Network;
            }
        };

        let mut runtime = UdpRuntime {
            rio,
            socket,
            port,
            queue,
            arena,
            request_queue,
            slots,
            notification,
            key,
            engine: UdpEngine::new(depth, options.rio_buffer_bytes),
            results: vec![empty_result(); COMPLETION_BATCH_SIZE],
        };

        // Every slot starts with an addressed receive over the datagram part of its region and
        // the sender address area right behind it.
        for index in 0..depth {
            let payload = match runtime
                .arena
                .slot_tail_view(index, stride, 0, options.rio_buffer_bytes)
            {
                Ok(view) => view,
                Err(error) => {
                    report(error.stage, error.code);
                    runtime.engine.on_post_failure(index);
                    break;
                }
            };
            let remote = match runtime.arena.slot_tail_view(
                index,
                stride,
                options.rio_buffer_bytes,
                UDP_ADDRESS_BYTES as u32,
            ) {
                Ok(view) => view,
                Err(error) => {
                    report(error.stage, error.code);
                    runtime.engine.on_post_failure(index);
                    break;
                }
            };
            runtime.slots[index as usize].payload = payload;
            runtime.slots[index as usize].remote_address = remote;
            runtime.post_slot(index);
            if runtime.engine.failed {
                break;
            }
        }

        let start = now_milliseconds();
        let run_deadline = if options.run_seconds == 0 {
            u64::MAX
        } else {
            start.saturating_add(u64::from(options.run_seconds) * 1_000)
        };
        let mut armed = false;
        if runtime.engine.outstanding != 0 {
            runtime.arm(&mut armed);
        }

        while !runtime.engine.closing || runtime.engine.outstanding != 0 {
            if runtime.engine.outstanding != 0 && !runtime.queue.is_armed() {
                runtime.arm(&mut armed);
            }
            let expired = now_milliseconds() >= run_deadline;
            let stop_now = stop.load(Ordering::Acquire);
            // Closing the socket is what cancels the posted requests, so it has to follow from closing
            // alone and not only from the stop request: an error path sets closing without closing the
            // socket, and a drain waiting for completions that can never arrive never ends. Both calls
            // are idempotent, so running them while closing is safe.
            if runtime.engine.closing || stop_now || expired {
                runtime.engine.begin_drain();
                runtime.socket.reset();
            }
            let packet = get_queued_completion_status(runtime.port.raw(), 100);
            if packet.overlapped as usize == runtime.notification_address() {
                if !packet.succeeded {
                    fail_fast("GetQueuedCompletionStatus(UDP notification)", packet.error as i32);
                }
                if !crate::contract::notification_packet_matches(
                    packet.key,
                    packet.overlapped as usize,
                    runtime.key_address(),
                    runtime.notification_address(),
                ) {
                    fail_fast("server UDP RIO notification key", ERROR_INVALID_DATA);
                }
                if !crate::contract::notification_mark_delivered(&mut armed) {
                    fail_fast("server UDP notification delivery transition", ERROR_INVALID_DATA);
                }
                runtime.queue.on_delivery();
                let rio = runtime.rio;
                for _ in 0..COMPLETION_DRAIN_BATCHES {
                    // A saturated flood can keep the queue non-empty indefinitely, so the
                    // bounded drain also observes the stop request and the run deadline: the
                    // socket is closed here and no further request is reposted, which is what
                    // keeps a controlled stop bounded under full load.
                    if runtime.engine.closing
                        || stop.load(Ordering::Acquire)
                        || now_milliseconds() >= run_deadline
                    {
                        runtime.engine.begin_drain();
                        runtime.socket.reset();
                    }
                    let count = match runtime.queue.dequeue(&rio, &mut runtime.results) {
                        Ok(count) => count,
                        Err(error) => fail_fast("RIODequeueCompletion(UDP)", error.code),
                    };
                    if count == 0 {
                        break;
                    }
                    for position in 0..count as usize {
                        let result = runtime.results[position];
                        let index = runtime.slot_index(result.RequestContext as usize);
                        match runtime
                            .engine
                            .on_completion(index, result.Status, result.BytesTransferred)
                        {
                            UdpAction::Post { index } => runtime.post_slot(index),
                            UdpAction::Fatal { error, .. } => {
                        // The engine gave up on the socket, so cancel the posted requests here as well
                        // instead of leaving the drain to wait for completions the socket still holds.
                        report("UDP RIO completion", error);
                        runtime.engine.begin_drain();
                        runtime.socket.reset();
                    }
                            UdpAction::None => {}
                        }
                    }
                }
            } else if !packet.succeeded && packet.error != WAIT_TIMEOUT {
                fail_fast("GetQueuedCompletionStatus(UDP)", packet.error as i32);
            } else if !(!packet.succeeded && packet.error == WAIT_TIMEOUT && packet.overlapped.is_null()) {
                fail_fast("unexpected UDP IOCP packet", ERROR_INVALID_DATA);
            }
        }

        // A socket that was closed for the drain is already gone; one closed by a failure still
        // has to be released here.
        runtime.socket.reset();
        if armed {
            if let Err(error) = post_completion(runtime.port.raw(), 0, &mut *runtime.notification) {
                fail_fast("PostQueuedCompletionStatus(UDP notification shutdown)", error.code);
            }
            let packet = get_queued_completion_status(runtime.port.raw(), 1_000);
            if !packet.succeeded {
                fail_fast("GetQueuedCompletionStatus(UDP notification shutdown)", packet.error as i32);
            }
            if !crate::contract::notification_packet_matches(
                packet.key,
                packet.overlapped as usize,
                0,
                runtime.notification_address(),
            ) {
                fail_fast("UDP notification shutdown packet", ERROR_INVALID_DATA);
            }
            if !crate::contract::notification_mark_delivered(&mut armed) {
                fail_fast("UDP notification shutdown transition", ERROR_INVALID_DATA);
            }
        }
        if runtime.engine.outstanding != 0 {
            fail_fast("UDP cleanup with outstanding operations", ERROR_IO_INCOMPLETE);
        }
        runtime.engine.stopped();
        if !runtime.engine.may_release() {
            fail_fast("UDP release precondition", ERROR_INVALID_DATA);
        }
        let elapsed = now_milliseconds().saturating_sub(start);
        let statistics = runtime.engine.statistics;
        let failed = runtime.engine.failed;
        if options.stats {
            println!(
                "{}",
                statistics.final_line(Protocol::Udp, elapsed, 1, runtime.engine.outstanding)
            );
        }
        // Release order of the baseline: completion queue, registration and arena, then the
        // socket, then the port. Nothing is outstanding, so no completion can be lost.
        let rio = runtime.rio;
        runtime.queue.close(&rio);
        runtime.arena.destroy(&rio);
        drop(runtime);
        if failed { ExitCode::Network } else { ExitCode::Success }
    }
}
}

pub mod worker {
    //! TCP worker runtime: one thread drives one completion queue, one registered arena and
    //! one connection table.
    //!
    //! The echo progression itself lives in `engine`; this module is the native side the loop
    //! drives: RIO posts, the accept handoff, the completion drain and the release of a
    //! finished slot. It mirrors `ces_engine_worker_thread` in the C++ baseline and
    //! `runWorker` in the Swift port, including their failure classification.

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use windows::Win32::minwinbase::OVERLAPPED;
    use windows::Win32::mswsockdef::{RIO_BUF, RIORESULT};
    use windows::Win32::winsock2::INVALID_SOCKET;

    use crate::acceptor::AcceptTable;
    use crate::native::arena::Arena;
    use crate::contract::notification_packet_matches;
    use crate::engine::{Step, TcpEngine};
    use crate::native::{
        fail_fast, now_milliseconds, report, NativeError, RioFunctions, SendHandle, SocketOwner,
    };
    use crate::native::rio::{
        empty_result, get_queued_completion_status, post_completion, CompletionPort, CompletionQueue,
        RequestQueue,
    };
    use crate::types::{
        EngineOperation, Statistics, WorkerPhase, ADMISSION_CLOSED_KEY, COMPLETION_BATCH_SIZE,
        COMPLETION_DRAIN_BATCHES, ERROR_INVALID_DATA, STOP_KEY, WAIT_TIMEOUT,
    };

    /// The RIO request context. It is the first field of a connection record, so the address
    /// RIO hands back in RIORESULT is the record address and the slot index follows from the
    /// table layout alone.
    #[repr(C)]
    pub struct Request {
        pub connection_index: u32,
        pub operation: EngineOperation,
    }

    /// One connection slot's native state. The socket and the request queue exist only while
    /// the slot is adopted; the buffer describes the registered region the echo moves through.
    #[repr(C)]
    struct ConnectionRuntime {
        request: Request,
        socket: SocketOwner,
        request_queue: Option<RequestQueue>,
        buffer: RIO_BUF,
    }

    impl ConnectionRuntime {
        fn request_context(&self) -> *const c_void {
            &self.request as *const Request as *const c_void
        }

        /// Closes the socket and forgets the request queue. The engine has already returned
        /// the index to its free list, so nothing may post through this record any more.
        fn release(&mut self) {
            self.request_queue = None;
            self.socket.reset();
            self.buffer = RIO_BUF::default();
        }
    }

    /// Identity marker whose address is the worker's IOCP completion key. Using an address
    /// keeps worker keys in the same space as accept-operation keys, which the loop separates
    /// by the OVERLAPPED field: only a notification carries one.
    pub struct WorkerKey {
        pub index: u32,
        /// Never read: the key's address is the identity. The field gives the marker a real
        /// allocation, which is what makes that address unique inside the process.
        #[allow(dead_code)]
        pub marker: u64,
    }

    // SAFETY: a worker is built on the coordinator thread and then moved into exactly one
    // thread that owns it until it returns. Every native handle inside (completion port,
    // completion queue, registered arena, sockets) is used only by that owning thread; the
    // coordinator keeps a separate SendHandle copy of the port and only posts control packets
    // to it.
    unsafe impl Send for TcpWorker {}

    /// What the coordinator reports for one worker after it has joined.
    pub struct WorkerReport {
        pub index: u32,
        pub statistics: Statistics,
        pub active: u32,
    }

    pub struct TcpWorker {
        index: u32,
        rio: RioFunctions,
        stride: u32,
        port: CompletionPort,
        queue: CompletionQueue,
        arena: Arena,
        notification: Box<OVERLAPPED>,
        key: Box<WorkerKey>,
        results: Vec<RIORESULT>,
        connections: Box<[ConnectionRuntime]>,
        engine: TcpEngine,
        failure: Arc<AtomicBool>,
    }
    impl TcpWorker {
        /// Builds a worker: completion port, completion queue, registered arena and the
        /// connection table. Nothing is posted yet: the first receive goes out when the
        /// acceptor hands a socket over.
        #[allow(clippy::too_many_arguments)]
        pub fn create(
            rio: RioFunctions,
            index: u32,
            slot_count: u32,
            stride: u32,
            cq_capacity: u32,
            memory_share: u64,
            timeout_milliseconds: u64,
            failure: Arc<AtomicBool>,
        ) -> Result<Self, NativeError> {
            if stride == 0 || slot_count == 0 {
                return Err(NativeError { stage: "worker registered arena size", code: 8 });
            }
            let arena_bytes = crate::contract::checked_arena_bytes(
                u64::from(slot_count),
                u64::from(stride),
                memory_share,
            )
            .ok_or(NativeError { stage: "worker registered arena size", code: 8 })?;
            if arena_bytes == 0 || arena_bytes > u64::from(u32::MAX) {
                return Err(NativeError { stage: "worker registered arena size", code: 8 });
            }
            // Two queue entries per connection, exactly what the connection capacity reserved
            // out of /cq.
            let capacity = slot_count.checked_mul(2).unwrap_or(slot_count);
            let port = CompletionPort::create()?;
            let notification = Box::new(OVERLAPPED::default());
            let key = Box::new(WorkerKey { index, marker: 0x574F_524B_0000_0000 | u64::from(index) });
            let queue = CompletionQueue::create(
                &rio,
                &port,
                capacity.min(cq_capacity.max(1)),
                &*key as *const WorkerKey as *mut c_void,
                &*notification as *const OVERLAPPED as *mut c_void,
            )?;
            let arena = Arena::create(&rio, arena_bytes as usize)?;
            let connections: Box<[ConnectionRuntime]> = (0..slot_count)
                .map(|slot| ConnectionRuntime {
                    request: Request { connection_index: slot, operation: EngineOperation::Receive },
                    socket: SocketOwner::new(INVALID_SOCKET),
                    request_queue: None,
                    buffer: RIO_BUF::default(),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let engine = TcpEngine::new(slot_count, timeout_milliseconds);
            Ok(Self {
                index,
                rio,
                stride,
                port,
                queue,
                arena,
                notification,
                key,
                results: vec![empty_result(); COMPLETION_BATCH_SIZE],
                connections,
                engine,
                failure,
            })
        }

        pub fn port_handle(&self) -> SendHandle {
            SendHandle(self.port.raw())
        }

        pub fn slot_count(&self) -> u32 {
            self.engine.slot_count()
        }

        fn key_address(&self) -> usize {
            &*self.key as *const WorkerKey as usize
        }

        fn notification_address(&self) -> usize {
            &*self.notification as *const OVERLAPPED as usize
        }

        /// Marks the worker as running. The coordinator waits for the ready event, so this
        /// happens before the loop can touch a connection.
        pub fn mark_running(&mut self) {
            self.engine.phase = WorkerPhase::Running;
        }

        /// Runs the worker loop until admission closed and every connection drained.
        pub fn run(&mut self, stop: &Arc<AtomicBool>, accept: &AcceptTable, ready: SendHandle) -> WorkerReport {
            if !set_ready(ready) {
                fail_fast("SetEvent(worker ready)", 6);
            }
            loop {
                // Lazy notification: a registration exists only while this worker owns
                // connections with requests in flight, so an idle worker never holds a pending
                // RIONotify. RIONotify called with a non-empty queue notifies immediately, so a
                // completion that arrives between the post and the arm cannot be lost.
                if self.engine.active_count() != 0 && !self.queue.is_armed() {
                    self.arm();
                }
                let wait = self.engine.waiting_milliseconds(now_milliseconds());
                let packet = get_queued_completion_status(self.port.raw(), wait);
                if packet.overlapped as usize == self.notification_address() {
                    if !packet.succeeded {
                        fail_fast("GetQueuedCompletionStatus(worker notification)", packet.error as i32);
                    }
                    if !notification_packet_matches(
                        packet.key,
                        packet.overlapped as usize,
                        self.key_address(),
                        self.notification_address(),
                    ) {
                        fail_fast("server worker RIO notification key", ERROR_INVALID_DATA);
                    }
                    if !crate::contract::notification_mark_delivered(&mut self.engine.notification_armed) {
                        fail_fast("server worker notification delivery transition", 5023);
                    }
                    self.queue.on_delivery();
                    self.drain(stop);
                } else if packet.overlapped.is_null() && packet.key == STOP_KEY {
                    let steps = self.engine.begin_stop();
                    self.execute_all(steps);
                } else if packet.overlapped.is_null() && packet.key == ADMISSION_CLOSED_KEY {
                    self.engine.close_admission();
                } else if packet.overlapped.is_null() && packet.key > ADMISSION_CLOSED_KEY {
                    self.take_socket(accept, packet.key);
                } else if !packet.succeeded && packet.error != WAIT_TIMEOUT {
                    report("GetQueuedCompletionStatus(worker)", packet.error as i32);
                    self.failure.store(true, Ordering::Release);
                    let steps = self.engine.begin_stop();
                    self.execute_all(steps);
                } else if !(!packet.succeeded && packet.error == WAIT_TIMEOUT && packet.overlapped.is_null()) {
                    fail_fast("unexpected worker IOCP packet", ERROR_INVALID_DATA);
                }
                if self.engine.fatal {
                    fail_fast("server timer insert/update", ERROR_INVALID_DATA);
                }
                let mut expired = Vec::new();
                let steps = self.engine.on_timeout(now_milliseconds(), &mut expired);
                self.execute_all(steps);
                if self.engine.stopping && self.engine.admission_closed && self.engine.active_count() == 0 {
                    break;
                }
            }
            // Lazy arming means no registration can be left once nothing has work in flight.
            if self.engine.notification_armed {
                report("server worker notification unarmed precondition", 5023);
            }
            if !self.engine.may_exit() {
                fail_fast("server worker release precondition", 5023);
            }
            self.engine.phase = WorkerPhase::Stopped;
            WorkerReport {
                index: self.index,
                statistics: self.engine.statistics,
                active: self.engine.active_count(),
            }
        }

        /// Releases the worker's native resources in the baseline's order: the completion
        /// queue, the registered region, the arena pages and finally the per-connection
        /// sockets. Only called after the loop has drained every connection and validated the
        /// release preconditions.
        pub fn destroy(mut self) {
            let rio = self.rio;
            self.queue.close(&rio);
            for runtime in self.connections.iter_mut() {
                runtime.release();
            }
            self.arena.destroy(&rio);
        }
    }
    impl TcpWorker {
        /// Arms the completion queue. Every call is paired with a delivery: the armed flag in
        /// the engine and the queue's own flag move together.
        fn arm(&mut self) {
            if self.queue.is_armed() {
                fail_fast("server duplicate worker RIONotify", 5023);
            }
            let rio = self.rio;
            if let Err(error) = self.queue.arm(&rio) {
                fail_fast("RIONotify(worker)", error.code);
            }
            if !crate::contract::notification_mark_rearmed(&mut self.engine.notification_armed) {
                fail_fast("server worker notification rearm transition", 5023);
            }
        }

        /// Drains completions in bounded batches. A saturated echo peer can keep the queue
        /// non-empty indefinitely, so the drain yields to the control path after a fixed number
        /// of batches; whatever is left stays queued and the notification is re-armed later.
        fn drain(&mut self, stop: &Arc<AtomicBool>) {
            let rio = self.rio;
            for _ in 0..COMPLETION_DRAIN_BATCHES {
                let count = match self.queue.dequeue(&rio, &mut self.results) {
                    Ok(count) => count,
                    Err(error) => fail_fast("RIODequeueCompletion(worker)", error.code),
                };
                if count == 0 {
                    return;
                }
                for position in 0..count as usize {
                    let result = self.results[position];
                    let index = self.request_index(result.RequestContext as usize);
                    let operation = self.connections[index as usize].request.operation;
                    let step = self.engine.on_completion(
                        index,
                        operation,
                        result.Status,
                        result.BytesTransferred,
                        now_milliseconds(),
                    );
                    self.execute(step);
                }
                if stop.load(Ordering::Acquire) {
                    return;
                }
            }
        }

        /// Maps a RIO request context back to its slot. The context is the address of the
        /// record's first field, so the address has to fall inside this table, be aligned and
        /// carry the slot's own index; anything else is a completion this worker does not own.
        fn request_index(&self, address: usize) -> u32 {
            let base = self.connections.as_ptr() as usize;
            let stride = size_of::<ConnectionRuntime>();
            let extent = stride * self.connections.len();
            let end = base.saturating_add(extent);
            if stride == 0 || address < base || address >= end || (address - base) % stride != 0 {
                fail_fast("server RIO RequestContext range", ERROR_INVALID_DATA);
            }
            let index = ((address - base) / stride) as u32;
            let request = unsafe { &*(address as *const Request) };
            if request.connection_index != index {
                fail_fast("server RIO request metadata", ERROR_INVALID_DATA);
            }
            index
        }

        fn execute_all(&mut self, steps: Vec<Step>) {
            for step in steps {
                self.execute(Some(step));
            }
        }

        fn execute(&mut self, step: Option<Step>) {
            match step {
                None => {}
                Some(Step::Close { index }) => self.close_slot(index),
                Some(Step::Release { index }) => self.release_slot(index),
                Some(Step::Receive { index, .. }) => self.post_receive(index),
                Some(Step::Send { index, offset, length, .. }) => self.post_send(index, offset, length),
            }
        }

        fn post_receive(&mut self, index: u32) {
            let rio = self.rio;
            let stride = self.stride;
            let outcome = {
                let Some(runtime) = self.connections.get_mut(index as usize) else {
                    return;
                };
                runtime.request.operation = EngineOperation::Receive;
                runtime.buffer.Offset = index * stride;
                runtime.buffer.Length = stride;
                let context = runtime.request_context();
                match runtime.request_queue.as_ref() {
                    Some(queue) => queue.receive(&rio, &mut runtime.buffer, context),
                    None => Err(NativeError {
                        stage: "RIOReceive(missing request queue)",
                        code: ERROR_INVALID_DATA,
                    }),
                }
            };
            if let Err(error) = outcome {
                report(error.stage, error.code);
                let step = self.engine.on_post_failure(index);
                self.execute(step);
            }
        }

        fn post_send(&mut self, index: u32, offset: u32, length: u32) {
            let rio = self.rio;
            let stride = self.stride;
            if length == 0 || offset >= stride || length > stride - offset {
                // The echo would leave the connection's registered slot.
                fail_fast("server send registration extent", ERROR_INVALID_DATA);
            }
            let outcome = {
                let Some(runtime) = self.connections.get_mut(index as usize) else {
                    return;
                };
                runtime.request.operation = EngineOperation::Send;
                runtime.buffer.Offset = index * stride + offset;
                runtime.buffer.Length = length;
                let context = runtime.request_context();
                match runtime.request_queue.as_ref() {
                    Some(queue) => queue.send(&rio, &mut runtime.buffer, context),
                    None => Err(NativeError {
                        stage: "RIOSend(missing request queue)",
                        code: ERROR_INVALID_DATA,
                    }),
                }
            };
            if let Err(error) = outcome {
                report(error.stage, error.code);
                let step = self.engine.on_post_failure(index);
                self.execute(step);
            }
        }

        /// Closes the socket while the slot still waits for its outstanding completions. The
        /// peer sees the connection end immediately, which is what an idle /t timeout and a
        /// stop both rely on.
        fn close_slot(&mut self, index: u32) {
            if let Some(runtime) = self.connections.get_mut(index as usize) {
                runtime.socket.reset();
            }
        }

        /// The engine returned the slot: drop the socket and the request queue. Anything RIO
        /// still held completed before this ran, because a slot is only released once its
        /// outstanding count reached zero.
        fn release_slot(&mut self, index: u32) {
            if let Some(runtime) = self.connections.get_mut(index as usize) {
                runtime.release();
            }
        }

        /// Adopts (or refuses) a socket the acceptor handed over, then acknowledges the handoff
        /// so the acceptor can post the slot again.
        fn take_socket(&mut self, accept: &AcceptTable, address: usize) {
            let Some(operation) = accept.find(address) else {
                fail_fast("server accept handoff identity", ERROR_INVALID_DATA);
            };
            let index = operation.index;
            let Some(raw) = accept.take_socket(index) else {
                // The acceptor withdrew the socket (a reset peer or a stop): the slot only has
                // to be acknowledged so it can be recycled.
                self.ack(accept, index);
                return;
            };
            let mut socket = SocketOwner::new(raw);
            let Some(slot) = self.engine.take_slot() else {
                // Stopping, or the table is full: closing the socket is the baseline's refused
                // handoff, and the acceptor reposts the operation. Only a full table is a capacity
                // refusal, so only that one is counted.
                if !self.engine.is_stopping() {
                    self.engine.statistics.rejected =
                        self.engine.statistics.rejected.wrapping_add(1);
                }
                self.ack(accept, index);
                return;
            };
            let prepared = {
                let context = self.connections[slot as usize].request_context() as *mut c_void;
                let queue = RequestQueue::create(
                    &self.rio,
                    socket.raw(),
                    1,
                    1,
                    1,
                    1,
                    self.queue.raw(),
                    self.queue.raw(),
                    context,
                )
                .and_then(|queue| {
                    let buffer = self.arena.slot_view(slot, self.stride)?;
                    Ok((queue, buffer))
                });
                queue
            };
            match prepared {
                Ok((queue, buffer)) => {
                    let runtime = &mut self.connections[slot as usize];
                    runtime.buffer = buffer;
                    runtime.request_queue = Some(queue);
                    runtime.request.operation = EngineOperation::Receive;
                    core::mem::swap(&mut runtime.socket, &mut socket);
                }
                Err(error) => {
                    // The socket was accepted but its request queue or arena was refused: a
                    // connection failure on this server, counted as the reference counts it.
                    self.engine.statistics.network_errors =
                        self.engine.statistics.network_errors.wrapping_add(1);
                    report(error.stage, error.code);
                    self.engine.return_slot(slot);
                    self.ack(accept, index);
                    return;
                }
            }
            let step = self.engine.admit(slot, now_milliseconds());
            self.execute(step);
            self.ack(accept, index);
        }

        /// Acknowledges a handoff. The acceptor owns the operation table and reclaims any
        /// socket that is still attached when the acknowledgement arrives.
        fn ack(&mut self, accept: &AcceptTable, index: u32) {
            let Some(operation) = accept.operation(index) else {
                fail_fast("server accept acknowledgement identity", ERROR_INVALID_DATA);
            };
            let key = operation as *const crate::acceptor::AcceptOperation as usize;
            if let Err(error) = post_completion(accept.port().0, key, ptr::null_mut()) {
                fail_fast("PostQueuedCompletionStatus(accept ack)", error.code);
            }
        }
    }

    /// Signals the worker's ready event. The handle is borrowed, not owned: the coordinator
    /// keeps ownership until the worker has joined.
    fn set_ready(handle: SendHandle) -> bool {
        unsafe { windows::Win32::synchapi::SetEvent(handle.0) }.as_bool()
    }

    // The worker owns its TCP runtime, its request queue and its timer wheel.

pub mod tcp {
    //! TCP admission and coordination.
    //!
    //! The acceptor thread pre-posts AcceptEx operations on its own completion port, hands
    //! each accepted socket to a worker through that worker's port and recycles the operation
    //! once the worker acknowledges it. The coordinator owns the stop order, which is the
    //! baseline's: close admission and join the acceptor first, then publish the
    //! admission-closed barrier plus stop to every worker, join them, then report.

    use core::ptr;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use windows::Win32::mswsock::LPFN_ACCEPTEX;
    use windows::Win32::winsock2::INVALID_SOCKET;

    use crate::acceptor::{AcceptAction, AcceptState, AcceptTable, AcceptorCore};
    use crate::native::arena::tcp_stride;
    use crate::contract::{accept_operation_count, tcp_connection_capacity};
    use crate::native::endpoint::{bind_endpoint, listen_endpoint, update_accept_context};
    use crate::native::{
        active_processor_count, configure_socket, fail_fast, load_accept_ex, now_milliseconds, report,
        registered_socket, HandleOwner, RioFunctions, SendHandle, SocketOwner,
    };
    use crate::native::rio::{get_queued_completion_status, post_completion, CompletionPort};
    use crate::types::{
        resolved_worker_count, ExitCode, Options, Protocol, Statistics, ACCEPTS_PER_WORKER,
        ACCEPT_ADDRESS_BYTES, ADMISSION_CLOSED_KEY, ERROR_INVALID_DATA, ERROR_IO_PENDING,
        ERROR_NOT_ENOUGH_MEMORY, MAXIMUM_ACCEPTS, STOP_KEY, WAIT_TIMEOUT,
    };
    use crate::worker::{TcpWorker, WorkerReport};

    /// How a handoff ended: posted to a worker, withdrawn because the acceptor closed the
    /// socket first, or failed for a reason admission cannot continue from.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum HandoffOutcome {
        Posted,
        Withdrawn,
        Failed,
    }

    /// One worker's control surface: the port the acceptor hands sockets to and the join handle
    /// the coordinator collects.
    struct WorkerControl {
        port: SendHandle,
        join: JoinHandle<WorkerReport>,
    }

    /// The acceptor runtime: listener, completion port, AcceptEx entry point and the
    /// operation table the workers take their sockets from.
    struct AcceptorRuntime {
        core: AcceptorCore,
        listener: SocketOwner,
        port: CompletionPort,
        accept_ex: LPFN_ACCEPTEX,
        table: Arc<AcceptTable>,
        operation_sockets: Box<[SocketOwner]>,
        workers: Vec<SendHandle>,
        socket_buffer_bytes: u32,
        failure: Arc<AtomicBool>,
    }

    // SAFETY: the acceptor runtime is created on the coordinator thread and moved into the
    // acceptor thread, which owns it until it returns. The only state two threads share is the
    // operation table, whose socket field is atomic and whose ownership transfer is ordered by
    // the IOCP packet pair (handoff, acknowledgement).
    unsafe impl Send for AcceptorRuntime {}

    impl AcceptorRuntime {
        fn initialize(
            options: &Options,
            worker_count: u32,
            workers: Vec<SendHandle>,
            failure: Arc<AtomicBool>,
        ) -> Option<Self> {
            let listener = match registered_socket(Protocol::Tcp) {
                Ok(listener) => listener,
                Err(error) => {
                    report(error.stage, error.code);
                    return None;
                }
            };
            if let Err(error) = configure_socket(listener.raw(), true, options.socket_buffer_bytes) {
                report(error.stage, error.code);
                return None;
            }
            let port = match CompletionPort::create() {
                Ok(port) => port,
                Err(error) => {
                    report(error.stage, error.code);
                    return None;
                }
            };
            if let Err(error) = bind_endpoint(listener.raw(), options.port) {
                report(error.stage, error.code);
                return None;
            }
            if let Err(error) = listen_endpoint(listener.raw()) {
                report(error.stage, error.code);
                return None;
            }
            if let Err(error) = port.associate_socket(listener.raw()) {
                report(error.stage, error.code);
                return None;
            }
            let accept_ex = match load_accept_ex(listener.raw()) {
                Ok(accept_ex) => accept_ex,
                Err(error) => {
                    report(error.stage, error.code);
                    return None;
                }
            };
            let operation_count =
                accept_operation_count(worker_count, ACCEPTS_PER_WORKER, MAXIMUM_ACCEPTS);
            if operation_count == 0 {
                report("AcceptEx operation count", ERROR_NOT_ENOUGH_MEMORY);
                return None;
            }
            let table = Arc::new(AcceptTable::new(operation_count, SendHandle(port.raw())));
            let operation_sockets: Box<[SocketOwner]> = (0..operation_count)
                .map(|_| SocketOwner::new(INVALID_SOCKET))
                .collect::<Vec<_>>()
                .into_boxed_slice();
            Some(Self {
                core: AcceptorCore::new(operation_count, worker_count),
                listener,
                port,
                accept_ex,
                table,
                operation_sockets,
                workers,
                socket_buffer_bytes: options.socket_buffer_bytes,
                failure,
            })
        }

        fn table(&self) -> Arc<AcceptTable> {
            Arc::clone(&self.table)
        }

        fn port_handle(&self) -> SendHandle {
            SendHandle(self.port.raw())
        }

        /// Closes whatever socket the slot currently owns, in either owner: the acceptor's own
        /// slot while the operation is posted, or the table mirror once it was transferred for
        /// a handoff.
        fn close_accept_socket(&mut self, index: u32) {
            // The socket is owned by exactly one of the two places: the acceptor's own slot while the
            // operation is posted, or the table mirror once it was transferred for a handoff. Closing both
            // closed one value twice, and Windows is free to hand a closed value to another socket in
            // between. The slot therefore hands its value over with release(), which does not close it, and
            // the single owner is closed once below.
            let slot_raw = self.operation_sockets[index as usize].raw();
            let _ = self.operation_sockets[index as usize].release();
            let raw = self.table.clear_socket(index).unwrap_or(slot_raw);
            if raw != INVALID_SOCKET {
                let mut owner = SocketOwner::new(raw);
                owner.reset();
            }
        }

        /// Posts an AcceptEx on one operation slot with a fresh registered socket.
        fn post_accept(&mut self, index: u32) -> bool {
            let overlapped = self.table.overlapped_ptr(index);
            if overlapped.is_null() || self.table.address_ptr(index).is_null() {
                report("AcceptEx operation table", ERROR_INVALID_DATA);
                return false;
            }
            unsafe {
                *overlapped = windows::Win32::minwinbase::OVERLAPPED::default();
            }
            let socket = match registered_socket(Protocol::Tcp) {
                Ok(socket) => socket,
                Err(error) => {
                    report(error.stage, error.code);
                    return false;
                }
            };
            let raw = socket.raw();
            self.operation_sockets[index as usize] = socket;
            self.table.store_socket(index, raw);
            let Some(accept_ex) = self.accept_ex else {
                report("AcceptEx entry point", ERROR_INVALID_DATA);
                self.close_accept_socket(index);
                return false;
            };
            let mut received: u32 = 0;
            let accepted = unsafe {
                accept_ex(
                    self.listener.raw(),
                    raw,
                    self.table.address_ptr(index),
                    0,
                    ACCEPT_ADDRESS_BYTES as u32,
                    ACCEPT_ADDRESS_BYTES as u32,
                    &mut received,
                    overlapped,
                )
            };
            if !accepted.as_bool() {
                let error = unsafe { windows::Win32::winsock2::WSAGetLastError() };
                if error != ERROR_IO_PENDING {
                    report("AcceptEx", error);
                    self.close_accept_socket(index);
                    return false;
                }
            }
            self.core.mark_posted(index);
            true
        }

        /// Stops admission, closes the listener and unposts every operation that is still
        /// waiting; handoffs already in transit are awaited by the loop condition.
        fn stop_admission(&mut self) {
            self.core.stop();
            self.listener.reset();
            for index in 0..self.core.operation_count() {
                if self.core.state(index) == Some(AcceptState::Posted) {
                    self.close_accept_socket(index);
                }
            }
        }

        fn fail_admission(&mut self, stage: &str, error: i32) {
            report(stage, error);
            self.failure.store(true, Ordering::Release);
            self.stop_admission();
        }
    }


    /// Runs the TCP server until the stop flag is set, a run deadline passes or admission
    /// fails, then reports the aggregated statistics.
    ///
    /// Stop order (the baseline's): close admission and join the acceptor, publish the
    /// admission-closed barrier plus stop to every worker, join them, aggregate, report.
    pub fn run_tcp(rio: RioFunctions, options: &Options, stop: &Arc<AtomicBool>) -> ExitCode {
        let worker_count = resolved_worker_count(options.worker_count, active_processor_count());
        let failure = Arc::new(AtomicBool::new(false));
        let stride = tcp_stride(options.rio_buffer_bytes);
        let memory_share = options.memory_bytes / u64::from(worker_count);
        let possible_slots = if stride == 0 { 0 } else { memory_share / u64::from(stride) };
        let slot_count = tcp_connection_capacity(options.cq_capacity, possible_slots);
        if possible_slots == 0 || slot_count == 0 {
            report("worker registered arena capacity", ERROR_NOT_ENOUGH_MEMORY);
            return ExitCode::Network;
        }
        let timeout_milliseconds = u64::from(options.timeout_seconds) * 1_000;

        // Workers first: their completion ports are what the acceptor hands sockets to.
        let mut workers: Vec<TcpWorker> = Vec::with_capacity(worker_count as usize);
        let mut ready_events: Vec<HandleOwner> = Vec::with_capacity(worker_count as usize);
        let mut created = 0u32;
        while created < worker_count {
            let ready = HandleOwner::new(unsafe {
                windows::Win32::synchapi::CreateEventW(None, true, false, None)
            });
            if !ready.is_open() {
                // The failure code is captured here: a later Win32 call would overwrite it.
                let error = crate::native::NativeError::last("CreateEvent(worker ready)");
                report(error.stage, error.code);
                failure.store(true, Ordering::Release);
                break;
            }
            match TcpWorker::create(
                rio,
                created,
                slot_count,
                stride,
                options.cq_capacity,
                memory_share,
                timeout_milliseconds,
                Arc::clone(&failure),
            ) {
                Ok(mut worker) => {
                    worker.mark_running();
                    workers.push(worker);
                    ready_events.push(ready);
                    created += 1;
                }
                Err(error) => {
                    report(error.stage, error.code);
                    failure.store(true, Ordering::Release);
                    break;
                }
            }
        }

        // Admission opens only when every worker exists.
        let mut acceptor = None;
        if !failure.load(Ordering::Acquire) {
            let ports: Vec<SendHandle> = workers.iter().map(TcpWorker::port_handle).collect();
            match AcceptorRuntime::initialize(options, created, ports, Arc::clone(&failure)) {
                Some(runtime) => acceptor = Some(runtime),
                None => failure.store(true, Ordering::Release),
            }
        }
        if acceptor.is_none() {
            // No thread was started, so the workers are released without ever running.
            for worker in workers {
                worker.destroy();
            }
            return ExitCode::Network;
        }
        let Some(mut acceptor_runtime) = acceptor.take() else {
            for worker in workers {
                worker.destroy();
            }
            return ExitCode::Network;
        };
        let table = acceptor_runtime.table();
        let acceptor_port = acceptor_runtime.port_handle();

        // Worker threads: each owns its worker, and the table it needs for a handoff.
        let mut controls: Vec<WorkerControl> = Vec::with_capacity(workers.len());
        for (index, worker) in workers.into_iter().enumerate() {
            let ready = SendHandle(ready_events[index].raw());
            let stop_clone = Arc::clone(stop);
            let table_clone = Arc::clone(&table);
            let port = worker.port_handle();
            let join = thread::spawn(move || {
                let mut worker = worker;
                let report = worker.run(&stop_clone, &table_clone, ready);
                // The thread owns the worker, so the release happens here and not in the
                // coordinator: RIO must not be touched after the owning thread ended.
                worker.destroy();
                report
            });
            controls.push(WorkerControl { port, join });
        }
        for event in &ready_events {
            let status = unsafe { windows::Win32::synchapi::WaitForSingleObject(event.raw(), u32::MAX) };
            if status != crate::types::WAIT_OBJECT_0 {
                report("worker startup readiness", ERROR_INVALID_DATA);
                failure.store(true, Ordering::Release);
            }
        }

        let acceptor_join = thread::spawn(move || acceptor_runtime.run());

        let start = now_milliseconds();
        while !failure.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
            if options.run_seconds != 0
                && now_milliseconds().saturating_sub(start) >= u64::from(options.run_seconds) * 1_000
            {
                stop.store(true, Ordering::Release);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        if let Err(error) = post_completion(acceptor_port.0, STOP_KEY, ptr::null_mut()) {
            fail_fast("PostQueuedCompletionStatus(acceptor stop)", error.code);
        }
        if acceptor_join.join().is_err() {
            // A panicking acceptor thread still has to fail the run: the workers below must
            // not be told that admission closed normally.
            failure.store(true, Ordering::Release);
        }
        for control in &controls {
            if let Err(error) = post_completion(control.port.0, ADMISSION_CLOSED_KEY, ptr::null_mut()) {
                fail_fast("PostQueuedCompletionStatus(worker admission closed)", error.code);
            }
            if let Err(error) = post_completion(control.port.0, STOP_KEY, ptr::null_mut()) {
                fail_fast("PostQueuedCompletionStatus(worker stop)", error.code);
            }
        }

        let mut statistics = Statistics::default();
        for control in controls {
            match control.join.join() {
                Ok(report) => {
                    statistics.merge(&report.statistics);
                    if options.stats {
                        println!("{}", report.statistics.worker_line(report.index, report.active));
                    }
                }
                Err(_) => failure.store(true, Ordering::Release),
            }
        }
        if options.stats {
            println!(
                "{}",
                statistics.final_line(
                    Protocol::Tcp,
                    now_milliseconds().saturating_sub(start),
                    worker_count,
                    0
                )
            );
        }
        if failure.load(Ordering::Acquire) { ExitCode::Network } else { ExitCode::Success }
    }

    impl AcceptorRuntime {
        /// Runs the acceptor loop until it stops and every operation has been recycled.
        fn run(&mut self) {
            for index in self.core.initial_posts() {
                if !self.post_accept(index) {
                    self.fail_admission("AcceptEx(initial)", ERROR_INVALID_DATA);
                    break;
                }
            }
            while !self.core.stopping || self.core.has_live() {
                let packet = get_queued_completion_status(self.port.raw(), 100);
                if packet.overlapped.is_null() && packet.key == STOP_KEY {
                    self.stop_admission();
                    continue;
                }
                if packet.overlapped.is_null() && packet.key > STOP_KEY {
                    let Some(operation) = self.table.find(packet.key) else {
                        fail_fast("server accept acknowledgement identity", ERROR_INVALID_DATA);
                    };
                    let index = operation.index;
                    // The worker adopts or closes the socket before acknowledging; anything
                    // still attached here is a stray the acceptor reclaims.
                    if let Some(stray) = self.table.clear_socket(index) {
                        if stray != INVALID_SOCKET {
                            let mut owner = SocketOwner::new(stray);
                            owner.reset();
                        }
                    }
                    match self.core.on_ack(index) {
                        AcceptAction::Repost { index } => {
                            if !self.post_accept(index) {
                                self.fail_admission("AcceptEx(repost)", ERROR_INVALID_DATA);
                            }
                        }
                        AcceptAction::None => {}
                        _ => fail_fast("server accept acknowledgement state", ERROR_INVALID_DATA),
                    }
                    continue;
                }
                if !packet.overlapped.is_null() {
                    let Some(operation) = self.table.find(packet.overlapped as usize) else {
                        fail_fast("server AcceptEx completion identity", ERROR_INVALID_DATA);
                    };
                    let index = operation.index;
                    if self.table.overlapped_ptr(index) != packet.overlapped {
                        fail_fast("server AcceptEx completion identity", ERROR_INVALID_DATA);
                    }
                    match self.core.on_completion(index, packet.succeeded, packet.error) {
                        AcceptAction::Repost { index } => {
                            if !self.post_accept(index) {
                                self.fail_admission("AcceptEx(repost after reset)", ERROR_INVALID_DATA);
                            }
                        }
                        AcceptAction::Handoff { index, worker } => match self.handoff(index, worker) {
                            HandoffOutcome::Posted => {}
                            HandoffOutcome::Withdrawn => {
                                // The acceptor closed this socket while unposting (a stop raced
                                // the completion); the slot goes back to idle and admission
                                // stays healthy unless it was not stopping.
                                self.core.abort_handoff(index);
                                if !self.core.stopping {
                                    self.fail_admission("AcceptEx handoff withdrawn", ERROR_INVALID_DATA);
                                }
                            }
                            HandoffOutcome::Failed => {
                                self.core.abort_handoff(index);
                                self.fail_admission("AcceptEx handoff", ERROR_INVALID_DATA);
                            }
                        },
                        AcceptAction::Fatal { error, .. } => {
                            self.fail_admission("AcceptEx completion", error as i32);
                        }
                        AcceptAction::None => {}
                    }
                    continue;
                }
                if !packet.succeeded && packet.error != WAIT_TIMEOUT {
                    self.fail_admission("GetQueuedCompletionStatus(acceptor)", packet.error as i32);
                }
            }
        }

        /// Applies the accept context, transfers the socket to the worker and posts the
        /// handoff. Ownership leaves this thread with the transfer.
        fn handoff(&mut self, index: u32, worker: u32) -> HandoffOutcome {
            let socket = self.operation_sockets[index as usize].release();
            if socket == INVALID_SOCKET {
                // The socket is gone because the acceptor closed it while unposting; a stop
                // that raced a successful completion lands here.
                return HandoffOutcome::Withdrawn;
            }
            self.table.store_socket(index, socket);
            if let Err(error) = update_accept_context(socket, self.listener.raw()) {
                report(error.stage, error.code);
                self.close_accept_socket(index);
                return HandoffOutcome::Failed;
            }
            if let Err(error) = configure_socket(socket, true, self.socket_buffer_bytes) {
                report(error.stage, error.code);
                self.close_accept_socket(index);
                return HandoffOutcome::Failed;
            }
            let Some(target) = self.workers.get(worker as usize).copied() else {
                report("server acceptor worker table", ERROR_INVALID_DATA);
                self.close_accept_socket(index);
                return HandoffOutcome::Failed;
            };
            let Some(key) = self
                .table
                .operation(index)
                .map(|operation| operation as *const crate::acceptor::AcceptOperation as usize)
            else {
                report("server accept handoff identity", ERROR_INVALID_DATA);
                self.close_accept_socket(index);
                return HandoffOutcome::Failed;
            };
            if let Err(error) = post_completion(target.0, key, ptr::null_mut()) {
                report(error.stage, error.code);
                self.close_accept_socket(index);
                return HandoffOutcome::Failed;
            }
            HandoffOutcome::Posted
        }
    }
}

pub mod timer {
    //! Worker-private index minimum heap over connection deadlines.
    //!
    //! Only the owning thread touches it, so no synchronisation is needed. The heap keeps a
    //! position map so a connection's deadline can be updated or removed in place, and its
    //! capacity is fixed for the whole run: it never grows past the worker's slot count.
    //!
    //! This is the same structure as ces_timer_heap in the C++ baseline and CESTimerHeap in
    //! the Swift port, including the order rule (deadline, then index) and the wait rule
    //! (INFINITE when empty, saturated one below INFINITE otherwise).

    use crate::types::{TimerNode, INFINITE};

    #[derive(Debug)]
    pub struct TimerHeap {
        capacity: usize,
        size: usize,
        nodes: Vec<TimerNode>,
        /// Position of a connection inside `nodes`, or -1 when it has no deadline.
        positions: Vec<i32>,
    }

    impl TimerHeap {
        pub fn new(capacity: usize) -> Self {
            Self {
                capacity,
                size: 0,
                nodes: vec![TimerNode::default(); capacity],
                positions: vec![-1; capacity],
            }
        }

        pub fn capacity(&self) -> usize {
            self.capacity
        }

        pub fn len(&self) -> usize {
            self.size
        }

        pub fn is_empty(&self) -> bool {
            self.size == 0
        }

        pub fn contains(&self, connection_index: u32) -> bool {
            (connection_index as usize) < self.capacity && self.positions[connection_index as usize] >= 0
        }

        pub fn next_deadline(&self) -> Option<u64> {
            if self.size == 0 { None } else { Some(self.nodes[0].deadline) }
        }

        /// Position of a connection inside the heap, as the reference model reads it.
        pub fn position_of(&self, connection_index: u32) -> Option<usize> {
            if (connection_index as usize) >= self.capacity {
                return None;
            }
            let position = self.positions[connection_index as usize];
            if position < 0 { None } else { Some(position as usize) }
        }

        fn less(&self, a: usize, b: usize) -> bool {
            let left = self.nodes[a];
            let right = self.nodes[b];
            (left.deadline, left.connection_index) < (right.deadline, right.connection_index)
        }

        fn swap(&mut self, a: usize, b: usize) {
            self.nodes.swap(a, b);
            let left = self.nodes[a].connection_index as usize;
            let right = self.nodes[b].connection_index as usize;
            self.positions[left] = a as i32;
            self.positions[right] = b as i32;
        }

        fn sift_up(&mut self, mut index: usize) {
            while index > 0 {
                let parent = (index - 1) / 2;
                if !self.less(index, parent) {
                    break;
                }
                self.swap(index, parent);
                index = parent;
            }
        }

        fn sift_down(&mut self, mut index: usize) {
            loop {
                let left = index * 2 + 1;
                if left >= self.size {
                    break;
                }
                let right = left + 1;
                let smallest = if right < self.size && self.less(right, left) { right } else { left };
                if !self.less(smallest, index) {
                    break;
                }
                self.swap(index, smallest);
                index = smallest;
            }
        }

        /// Schedules or reschedules a connection. Returns false when the index is outside the
        /// fixed capacity or the heap is full: the caller must treat that as a hard failure
        /// instead of silently dropping a deadline.
        pub fn insert_or_update(&mut self, deadline: u64, connection_index: u32) -> bool {
            let slot = connection_index as usize;
            if slot >= self.capacity {
                return false;
            }
            let existing = self.positions[slot];
            if existing >= 0 {
                let position = existing as usize;
                let previous = self.nodes[position].deadline;
                if deadline == previous {
                    return true;
                }
                self.nodes[position].deadline = deadline;
                if deadline < previous {
                    self.sift_up(position);
                } else {
                    self.sift_down(position);
                }
                return true;
            }
            if self.size == self.capacity {
                return false;
            }
            let position = self.size;
            self.size += 1;
            self.nodes[position] = TimerNode { deadline, connection_index };
            self.positions[slot] = position as i32;
            self.sift_up(position);
            true
        }

        /// Drops a connection's deadline. Removing an unscheduled connection is not an error.
        pub fn remove(&mut self, connection_index: u32) -> bool {
            let slot = connection_index as usize;
            if slot >= self.capacity {
                return false;
            }
            let position = self.positions[slot];
            if position < 0 {
                return false;
            }
            let position = position as usize;
            self.positions[slot] = -1;
            let last = self.size - 1;
            self.size = last;
            if position != last {
                self.nodes[position] = self.nodes[last];
                self.positions[self.nodes[position].connection_index as usize] = position as i32;
                let parent = if position > 0 { Some((position - 1) / 2) } else { None };
                if let Some(parent) = parent {
                    if self.less(position, parent) {
                        self.sift_up(position);
                        return true;
                    }
                }
                self.sift_down(position);
            }
            true
        }

        /// Wakes up only the connections whose deadline has passed. Each removed connection is
        /// reported so the caller can close it.
        pub fn pop_expired(&mut self, now: u64, out: &mut Vec<u32>) -> usize {
            let mut count = 0;
            while self.size > 0 && self.nodes[0].deadline <= now {
                let node = self.nodes[0];
                self.remove(node.connection_index);
                out.push(node.connection_index);
                count += 1;
            }
            count
        }

        /// Milliseconds to wait for the nearest deadline: INFINITE when nothing is scheduled,
        /// zero when the nearest deadline has already passed, and otherwise one below INFINITE
        /// at most so the value is always a usable timeout.
        pub fn wait_milliseconds(&self, now: u64) -> u32 {
            let Some(deadline) = self.next_deadline() else {
                return INFINITE;
            };
            if deadline <= now {
                return 0;
            }
            let remaining = deadline - now;
            remaining.min(u64::from(INFINITE) - 1) as u32
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::types::WAIT_TIMEOUT;

        fn xorshift(state: &mut u32) -> u32 {
            let mut value = *state;
            value ^= value << 13;
            value ^= value >> 17;
            value ^= value << 5;
            *state = value;
            value
        }

        #[test]
        fn orders_by_deadline_then_index() {
            let mut heap = TimerHeap::new(8);
            assert!(heap.insert_or_update(30, 2));
            assert!(heap.insert_or_update(10, 1));
            assert!(heap.insert_or_update(20, 0));
            assert_eq!(heap.next_deadline(), Some(10));
            let mut expired = Vec::new();
            assert_eq!(heap.pop_expired(25, &mut expired), 2);
            assert_eq!(expired, vec![1, 0]);
            assert_eq!(heap.next_deadline(), Some(30));
            assert_eq!(heap.len(), 1);
            // Equal deadlines are ordered by connection index.
            let mut tied = TimerHeap::new(4);
            assert!(tied.insert_or_update(50, 3));
            assert!(tied.insert_or_update(50, 1));
            let mut expired = Vec::new();
            // Both deadlines passed at once; the pop order is by index.
            assert_eq!(tied.pop_expired(50, &mut expired), 2);
            assert_eq!(expired, vec![1, 3]);
            // Nothing else was due before the deadline.
            let mut early = TimerHeap::new(2);
            assert!(early.insert_or_update(50, 0));
            assert!(early.insert_or_update(50, 1));
            let mut expired = Vec::new();
            assert_eq!(early.pop_expired(49, &mut expired), 0);
            assert!(expired.is_empty());
        }

        #[test]
        fn update_moves_the_entry_in_both_directions() {
            let mut heap = TimerHeap::new(4);
            assert!(heap.insert_or_update(100, 0));
            assert!(heap.insert_or_update(200, 1));
            assert!(heap.insert_or_update(5, 0));
            assert_eq!(heap.next_deadline(), Some(5));
            assert_eq!(heap.len(), 2);
            assert!(heap.insert_or_update(500, 0));
            assert_eq!(heap.next_deadline(), Some(200));
            assert!(heap.contains(0));
            // Re-scheduling the same deadline keeps the entry where it is.
            assert!(heap.insert_or_update(500, 0));
            assert_eq!(heap.next_deadline(), Some(200));
        }

        #[test]
        fn remove_reports_missing_entries_and_repairs_the_heap() {
            let mut heap = TimerHeap::new(4);
            assert!(!heap.remove(0));
            assert!(heap.insert_or_update(10, 0));
            assert!(heap.insert_or_update(20, 1));
            assert!(heap.insert_or_update(30, 2));
            assert!(heap.remove(0));
            assert!(!heap.contains(0));
            assert_eq!(heap.next_deadline(), Some(20));
            assert_eq!(heap.len(), 2);
            assert!(heap.remove(2));
            assert_eq!(heap.next_deadline(), Some(20));
        }

        #[test]
        fn capacity_is_fixed_and_indices_are_bounds_checked() {
            let mut heap = TimerHeap::new(2);
            assert!(heap.insert_or_update(1, 0));
            assert!(heap.insert_or_update(2, 1));
            // Full: a third distinct connection is refused instead of growing the heap.
            assert!(!heap.insert_or_update(3, 2));
            // Out-of-range indices are refused even when a slot is free.
            assert!(!heap.insert_or_update(3, 99));
            assert!(!heap.remove(99));
            assert_eq!(heap.len(), 2);
        }

        #[test]
        fn wait_is_infinite_when_empty_and_saturates_below_infinite() {
            let mut heap = TimerHeap::new(2);
            assert_eq!(heap.wait_milliseconds(10), INFINITE);
            assert!(heap.insert_or_update(20, 0));
            assert_eq!(heap.wait_milliseconds(10), 10);
            assert_eq!(heap.wait_milliseconds(20), 0);
            assert_eq!(heap.wait_milliseconds(25), 0);
            assert!(heap.insert_or_update(u64::MAX, 0));
            assert_eq!(heap.wait_milliseconds(0), INFINITE - 1);
            assert_ne!(heap.wait_milliseconds(0), WAIT_TIMEOUT + 1);
        }

        #[test]
        fn heap_matches_a_fixed_seed_reference_model() {
            const CAPACITY: u32 = 64;
            const STEPS: u32 = 20_000;
            let mut heap = TimerHeap::new(CAPACITY as usize);
            let mut active = vec![false; CAPACITY as usize];
            let mut deadlines = vec![0u64; CAPACITY as usize];
            let mut state = 0x51A7_E123u32;
            for step in 0..STEPS {
                let operation = xorshift(&mut state) & 3;
                let index = xorshift(&mut state) % CAPACITY;
                let now = u64::from(step % 4096);
                match operation {
                    0 | 1 => {
                        let deadline = u64::from(xorshift(&mut state) % 4096);
                        assert!(heap.insert_or_update(deadline, index));
                        active[index as usize] = true;
                        deadlines[index as usize] = deadline;
                    }
                    2 => {
                        let expected = active[index as usize];
                        assert_eq!(heap.remove(index), expected);
                        active[index as usize] = false;
                    }
                    _ => {
                        // pop_expired drains every deadline that has passed, ordered by
                        // (deadline, index): the reference model builds that list directly.
                        let mut expected: Vec<u32> = (0..CAPACITY)
                            .filter(|candidate| {
                                active[*candidate as usize] && deadlines[*candidate as usize] <= now
                            })
                            .collect();
                        expected.sort_by_key(|candidate| (deadlines[*candidate as usize], *candidate));
                        let mut expired = Vec::new();
                        let count = heap.pop_expired(now, &mut expired);
                        assert_eq!(count, expected.len());
                        assert_eq!(expired, expected);
                        for index in &expected {
                            active[*index as usize] = false;
                        }
                    }
                }

                // The heap root, the position map and the size must agree with the model.
                let mut minimum: Option<u32> = None;
                let mut active_count = 0;
                for index in 0..CAPACITY {
                    if !active[index as usize] {
                        assert!(!heap.contains(index));
                        continue;
                    }
                    active_count += 1;
                    let position = heap.position_of(index).expect("scheduled connection has a position");
                    assert!(position < heap.len());
                    assert_eq!(heap.nodes[position].connection_index, index);
                    assert_eq!(heap.nodes[position].deadline, deadlines[index as usize]);
                    let better = match minimum {
                        None => true,
                        Some(current) => {
                            (deadlines[index as usize], index) < (deadlines[current as usize], current)
                        }
                    };
                    if better {
                        minimum = Some(index);
                    }
                }
                assert_eq!(heap.len(), active_count);
                if let Some(index) = minimum {
                    assert_eq!(heap.nodes[0].connection_index, index);
                    assert_eq!(heap.nodes[0].deadline, deadlines[index as usize]);
                }
                let expected_wait = match minimum {
                    None => INFINITE,
                    Some(index) if deadlines[index as usize] <= now => 0,
                    Some(index) => (deadlines[index as usize] - now).min(u64::from(INFINITE) - 1) as u32,
                };
                assert_eq!(heap.wait_milliseconds(now), expected_wait);
            }
        }
    }
}
}
