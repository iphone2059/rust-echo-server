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

use crate::internal::acceptor::AcceptTable;
use crate::arena::Arena;
use crate::contract::notification_packet_matches;
use crate::engine::{Step, TcpEngine};
use crate::native::{
    fail_fast, now_milliseconds, report, NativeError, RioFunctions, SendHandle, SocketOwner,
};
use crate::rio::{
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
            // handoff, and the acceptor reposts the operation.
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
        let key = operation as *const crate::internal::acceptor::AcceptOperation as usize;
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




