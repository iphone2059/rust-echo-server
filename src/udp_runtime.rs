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

use crate::arena::{udp_stride, Arena};
use crate::ces_contract::checked_arena_bytes;
use crate::native::{fail_fast, now_milliseconds, report, RioFunctions, SocketOwner};
use crate::rio::{
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
        if !crate::ces_contract::notification_mark_rearmed(armed) {
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
    if let Err(error) = crate::endpoint::bind_endpoint(socket.raw(), options.port) {
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
        if !runtime.engine.closing && (stop_now || expired) {
            // Closing the socket first is what cancels the posted requests; the drain below
            // then completes them all before any storage is released.
            runtime.engine.begin_drain();
            runtime.socket.reset();
        }
        let packet = get_queued_completion_status(runtime.port.raw(), 100);
        if packet.overlapped as usize == runtime.notification_address() {
            if !packet.succeeded {
                fail_fast("GetQueuedCompletionStatus(UDP notification)", packet.error as i32);
            }
            if !crate::ces_contract::notification_packet_matches(
                packet.key,
                packet.overlapped as usize,
                runtime.key_address(),
                runtime.notification_address(),
            ) {
                fail_fast("server UDP RIO notification key", ERROR_INVALID_DATA);
            }
            if !crate::ces_contract::notification_mark_delivered(&mut armed) {
                fail_fast("server UDP notification delivery transition", ERROR_INVALID_DATA);
            }
            runtime.queue.on_delivery();
            let rio = runtime.rio;
            for _ in 0..COMPLETION_DRAIN_BATCHES {
                // A saturated flood can keep the queue non-empty indefinitely, so the
                // bounded drain also observes the stop request and the run deadline: the
                // socket is closed here and no further request is reposted, which is what
                // keeps a controlled stop bounded under full load.
                if !runtime.engine.closing
                    && (stop.load(Ordering::Acquire) || now_milliseconds() >= run_deadline)
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
                        UdpAction::Fatal { error, .. } => report("UDP RIO completion", error),
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
        if !crate::ces_contract::notification_packet_matches(
            packet.key,
            packet.overlapped as usize,
            0,
            runtime.notification_address(),
        ) {
            fail_fast("UDP notification shutdown packet", ERROR_INVALID_DATA);
        }
        if !crate::ces_contract::notification_mark_delivered(&mut armed) {
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
        println!("{}", statistics.final_line(Protocol::Udp, elapsed, runtime.engine.outstanding));
    }
    // Release order of the baseline: completion queue, registration and arena, then the
    // socket, then the port. Nothing is outstanding, so no completion can be lost.
    let rio = runtime.rio;
    runtime.queue.close(&rio);
    runtime.arena.destroy(&rio);
    drop(runtime);
    if failed { ExitCode::Network } else { ExitCode::Success }
}

