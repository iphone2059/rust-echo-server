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
            statistics.final_line(Protocol::Tcp, now_milliseconds().saturating_sub(start), 0)
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




