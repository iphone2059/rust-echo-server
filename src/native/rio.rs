//! RIO objects: completion ports and queues, registered buffers and request queues.
//!
//! Every call goes through the extension table loaded in `native`: RIO exports no
//! importable symbols, so a table entry that is missing is a hard error rather than a
//! silent fallback.

use core::ffi::c_void;
use core::ptr;

use windows::Win32::ioapiset::CreateIoCompletionPort;
use windows::Win32::mswsock::{
    RIO_IOCP_COMPLETION, RIO_NOTIFICATION_COMPLETION, RIO_NOTIFICATION_COMPLETION_0,
    RIO_NOTIFICATION_COMPLETION_0_1,
};
use windows::Win32::mswsockdef::{RIO_BUF, RIO_BUFFERID, RIO_CQ, RIO_RQ, RIORESULT};
use windows::Win32::winsock2::SOCKET;
use windows::Win32::{HANDLE, INVALID_HANDLE_VALUE};

use crate::native::{NativeError, RioFunctions};

/// The IOCP handle RIO signals when a completion queue becomes readable.
pub struct CompletionPort {
    handle: HANDLE,
}

impl CompletionPort {
    /// One concurrent thread per port, which is how the baseline sizes every worker port.
    pub fn create() -> Result<Self, NativeError> {
        let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(NativeError::last("CreateIoCompletionPort"));
        }
        Ok(Self { handle })
    }

    pub fn raw(&self) -> HANDLE {
        self.handle
    }

    /// Associates a socket with this port so its overlapped I/O completes here. The
    /// listener uses this to publish AcceptEx completions.
    pub fn associate_socket(&self, socket: SOCKET) -> Result<(), NativeError> {
        let associated = unsafe {
            CreateIoCompletionPort(socket as HANDLE, Some(self.handle), 0, 1)
        };
        if associated != self.handle {
            return Err(NativeError::last("CreateIoCompletionPort(listener association)"));
        }
        Ok(())
    }

    pub fn post(&self, key: usize, overlapped: *mut c_void) -> Result<(), NativeError> {
        let posted = unsafe {
            windows::Win32::ioapiset::PostQueuedCompletionStatus(
                self.handle,
                0,
                key,
                if overlapped.is_null() { None } else { Some(overlapped as *mut windows::Win32::minwinbase::OVERLAPPED) },
            )
        };
        if !posted.as_bool() {
            return Err(NativeError::last("PostQueuedCompletionStatus"));
        }
        Ok(())
    }
}

impl Drop for CompletionPort {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && !self.handle.is_null() {
            unsafe {
                // The result is not actionable: the port is being dropped either way.
                let _ = windows::Win32::handleapi::CloseHandle(self.handle);
            }
        }
    }
}

/// A RIO completion queue bound to an IOCP. Exactly one notification registration may be
/// outstanding at a time, which the armed flag tracks.
pub struct CompletionQueue {
    queue: RIO_CQ,
    capacity: u32,
    armed: bool,
}

impl CompletionQueue {
    pub fn create(
        rio: &RioFunctions,
        port: &CompletionPort,
        capacity: u32,
        completion_key: *mut c_void,
        overlapped: *mut c_void,
    ) -> Result<Self, NativeError> {
        if capacity == 0 {
            return Err(NativeError { stage: "RIOCreateCompletionQueue capacity", code: 13 });
        }
        let create = rio
            .table()
            .RIOCreateCompletionQueue
            .ok_or(NativeError { stage: "RIOCreateCompletionQueue entry point", code: 13 })?;
        let mut notification = RIO_NOTIFICATION_COMPLETION::default();
        notification.Type = RIO_IOCP_COMPLETION;
        notification.Anonymous = RIO_NOTIFICATION_COMPLETION_0 {
            Iocp: RIO_NOTIFICATION_COMPLETION_0_1 {
                IocpHandle: port.raw(),
                CompletionKey: completion_key,
                Overlapped: overlapped,
            },
        };
        let queue = unsafe { create(capacity, &mut notification as *mut RIO_NOTIFICATION_COMPLETION) };
        if queue.is_null() {
            return Err(NativeError::last("RIOCreateCompletionQueue"));
        }
        Ok(Self { queue, capacity, armed: false })
    }

    pub fn raw(&self) -> RIO_CQ {
        self.queue
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// Arms the IOCP notification. Calling it while a registration is already outstanding
    /// is refused: the baseline treats a duplicate RIONotify as an invariant violation.
    pub fn arm(&mut self, rio: &RioFunctions) -> Result<(), NativeError> {
        if self.armed {
            return Err(NativeError { stage: "duplicate RIONotify", code: 5023 });
        }
        let notify = rio
            .table()
            .RIONotify
            .ok_or(NativeError { stage: "RIONotify entry point", code: 13 })?;
        // Only ERROR_SUCCESS is accepted: any other status leaves the queue unarmed and the
        // caller must not assume a wake-up is coming.
        let status = unsafe { notify(self.queue) };
        if status != 0 {
            return Err(NativeError { stage: "RIONotify", code: status });
        }
        self.armed = true;
        Ok(())
    }

    /// A delivery clears the armed state; the next queued operation re-arms it.
    pub fn on_delivery(&mut self) {
        self.armed = false;
    }

    /// Drains up to `results.len()` completions. RIO_CORRUPT_CQ is reported as a hard
    /// failure instead of being mistaken for "no work".
    pub fn dequeue(&mut self, rio: &RioFunctions, results: &mut [RIORESULT]) -> Result<u32, NativeError> {
        let dequeue = rio
            .table()
            .RIODequeueCompletion
            .ok_or(NativeError { stage: "RIODequeueCompletion entry point", code: 13 })?;
        let capacity = u32::try_from(results.len())
            .map_err(|_| NativeError { stage: "RIODequeueCompletion capacity", code: 13 })?;
        // The array size is independent of the queue size: RIO returns at most as many
        // entries as there are completions, and the baseline always passes its full batch
        // buffer even when /cq reserved fewer entries than that.
        if capacity == 0 {
            return Err(NativeError { stage: "RIODequeueCompletion capacity", code: 13 });
        }
        let count = unsafe { dequeue(self.queue, results.as_mut_ptr(), capacity) };
        if count == u32::MAX {
            return Err(NativeError { stage: "RIODequeueCompletion(RIO_CORRUPT_CQ)", code: 13 });
        }
        if count > capacity {
            return Err(NativeError { stage: "RIODequeueCompletion count", code: 13 });
        }
        Ok(count)
    }

    /// Closes the queue through the table. The owner calls this after every worker thread
    /// has joined, so no completion can be lost by closing early.
    pub fn close(&mut self, rio: &RioFunctions) {
        if self.queue.is_null() {
            return;
        }
        if let Some(close) = rio.table().RIOCloseCompletionQueue {
            unsafe { close(self.queue) };
        }
        self.queue = ptr::null_mut();
        self.armed = false;
    }
}

impl Drop for CompletionQueue {
    fn drop(&mut self) {
        // Closing happens through `close`, which has the extension table; dropping only
        // forgets the handle so a partially initialised engine cannot double close.
        self.queue = ptr::null_mut();
    }
}
/// A registered memory region. RIO requires every buffer to be registered before it can
/// be referenced by a RIO_BUF.
pub struct RegisteredBuffer {
    id: RIO_BUFFERID,
    length: u32,
}

impl RegisteredBuffer {
    pub fn register(rio: &RioFunctions, bytes: &mut [u8]) -> Result<Self, NativeError> {
        let register = rio
            .table()
            .RIORegisterBuffer
            .ok_or(NativeError { stage: "RIORegisterBuffer entry point", code: 13 })?;
        let length = u32::try_from(bytes.len())
            .map_err(|_| NativeError { stage: "RIORegisterBuffer length", code: 13 })?;
        if length == 0 {
            return Err(NativeError { stage: "RIORegisterBuffer length", code: 13 });
        }
        let id = unsafe { register(bytes.as_mut_ptr() as *mut i8, length) };
        if id.is_null() {
            return Err(NativeError::last("RIORegisterBuffer"));
        }
        Ok(Self { id, length })
    }

    pub fn raw(&self) -> RIO_BUFFERID {
        self.id
    }

    pub fn length(&self) -> u32 {
        self.length
    }

    /// Builds a descriptor for a slice of the registered region. Bounds are checked here so
    /// the engine can never hand RIO an out-of-range view.
    pub fn slice(&self, offset: u32, length: u32) -> Result<RIO_BUF, NativeError> {
        if length == 0 || offset > self.length || length > self.length - offset {
            return Err(NativeError { stage: "RIO_BUF slice bounds", code: 13 });
        }
        Ok(RIO_BUF { BufferId: self.id, Offset: offset, Length: length })
    }

    /// Deregisters the region through the table. The owner calls this after every posted
    /// request has completed.
    pub fn deregister(&mut self, rio: &RioFunctions) {
        if self.id.is_null() {
            return;
        }
        if let Some(deregister) = rio.table().RIODeregisterBuffer {
            unsafe { deregister(self.id) };
        }
        self.id = ptr::null_mut();
        self.length = 0;
    }
}

/// A RIO request queue over one socket. The same queue carries receives and sends; the
/// UDP engine additionally uses the explicit-address variants.
pub struct RequestQueue {
    queue: RIO_RQ,
}

impl RequestQueue {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        rio: &RioFunctions,
        socket: SOCKET,
        receive_depth: u32,
        receive_buffers: u32,
        send_depth: u32,
        send_buffers: u32,
        receive_queue: RIO_CQ,
        send_queue: RIO_CQ,
        socket_context: *mut c_void,
    ) -> Result<Self, NativeError> {
        let create = rio
            .table()
            .RIOCreateRequestQueue
            .ok_or(NativeError { stage: "RIOCreateRequestQueue entry point", code: 13 })?;
        let queue = unsafe {
            create(
                socket,
                receive_depth,
                receive_buffers,
                send_depth,
                send_buffers,
                receive_queue,
                send_queue,
                socket_context,
            )
        };
        if queue.is_null() {
            return Err(NativeError::last("RIOCreateRequestQueue"));
        }
        Ok(Self { queue })
    }

    pub fn raw(&self) -> RIO_RQ {
        self.queue
    }

    /// Posts a receive. `request_context` is what comes back in the RIORESULT.
    pub fn receive(&self, rio: &RioFunctions, buffer: &mut RIO_BUF, request_context: *const c_void)
        -> Result<(), NativeError>
    {
        let receive = rio
            .table()
            .RIOReceive
            .ok_or(NativeError { stage: "RIOReceive entry point", code: 13 })?;
        let ok = unsafe { receive(self.queue, buffer, 1, 0, request_context) };
        if !ok.as_bool() {
            return Err(NativeError::last("RIOReceive"));
        }
        Ok(())
    }

    /// Posts a send of one buffer.
    pub fn send(&self, rio: &RioFunctions, buffer: &mut RIO_BUF, request_context: *const c_void)
        -> Result<(), NativeError>
    {
        let send = rio
            .table()
            .RIOSend
            .ok_or(NativeError { stage: "RIOSend entry point", code: 13 })?;
        let ok = unsafe { send(self.queue, buffer, 1, 0, request_context) };
        if !ok.as_bool() {
            return Err(NativeError::last("RIOSend"));
        }
        Ok(())
    }

    /// Posts an addressed receive. The UDP engine keeps a remote-address buffer per slot so
    /// the echo can be sent back to whoever sent the datagram.
    pub fn receive_ex(
        &self,
        rio: &RioFunctions,
        buffer: &mut RIO_BUF,
        remote_address: &mut RIO_BUF,
        request_context: *const c_void,
    ) -> Result<(), NativeError> {
        let receive = rio
            .table()
            .RIOReceiveEx
            .ok_or(NativeError { stage: "RIOReceiveEx entry point", code: 13 })?;
        let status = unsafe {
            receive(self.queue, buffer, 1, ptr::null_mut(), remote_address, ptr::null_mut(), ptr::null_mut(), 0, request_context)
        };
        if status == 0 {
            return Err(NativeError::last("RIOReceiveEx"));
        }
        Ok(())
    }

    /// Posts an addressed send of the bytes the matching receive received.
    pub fn send_ex(
        &self,
        rio: &RioFunctions,
        buffer: &mut RIO_BUF,
        remote_address: &mut RIO_BUF,
        request_context: *const c_void,
    ) -> Result<(), NativeError> {
        let send = rio
            .table()
            .RIOSendEx
            .ok_or(NativeError { stage: "RIOSendEx entry point", code: 13 })?;
        let ok = unsafe {
            send(self.queue, buffer, 1, ptr::null_mut(), remote_address, ptr::null_mut(), ptr::null_mut(), 0, request_context)
        };
        if !ok.as_bool() {
            return Err(NativeError::last("RIOSendEx"));
        }
        Ok(())
    }
}

/// Zeroed result slot: RIO writes every field of each dequeued entry.
pub fn empty_result() -> RIORESULT {
    RIORESULT { Status: 0, BytesTransferred: 0, SocketContext: 0, RequestContext: 0 }
}

/// One packet from an IOCP queue.
pub struct CompletionPacket {
    pub succeeded: bool,
    pub transferred: u32,
    pub key: usize,
    pub overlapped: *mut windows::Win32::minwinbase::OVERLAPPED,
    pub error: u32,
}

/// Blocks for up to `wait_milliseconds` for a packet. A timeout reports `succeeded == false`,
/// `error == WAIT_TIMEOUT` and a null OVERLAPPED, which is how the baseline tells a timeout
/// apart from a port failure.
pub fn get_queued_completion_status(
    port: HANDLE,
    wait_milliseconds: u32,
) -> CompletionPacket {
    let mut transferred: u32 = 0;
    // ULONG_PTR is u64 on x64; the packet reports it as usize, which is the same width.
    let mut key: u64 = 0;
    let mut overlapped: *mut windows::Win32::minwinbase::OVERLAPPED = ptr::null_mut();
    let ok = unsafe {
        windows::Win32::ioapiset::GetQueuedCompletionStatus(
            port,
            &mut transferred,
            &mut key,
            &mut overlapped,
            wait_milliseconds,
        )
    }
    .as_bool();
    let error = if ok {
        0
    } else {
        unsafe { windows::Win32::errhandlingapi::GetLastError() }
    };
    CompletionPacket { succeeded: ok, transferred, key: key as usize, overlapped, error }
}

/// Posts a control packet to a port the caller does not own: the acceptor hands a socket to
/// a worker this way, and a worker acknowledges it the same way.
pub fn post_completion(
    port: HANDLE,
    key: usize,
    overlapped: *mut windows::Win32::minwinbase::OVERLAPPED,
) -> Result<(), NativeError> {
    let posted = unsafe {
        windows::Win32::ioapiset::PostQueuedCompletionStatus(
            port,
            0,
            key,
            if overlapped.is_null() { None } else { Some(overlapped) },
        )
    };
    if !posted.as_bool() {
        return Err(NativeError::last("PostQueuedCompletionStatus"));
    }
    Ok(())
}
