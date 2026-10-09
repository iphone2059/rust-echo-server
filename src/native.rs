//! Win32/Winsock ownership, socket creation and configuration, the RIO extension table
//! and the AcceptEx entry point.
//!
//! windows-rs organises its generated surface by Windows header and its signatures differ
//! from the published 0.6x line (for example `WSASocketW` returns a raw `SOCKET` and
//! `WSAStartup` returns an `i32` status). Every path and signature used here was read from
//! the committed bindings under `crates/libs/windows/src/Windows/Win32/<header>/mod.rs` in
//! the resolved revision.

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;

use windows::Win32::errhandlingapi::GetLastError;
use windows::Win32::handleapi::CloseHandle;
use windows::Win32::mswsock::{LPFN_ACCEPTEX, RIO_EXTENSION_FUNCTION_TABLE};
use windows::Win32::winsock2::{
    SOCKET, WSA_FLAG_OVERLAPPED, WSA_FLAG_REGISTERED_IO, WSACleanup, WSADATA, WSASocketW,
    WSAStartup, WSAIoctl, closesocket, setsockopt, INVALID_SOCKET,
};
use windows::Win32::ws2::{
    AF_INET, IPPROTO_TCP, IPPROTO_UDP, SIO_GET_EXTENSION_FUNCTION_POINTER,
    SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, SO_RCVBUF, SO_SNDBUF, SOL_SOCKET, SOCK_DGRAM,
    SOCK_STREAM, TCP_NODELAY,
};
use windows::Win32::{HANDLE, INVALID_HANDLE_VALUE};
use windows::core::GUID;

use crate::types::Protocol;

/// A Win32 failure together with the API stage that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeError {
    pub stage: &'static str,
    pub code: i32,
}

impl NativeError {
    /// Captures the thread's last-error value at the failing call site; the value is never
    /// read back later, when another Win32 call would have overwritten it.
    pub fn last(stage: &'static str) -> Self {
        Self { stage, code: unsafe { GetLastError() } as i32 }
    }

    pub fn code(stage: &'static str, code: i32) -> Self {
        Self { stage, code }
    }
}

/// Winsock lifetime guard: construction starts Winsock, drop cleans it up.
pub struct Winsock {
    started: bool,
}

impl Winsock {
    pub fn start() -> Result<Self, NativeError> {
        let mut data = WSADATA::default();
        let status = unsafe { WSAStartup(0x0202, &mut data) };
        if status != 0 {
            return Err(NativeError { stage: "WSAStartup", code: status });
        }
        Ok(Self { started: true })
    }
}

impl Drop for Winsock {
    fn drop(&mut self) {
        if self.started {
            unsafe {
                WSACleanup();
            }
        }
    }
}

/// Sole owner of a socket. The numeric value never escapes without an explicit release,
/// which mirrors the move-only socket owners of the C++ and Swift ports.
pub struct SocketOwner {
    socket: SOCKET,
}

impl SocketOwner {
    pub fn new(socket: SOCKET) -> Self {
        Self { socket }
    }

    pub fn raw(&self) -> SOCKET {
        self.socket
    }

    /// Transfers ownership out of the guard; the guard no longer closes the socket.
    pub fn release(&mut self) -> SOCKET {
        core::mem::replace(&mut self.socket, INVALID_SOCKET)
    }

    pub fn reset(&mut self) {
        let value = self.release();
        if value != INVALID_SOCKET {
            unsafe {
                closesocket(value);
            }
        }
    }
}

impl Drop for SocketOwner {
    fn drop(&mut self) {
        self.reset();
    }
}

/// Sole owner of a Win32 handle (IOCP, event, thread). A null or INVALID_HANDLE_VALUE
/// owner closes nothing, which is what a partially initialised engine holds.
pub struct HandleOwner {
    handle: HANDLE,
}

impl HandleOwner {
    pub fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    pub fn raw(&self) -> HANDLE {
        self.handle
    }

    pub fn is_open(&self) -> bool {
        !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE
    }

    pub fn release(&mut self) -> HANDLE {
        core::mem::replace(&mut self.handle, ptr::null_mut())
    }

    pub fn reset(&mut self, handle: HANDLE) {
        let previous = core::mem::replace(&mut self.handle, handle);
        if !previous.is_null() && previous != INVALID_HANDLE_VALUE {
            unsafe {
                // The result is not actionable: the handle is being dropped either way.
                let _ = CloseHandle(previous);
            }
        }
    }
}

impl Drop for HandleOwner {
    fn drop(&mut self) {
        self.reset(ptr::null_mut());
    }
}
/// Creates a socket that is both overlapped and registered with RIO. Registration is a
/// hard requirement: RIO refuses to associate an unregistered socket with a queue.
pub fn registered_socket(protocol: Protocol) -> Result<SocketOwner, NativeError> {
    let (kind, transport) = match protocol {
        Protocol::Tcp => (SOCK_STREAM, IPPROTO_TCP),
        Protocol::Udp => (SOCK_DGRAM, IPPROTO_UDP),
        Protocol::None => {
            // 87 = ERROR_INVALID_PARAMETER, matching the baseline's rejected-protocol path.
            return Err(NativeError { stage: "registered_socket(protocol)", code: 87 });
        }
    };
    // The bindings expose the WSA_FLAG_* constants as i32; dwflags is u32.
    let flags = (WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO) as u32;
    let socket = unsafe { WSASocketW(AF_INET, kind, transport, None, 0, flags) };
    if socket == INVALID_SOCKET {
        return Err(NativeError::last("WSASocketW(AF_INET, registered)"));
    }
    Ok(SocketOwner::new(socket))
}

/// Configures a listening or accepted socket. Zero buffer sizes leave the system default
/// in place, which is what the baseline does when /b is absent. TCP_NODELAY is only
/// meaningful for stream sockets.
pub fn configure_socket(socket: SOCKET, tcp: bool, buffer_bytes: u32) -> Result<(), NativeError> {
    if buffer_bytes != 0 {
        let value = buffer_bytes as i32;
        for (stage, option) in [
            ("setsockopt(SO_SNDBUF)", SO_SNDBUF),
            ("setsockopt(SO_RCVBUF)", SO_RCVBUF),
        ] {
            let status = unsafe {
                setsockopt(
                    socket,
                    SOL_SOCKET,
                    option,
                    Some(&value as *const i32 as *const i8),
                    size_of::<i32>() as i32,
                )
            };
            if status != 0 {
                return Err(NativeError::last(stage));
            }
        }
    }
    if tcp {
        let value: i32 = 1;
        let status = unsafe {
            setsockopt(
                socket,
                IPPROTO_TCP,
                TCP_NODELAY,
                Some(&value as *const i32 as *const i8),
                size_of::<i32>() as i32,
            )
        };
        if status != 0 {
            return Err(NativeError::last("setsockopt(TCP_NODELAY)"));
        }
    }
    Ok(())
}

/// {8509E081-96DD-4005-B165-9E2EE8C79E3F}: the RIO extension identifier. The bindings do
/// not export the WSAID_* constants, so it is declared here with the value the C++ and
/// Swift ports already run against.
const WSAID_MULTIPLE_RIO: GUID = GUID::from_u128(0x8509_e081_96dd_4005_b165_9e2e_e8c7_9e3f);

/// {B5367DF1-CBAC-11CF-95CA-00805F48A192}: the AcceptEx identifier.
const WSAID_ACCEPTEX: GUID = GUID::from_u128(0xb536_7df1_cbac_11cf_95ca_0080_5f48_a192);

/// The RIO entry points. RIO is never imported as a flat symbol: every function is
/// reached through this table, which the provider fills in for the running stack. The
/// table is a plain function-pointer record, so it is copied into each worker thread.
#[derive(Clone, Copy)]
pub struct RioFunctions {
    table: RIO_EXTENSION_FUNCTION_TABLE,
}

impl RioFunctions {
    pub fn load(socket: SOCKET) -> Result<Self, NativeError> {
        let expected = size_of::<RIO_EXTENSION_FUNCTION_TABLE>() as u32;
        // The table is written by the provider, so it starts zeroed and cbSize is set.
        let mut table: RIO_EXTENSION_FUNCTION_TABLE = unsafe { core::mem::zeroed() };
        table.cbSize = expected;
        let mut returned: u32 = 0;
        let status = unsafe {
            WSAIoctl(
                socket,
                SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
                Some(&WSAID_MULTIPLE_RIO as *const GUID as *const c_void),
                size_of::<GUID>() as u32,
                Some(&mut table as *mut RIO_EXTENSION_FUNCTION_TABLE as *mut c_void),
                expected,
                &mut returned,
                None,
                None,
            )
        };
        if status != 0 {
            return Err(NativeError::last(
                "WSAIoctl(SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER)",
            ));
        }
        if returned != expected || table.cbSize != expected {
            return Err(NativeError { stage: "RIO table size", code: 13 });
        }
        Ok(Self { table })
    }

    pub fn table(&self) -> &RIO_EXTENSION_FUNCTION_TABLE {
        &self.table
    }
}

/// A raw handle that may cross a thread boundary. Ownership stays with the thread that
/// created the object; the receiving side only posts to it.
#[derive(Clone, Copy)]
pub struct SendHandle(pub HANDLE);

// SAFETY: every use transfers nothing but the handle value, and Windows handles are
// process-wide. Ownership and lifetime stay with the creating thread, which outlives the
// threads that only post to the handle.
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

/// Reports a native failure exactly like the baseline: stage plus the error value of the
/// API that failed.
pub fn report(stage: &str, code: i32) {
    eprintln!("{} failed: native_error={}", stage, code);
}

/// Internal invariant damage terminates deterministically with the internal exit code; no
/// retry, no completion-queue polling and no fallback data path exist.
pub fn fail_fast(stage: &str, code: i32) -> ! {
    report(stage, code);
    unsafe {
        let _ = windows::Win32::processthreadsapi::TerminateProcess(
            windows::Win32::processthreadsapi::GetCurrentProcess(),
            crate::types::ExitCode::Internal as u32,
        );
    }
    // TerminateProcess only fails for a handle without PROCESS_TERMINATE; the process is
    // still being torn down, so this thread must not resume the engine.
    loop {
        core::hint::spin_loop();
    }
}

/// Monotonic millisecond clock: GetTickCount64, which is what the baseline schedules on.
pub fn now_milliseconds() -> u64 {
    unsafe { windows::Win32::sysinfoapi::GetTickCount64() }
}

/// Processor count used when /threads is absent.
pub fn active_processor_count() -> u32 {
    unsafe { windows::Win32::winbase::GetActiveProcessorCount(0xFFFF) }
}

/// Loads the AcceptEx entry point for the listener. The extension belongs to that socket
/// and stays valid while the socket lives.
pub fn load_accept_ex(listener: SOCKET) -> Result<LPFN_ACCEPTEX, NativeError> {
    let mut function: LPFN_ACCEPTEX = None;
    let mut returned: u32 = 0;
    let status = unsafe {
        WSAIoctl(
            listener,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some(&WSAID_ACCEPTEX as *const GUID as *const c_void),
            size_of::<GUID>() as u32,
            Some(&mut function as *mut LPFN_ACCEPTEX as *mut c_void),
            size_of::<LPFN_ACCEPTEX>() as u32,
            &mut returned,
            None,
            None,
        )
    };
    if status != 0 {
        return Err(NativeError::last("WSAIoctl(WSAID_ACCEPTEX)"));
    }
    if function.is_none() {
        return Err(NativeError { stage: "AcceptEx entry point", code: 13 });
    }
    Ok(function)
}

// The Windows substrate: the RIO wrappers, the registered arena and the endpoint helpers.

pub mod arena {
    //! Registered arena: one VirtualAlloc region per worker (TCP) or one for the whole UDP
    //! engine, registered with RIO and sliced into fixed-stride slots.
    //!
    //! Every slot addresses a RIO_BUF inside the registration: a TCP slot is one
    //! /rio-buffer-sized connection buffer, a UDP slot is one buffer plus the remote-address
    //! area RIOReceiveEx writes the sender into.

    use core::ffi::c_void;

    use windows::Win32::memoryapi::{VirtualAlloc, VirtualFree};
    use windows::Win32::mswsockdef::RIO_BUF;

    use crate::native::{report, NativeError, RioFunctions};
    use crate::native::rio::RegisteredBuffer;

    // VirtualAlloc/VirtualFree flag values from winnt.h. The generated tree does not expose
    // them under memoryapi, and the API takes plain u32 flags.
    const MEM_COMMIT: u32 = 0x0000_1000;
    const MEM_RESERVE: u32 = 0x0000_2000;
    const MEM_RELEASE: u32 = 0x0000_8000;
    const PAGE_READWRITE: u32 = 0x04;

    /// Byte offset of a slot, rejecting index/stride combinations that would overflow or fall
    /// outside the arena. This is the check behind every RIO_BUF the engine builds.
    pub fn slot_offset(index: u32, stride: u32, total: usize) -> Option<usize> {
        if stride == 0 {
            return None;
        }
        let offset = (index as usize).checked_mul(stride as usize)?;
        if offset >= total {
            return None;
        }
        Some(offset)
    }

    /// Stride of a TCP connection slot: the whole registered buffer belongs to one echo.
    pub fn tcp_stride(rio_buffer_bytes: u32) -> u32 {
        rio_buffer_bytes
    }

    /// Stride of a UDP slot: the datagram buffer plus the address area the completion writes.
    pub fn udp_stride(rio_buffer_bytes: u32, address_bytes: usize) -> Option<u32> {
        (rio_buffer_bytes as usize).checked_add(address_bytes).and_then(|value| u32::try_from(value).ok())
    }

    /// Releases the pages and reports whether Windows accepted the release. Every Win32 result
    /// is inspected: a silent failure here would leak the arena.
    fn release_pages(base: *mut u8) -> bool {
        unsafe { VirtualFree(base as *mut c_void, 0, MEM_RELEASE) }.as_bool()
    }

    /// A registered block of memory. The registration is process-scoped and stays alive for
    /// the lifetime of the engine; dropping releases the pages, so callers must have stopped
    /// posting operations first.
    pub struct Arena {
        base: *mut u8,
        bytes: usize,
        registered: RegisteredBuffer,
    }

    impl Arena {
        pub fn create(rio: &RioFunctions, bytes: usize) -> Result<Self, NativeError> {
            if bytes == 0 {
                return Err(NativeError { stage: "arena size", code: 13 });
            }
            let base = unsafe { VirtualAlloc(None, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) } as *mut u8;
            if base.is_null() {
                return Err(NativeError { stage: "VirtualAlloc(arena)", code: 8 });
            }
            let slice = unsafe { core::slice::from_raw_parts_mut(base, bytes) };
            let registered = match RegisteredBuffer::register(rio, slice) {
                Ok(buffer) => buffer,
                Err(error) => {
                    // The pages must not leak when registration is refused, and the release has to run in
                    // every build: debug_assert! does not evaluate its argument in a release build.
                    if !release_pages(base) {
                        report("VirtualFree(arena)", 13);
                    }
                    return Err(error);
                }
            };
            Ok(Self { base, bytes, registered })
        }

        pub fn bytes(&self) -> usize {
            self.bytes
        }

        pub fn raw(&self) -> *mut u8 {
            self.base
        }

        pub fn registration(&self) -> windows::Win32::mswsockdef::RIO_BUFFERID {
            self.registered.raw()
        }

        /// Borrows a bounded window of the arena. The bounds are re-checked here so no caller
        /// can widen a view by accident.
        pub fn window(&mut self, offset: u32, length: u32) -> Result<&mut [u8], NativeError> {
            let start = offset as usize;
            let len = length as usize;
            if len == 0 || start > self.bytes || len > self.bytes - start {
                return Err(NativeError { stage: "arena window bounds", code: 13 });
            }
            Ok(unsafe { core::slice::from_raw_parts_mut(self.base.add(start), len) })
        }

        /// A RIO descriptor for a region, checked against the arena size and the registration.
        pub fn view(&self, offset: u32, length: u32) -> Result<RIO_BUF, NativeError> {
            if offset as usize >= self.bytes {
                return Err(NativeError { stage: "arena view offset", code: 13 });
            }
            self.registered.slice(offset, length)
        }

        /// A RIO descriptor for one fixed-stride slot.
        pub fn slot_view(&self, index: u32, stride: u32) -> Result<RIO_BUF, NativeError> {
            let offset = slot_offset(index, stride, self.bytes)
                .ok_or(NativeError { stage: "arena slot offset", code: 13 })?;
            self.registered.slice(offset as u32, stride)
        }

        /// A RIO descriptor for the tail of a slot, used for the UDP remote-address area.
        pub fn slot_tail_view(&self, index: u32, stride: u32, tail_offset: u32, tail_length: u32)
            -> Result<RIO_BUF, NativeError>
        {
            let offset = slot_offset(index, stride, self.bytes)
                .ok_or(NativeError { stage: "arena slot offset", code: 13 })?;
            if tail_offset as usize > stride as usize || tail_length as usize > stride as usize - tail_offset as usize {
                return Err(NativeError { stage: "arena slot tail bounds", code: 13 });
            }
            let start = offset + tail_offset as usize;
            self.registered.slice(start as u32, tail_length)
        }
    }

    impl Arena {
        /// Releases the region the way both baselines do: deregister with RIO first, then free
        /// the pages. The engine calls this once every posted request has completed and the
        /// owning threads have joined.
        pub fn destroy(&mut self, rio: &RioFunctions) {
            self.registered.deregister(rio);
            self.release_pages();
        }

        fn release_pages(&mut self) {
            if !self.base.is_null() {
                // Free first, then forget the address, in every build. A debug_assert! skipped the free in
                // a release build and then cleared the pointer, so the whole region leaked silently.
                if !release_pages(self.base) {
                    report("VirtualFree(arena)", 13);
                }
                self.base = core::ptr::null_mut();
                self.bytes = 0;
            }
        }
    }

    impl Drop for Arena {
        fn drop(&mut self) {
            // Fallback for a partially initialised engine that never reached its explicit
            // tear-down; the registration is process-scoped in that case.
            self.release_pages();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn slot_arithmetic_is_checked() {
            assert_eq!(slot_offset(0, 1_024, 4_096), Some(0));
            assert_eq!(slot_offset(3, 1_024, 4_096), Some(3_072));
            // A slot that starts at or beyond the end of the arena is rejected.
            assert_eq!(slot_offset(4, 1_024, 4_096), None);
            assert_eq!(slot_offset(1, 0, 4_096), None);
            assert_eq!(slot_offset(u32::MAX, 2, 4_096), None);
        }

        #[test]
        fn strides_match_the_baseline_layout() {
            assert_eq!(tcp_stride(16_384), 16_384);
            assert_eq!(udp_stride(65_507, 144), Some(65_651));
            assert_eq!(udp_stride(u32::MAX, 144), None);
            // The UDP arena holds depth x (payload + address area) bytes.
            assert_eq!(
                crate::contract::checked_arena_bytes(256, 65_651, u64::MAX),
                Some(16_806_656)
            );
        }
    }
}

pub mod endpoint {
    //! IPv4 endpoint construction, listener setup and the AcceptEx context option.
    //!
    //! The generated tree does not export every SO_* value used here, so the AcceptEx context
    //! option is declared with the value from mswsock.h; it matches
    //! `windows::Win32::mswsock::SO_UPDATE_ACCEPT_CONTEXT`.

    use core::mem::{size_of, zeroed};

    use windows::Win32::mswsock::SO_UPDATE_ACCEPT_CONTEXT;
    use windows::Win32::winsock2::{SOCKET, bind, listen, setsockopt};
    use windows::Win32::ws2::{AF_INET, SOCKADDR, SOCKADDR_IN, SOL_SOCKET};

    use crate::native::NativeError;

    /// The value AcceptEx publishes on the accepted socket so it carries the listener's local
    /// address. Declared here so the module reads as intent rather than as a magic number.
    pub const UPDATE_ACCEPT_CONTEXT: i32 = SO_UPDATE_ACCEPT_CONTEXT;

    /// Builds the wildcard IPv4 endpoint a server binds: 0.0.0.0 with the requested port. The
    /// port is converted with to_be, which is exactly what htons does.
    pub fn any_endpoint(port: u16) -> SOCKADDR_IN {
        let mut address: SOCKADDR_IN = unsafe { zeroed() };
        address.sin_family = AF_INET as _;
        address.sin_port = port.to_be();
        address
    }

    pub fn sockaddr_ptr(address: &SOCKADDR_IN) -> *const SOCKADDR {
        address as *const SOCKADDR_IN as *const SOCKADDR
    }

    /// Binds the wildcard endpoint. The baseline binds before listening and reports the
    /// failure through the socket API's own error value.
    pub fn bind_endpoint(socket: SOCKET, port: u16) -> Result<(), NativeError> {
        let address = any_endpoint(port);
        let status = unsafe { bind(socket, sockaddr_ptr(&address), size_of::<SOCKADDR_IN>() as i32) };
        if status != 0 {
            return Err(NativeError::last("bind"));
        }
        Ok(())
    }

    /// Starts listening with the maximum backlog, as the baseline does.
    pub fn listen_endpoint(socket: SOCKET) -> Result<(), NativeError> {
        let status = unsafe { listen(socket, 2_147_483_647) };
        if status != 0 {
            return Err(NativeError::last("listen"));
        }
        Ok(())
    }

    /// Applies the listener context to an accepted socket once AcceptEx reports completion.
    /// The documented form of this option passes the listening socket as the value.
    pub fn update_accept_context(socket: SOCKET, listener: SOCKET) -> Result<(), NativeError> {
        let status = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                UPDATE_ACCEPT_CONTEXT,
                Some(&listener as *const SOCKET as *const i8),
                size_of::<SOCKET>() as i32,
            )
        };
        if status != 0 {
            return Err(NativeError::last("setsockopt(SO_UPDATE_ACCEPT_CONTEXT)"));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn wildcard_endpoint_encodes_the_port() {
            let address = any_endpoint(7000);
            assert_eq!(address.sin_port, 7000u16.to_be());
            assert_eq!(address.sin_family, AF_INET as _);
            // 0.0.0.0 is the wildcard address: every byte of sin_addr stays zero.
            assert_eq!(unsafe { address.sin_addr.S_un.S_addr }, 0);
            assert_eq!(any_endpoint(0).sin_port, 0);
        }

        #[test]
        fn accept_context_option_matches_the_header_value() {
            assert_eq!(UPDATE_ACCEPT_CONTEXT, 28_683);
        }
    }
}

pub mod rio {
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
}
