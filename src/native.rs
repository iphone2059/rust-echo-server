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

