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
