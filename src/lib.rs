//! Windows x64 RIO echo server core.
//!
//! The module tree mirrors the C++ baseline file for file:
//! contract -> native (Winsock/RIO/AcceptEx) -> engine (sessions and run) -> internal
//! (accept table, connections, datagram slots, worker threads) -> server -> main.
//! The internal module names are re-exported so the historical paths keep working.

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("ces targets Windows x64 (x86_64-pc-windows-msvc) only");

pub mod contract;
pub mod engine;
pub mod internal;
pub mod native;
pub mod server;
pub mod types;

pub use internal::acceptor;
pub use internal::connection;
pub use internal::udp;
pub use internal::worker;
