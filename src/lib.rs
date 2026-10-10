//! Windows x64 MSVC RIO echo server core.
//!
//! `server` loads Winsock/RIO and dispatches the protocol; `engine` is the native-free
//! TCP worker state machine. `internal` contains accept/connection/UDP state and native
//! worker runtimes, backed by `native` resource owners. Its public state modules are
//! re-exported so the historical paths keep working.

#[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
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
