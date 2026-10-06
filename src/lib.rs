//! Windows x64 RIO echo server core.
//!
//! Layering mirrors the C++ baseline and the Swift port:
//! contract -> native (Winsock/RIO/AcceptEx) -> engine -> worker threads -> main.
//!
//! The engine layer is split the way the baseline's single engine file is:
//! `connection` and `engine` hold the TCP echo progression, `acceptor` the AcceptEx table
//! and its policy, `udp` the datagram slots, and `worker`, `tcp` and `udp_runtime` the
//! native threads that drive them.

pub mod arena;
pub mod contract;
pub mod internal;
pub mod endpoint;
pub mod engine;
pub mod native;
pub mod rio;
pub mod server;
pub mod timer;
pub mod types;
pub mod worker;
