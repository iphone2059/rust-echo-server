//! Engine internals: the AcceptEx table and its policy, the TCP connection progression, the datagram
//! slots and the native worker threads that drive them.
//!
//! The reference keeps these in one engine-internal file; Rust keeps the same roles split across the
//! submodules below, which are reachable only through this module.

pub mod acceptor;
pub mod connection;
pub mod tcp;
pub mod udp;
pub mod udp_runtime;
