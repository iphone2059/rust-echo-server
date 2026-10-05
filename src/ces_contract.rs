//! The server binary's command-line contract, in one place.
//!
//! Switches, ranges, diagnostic tokens and help text live here so the four language ports can be
//! compared file by file. Reference implementation: echo-binary-contract-v1 (the C++ server).

/// Identifier of the frozen binary contract this file implements.
pub const CONTRACT_VERSION: &str = "echo-binary-contract-v1";

/// Diagnostic tokens that must follow "Invalid arguments: " on stderr.
pub mod token {
    pub const PROTOCOL_OPTION: &str = "protocol-option";
    pub const INVALID_NUMBER: &str = "invalid-number";
    pub const OUT_OF_RANGE: &str = "out-of-range";
    pub const UNKNOWN_SWITCH: &str = "unknown-switch";
}

/// Usage text, one entry per line; printed on stdout for a valid /h command line.
pub const USAGE: &[&str] = &[
    "Usage: rust-echo-server /p tcp|udp [/s port] [/t seconds] [/w seconds]",
    "       [/b bytes] [/k udp-depth] [/threads workers] [/rio-buffer bytes]",
    "       [/cq capacity] [/memory bytes] [/q] [/stats]",
    "Data I/O is always RIO; CQ notification is always IOCP. No fallback backend exists.",
];

/// The usage text as the process prints it.
pub fn help_text() -> String {
    USAGE.join("\n")
}
