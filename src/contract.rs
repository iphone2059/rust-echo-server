//! The server binary's contract: the command line (switches, ranges, diagnostic tokens, usage text)
//! and the engine helpers that belong to the contract, in one place, mirroring the reference's
//! single contract file.
//!
//! Reference implementation: echo-binary-contract-v1 (the C++ server).

/// Identifier of the frozen binary contract this file implements.
pub const CONTRACT_VERSION: &str = "echo-binary-contract-v1";

/// Diagnostic tokens that must follow "Invalid arguments: " on stderr.
pub mod token {
    pub const PROTOCOL_OPTION: &str = "protocol-option";
    pub const INVALID_NUMBER: &str = "invalid-number";
    pub const OUT_OF_RANGE: &str = "out-of-range";
    pub const UNKNOWN_SWITCH: &str = "unknown-switch";
    pub const UNEXPECTED_VALUE: &str = "unexpected-value";
    pub const MISSING_VALUE: &str = "missing-value";
    pub const MISSING_PROTOCOL: &str = "missing-protocol";
    pub const UNEXPECTED_TARGET: &str = "unexpected-target";
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


use crate::types::{ArgumentError, Options, Protocol, MAXIMUM_UDP_PAYLOAD_BYTES};

pub fn checked_product(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)
}

pub fn checked_arena_bytes(slots: u64, stride: u64, memory_limit: u64) -> Option<u64> {
    checked_product(slots, stride).filter(|bytes| *bytes <= memory_limit)
}

pub fn tcp_connection_capacity(cq_capacity: u32, memory_slots: u64) -> u32 {
    let queue_slots = u64::from(cq_capacity / 2);
    let bounded = queue_slots.min(memory_slots);
    bounded.min(u64::from(u32::MAX)) as u32
}

pub fn advance_offset(total: usize, transferred: usize, offset: &mut usize) -> bool {
    if transferred == 0 || *offset > total || transferred > total - *offset {
        return false;
    }
    *offset += transferred;
    true
}

/// One CQ notification is in flight at a time. A delivery consumes the armed state, so a
/// second delivery for the same registration is an invariant violation, not a no-op.
pub fn notification_mark_delivered(armed: &mut bool) -> bool {
    if !*armed {
        return false;
    }
    *armed = false;
    true
}

/// The drain has finished and the queue is armed again. Arming twice without a delivery
/// in between is refused for the same reason.
pub fn notification_mark_rearmed(armed: &mut bool) -> bool {
    if *armed {
        return false;
    }
    *armed = true;
    true
}

/// Identity of an IOCP packet: the completion key and the OVERLAPPED address must both
/// match the registration, which is what keeps an unrelated packet from being treated as
/// this queue's notification. Addresses are compared as integers so the check is testable
/// without native storage.
pub fn notification_packet_matches(
    key: usize,
    overlapped: usize,
    expected_key: usize,
    expected_overlapped: usize,
) -> bool {
    key == expected_key && overlapped == expected_overlapped
}

/// Pre-posted AcceptEx operations: 32 per worker, capped so a large /threads value cannot
/// allocate an unbounded operation table.
pub fn accept_operation_count(worker_count: u32, accepts_per_worker: u32, maximum: u32) -> u32 {
    let possible = u64::from(worker_count) * u64::from(accepts_per_worker);
    possible.min(u64::from(maximum)) as u32
}

/// Same rule as `advance_offset`, for the 32-bit byte counters the connection records
/// keep: a zero-byte transfer or one that would run past the total is refused, and the
/// offset is left untouched.
pub fn advance_offset_u32(total: u32, transferred: u32, offset: &mut u32) -> bool {
    if transferred == 0 || *offset > total || transferred > total - *offset {
        return false;
    }
    *offset += transferred;
    true
}

fn switch_offset(token: &str) -> Option<usize> {
    let bytes = token.as_bytes();
    if bytes.len() < 2 || (bytes[0] != b'/' && bytes[0] != b'-') {
        return None;
    }
    let offset = if bytes.len() > 2 && bytes[0] == b'-' && bytes[1] == b'-' { 2 } else { 1 };
    let first = bytes[offset].to_ascii_lowercase();
    if first.is_ascii_lowercase() { Some(offset) } else { None }
}

fn numeric(value: &str) -> Result<u64, ArgumentError> {
    value
        .parse::<u64>()
        .map_err(|_| ArgumentError(crate::contract::token::INVALID_NUMBER.to_string()))
}

/// Strict parser: unknown switches, empty values, positional arguments and
/// out-of-range numbers are usage errors, and /h never masks a malformed command line.
pub fn parse(arguments: &[String]) -> Result<Options, ArgumentError> {
    if arguments.is_empty() {
        return Err(ArgumentError("invalid parser arguments".to_string()));
    }
    let mut options = Options::default();
    let mut saw_timeout = false;
    let mut saw_udp_depth = false;
    let mut saw_rio_buffer = false;
    let mut index = 1;
    while index < arguments.len() {
        let token = arguments[index].clone();
        index += 1;
        let Some(offset) = switch_offset(&token) else {
            return Err(ArgumentError(token::UNEXPECTED_TARGET.to_string()));
        };
        let rest = &token[offset..];
        let (name, inline) = match rest.split_once('=') {
            Some((name, value)) => (name.to_ascii_lowercase(), Some(value.to_string())),
            None => (rest.to_ascii_lowercase(), None),
        };
        if matches!(name.as_str(), "q" | "quiet" | "stats" | "h" | "help") {
            if inline.is_some() {
                // A flag never takes a value, and an empty one is still a value.
                return Err(ArgumentError(token::UNEXPECTED_VALUE.to_string()));
            }
            match name.as_str() {
                "q" | "quiet" => options.quiet = true,
                "stats" => options.stats = true,
                _ => options.help = true,
            }
            continue;
        }
        if !matches!(
            name.as_str(),
            "p" | "s" | "t" | "w" | "b" | "k" | "threads" | "rio-buffer" | "cq" | "memory"
        ) {
            return Err(ArgumentError(crate::contract::token::UNKNOWN_SWITCH.to_string()));
        }
        let value = match inline {
            Some(value) if !value.is_empty() => value,
            Some(_) => return Err(ArgumentError(token::MISSING_VALUE.to_string())),
            None => {
                if index >= arguments.len()
                    || arguments[index].is_empty()
                    || switch_offset(&arguments[index]).is_some()
                {
                    return Err(ArgumentError(token::MISSING_VALUE.to_string()));
                }
                let value = arguments[index].clone();
                index += 1;
                value
            }
        };
        if name == "p" {
            // The reference matches the protocol keyword itself and reports the parse failure as
            // an out-of-range value, not as a protocol-specific message.
            options.protocol = match value.to_ascii_lowercase().as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => return Err(ArgumentError(token::OUT_OF_RANGE.to_string())),
            };
            continue;
        }
        let number = numeric(&value)?;
        let range = match name.as_str() {
            "s" => 1..=65_535,
            "t" | "w" => 1..=u64::from(u32::MAX),
            "b" => 0..=2_147_483_647,
            "k" => 1..=65_536,
            "threads" => 1..=64,
            "rio-buffer" => 512..=1_048_576,
            "cq" => 64..=1_048_576,
            _ => 1_048_576..=u64::MAX,
        };
        if !range.contains(&number) {
            return Err(ArgumentError(crate::contract::token::OUT_OF_RANGE.to_string()));
        }
        match name.as_str() {
            "s" => options.port = number as u16,
            "t" => {
                options.timeout_seconds = number as u32;
                saw_timeout = true;
            }
            "w" => options.run_seconds = number as u32,
            "b" => options.socket_buffer_bytes = number as u32,
            "k" => {
                options.udp_depth = number as u32;
                saw_udp_depth = true;
            }
            "threads" => options.worker_count = number as u32,
            "rio-buffer" => {
                options.rio_buffer_bytes = number as u32;
                saw_rio_buffer = true;
            }
            "cq" => options.cq_capacity = number as u32,
            _ => options.memory_bytes = number,
        }
    }
    if options.protocol == Protocol::Tcp && saw_udp_depth {
        return Err(ArgumentError(crate::contract::token::PROTOCOL_OPTION.to_string()));
    }
    if options.protocol == Protocol::Udp && saw_timeout {
        return Err(ArgumentError(crate::contract::token::PROTOCOL_OPTION.to_string()));
    }
    // Option validation precedes the help short-circuit, exactly like the reference: /h never
    // masks a malformed command line.
    if options.help {
        return Ok(options);
    }
    if options.protocol == Protocol::None {
        return Err(ArgumentError("missing-protocol".to_string()));
    }
    if options.protocol == Protocol::Udp {
        if !saw_rio_buffer {
            // UDP defaults to one maximum-sized datagram per slot; the depth keeps its
            // own default.
            options.rio_buffer_bytes = MAXIMUM_UDP_PAYLOAD_BYTES as u32;
        } else if u64::from(options.rio_buffer_bytes) < MAXIMUM_UDP_PAYLOAD_BYTES {
            return Err(ArgumentError(
                "UDP /rio-buffer must be at least 65507 bytes".to_string(),
            ));
        }
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        std::iter::once("rust-echo-server".to_string())
            .chain(values.iter().map(|value| value.to_string()))
            .collect()
    }

    #[test]
    fn defaults_match_the_baseline() {
        let options = parse(&args(&["/p", "tcp", "/s", "7000"])).expect("valid");
        assert_eq!(options.port, 7000);
        assert_eq!(options.timeout_seconds, 300);
        assert_eq!(options.cq_capacity, 4_096);
        assert_eq!(options.memory_bytes, 1_073_741_824);
    }

    #[test]
    fn udp_defaults_to_the_maximum_payload_buffer() {
        let options = parse(&args(&["--p=UDP"])).expect("valid");
        assert_eq!(options.rio_buffer_bytes, 65_507);
        assert!(parse(&args(&["/p", "udp", "/rio-buffer", "65000"])).is_err());
    }

    #[test]
    fn protocol_specific_switches_are_rejected() {
        assert!(parse(&args(&["/p", "tcp", "/k", "8"])).is_err());
        assert!(parse(&args(&["/p", "udp", "/t", "5"])).is_err());
        assert!(parse(&args(&["/p", "tcp", "/stats=1"])).is_err());
        assert!(parse(&args(&["/p", "tcp", "positional"])).is_err());
        assert!(parse(&args(&["/p", "tcp", "/s", "0"])).is_err());
    }

    #[test]
    fn checked_arithmetic_and_capacity() {
        assert_eq!(checked_product(3, 4), Some(12));
        assert_eq!(checked_product(u64::MAX, 2), None);
        assert_eq!(checked_arena_bytes(4, 16, 64), Some(64));
        assert_eq!(checked_arena_bytes(4, 16, 63), None);
        assert_eq!(tcp_connection_capacity(4_096, 1_000), 1_000);
        let mut offset = 0;
        assert!(advance_offset(10, 4, &mut offset));
        assert!(!advance_offset(10, 7, &mut offset));
    }

    #[test]
    fn send_progression_is_checked_like_the_baseline() {
        let mut offset = 4;
        assert!(advance_offset(10, 3, &mut offset));
        assert_eq!(offset, 7);
        // A zero-byte send is a terminal failure, never a silent no-op.
        assert!(!advance_offset(10, 0, &mut offset));
        assert_eq!(offset, 7);
        assert!(!advance_offset(10, 4, &mut offset));
        assert_eq!(offset, 7);
    }

    #[test]
    fn notification_transitions_are_one_shot() {
        let mut armed = true;
        assert!(notification_mark_delivered(&mut armed));
        assert!(!armed);
        assert!(!notification_mark_delivered(&mut armed));
        assert!(notification_mark_rearmed(&mut armed));
        assert!(armed);
        assert!(!notification_mark_rearmed(&mut armed));
    }

    #[test]
    fn notification_identity_requires_both_fields() {
        assert!(notification_packet_matches(7, 0x1000, 7, 0x1000));
        assert!(!notification_packet_matches(8, 0x1000, 7, 0x1000));
        assert!(!notification_packet_matches(7, 0x2000, 7, 0x1000));
    }

    #[test]
    fn accept_capacity_is_capped() {
        assert_eq!(accept_operation_count(2, 32, 1_024), 64);
        assert_eq!(accept_operation_count(64, 32, 1_024), 1_024);
        assert_eq!(accept_operation_count(0, 32, 1_024), 0);
    }
}
