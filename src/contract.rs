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
    pub const PAYLOAD_SIZE: &str = "payload-size";
    pub const CQ_CAPACITY: &str = "cq-capacity";
    pub const MEMORY_CAPACITY: &str = "memory-capacity";
    pub const INVALID_UTF16: &str = "invalid-utf16";
}

/// Usage text, one entry per line; printed on stdout for a valid /h command line.
pub const USAGE: &[&str] = &[
    "Usage: rust-echo-server /p tcp|udp [/s port] [/t seconds] [/w seconds] [/b bytes]",
    "       [/k depth] [/threads workers] [/rio-buffer bytes]",
    "       [/cq capacity] [/memory bytes] [/q] [/stats] [/h]",
    "/t seconds: TCP idle timeout; UDP rejects /t.",
    "/k depth: UDP receive slots; TCP rejects /k.",
    "/threads 0: automatic TCP workers, min(active processors, 64); UDP uses 1.",
    "/w 0: no run limit. /memory bounds page-rounded registered arenas.",
    "/q suppresses nonessential output; /stats prints final; /h shows help.",
];

/// The usage text as the process prints it.
pub fn help_text() -> String {
    USAGE.join("\n")
}

use crate::types::{ArgumentError, MAXIMUM_UDP_PAYLOAD_BYTES, Options, Protocol};

pub fn checked_product(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)
}

pub fn checked_arena_bytes(slots: u64, stride: u64, memory_limit: u64) -> Option<u64> {
    checked_product(slots, stride).filter(|bytes| *bytes <= memory_limit)
}

/// ws2def.h: the reference sizes a datagram slot as the payload plus SOCKADDR_STORAGE and its
/// sixteen trailing bytes, which is the stride its arena uses.
pub const UDP_ADDRESS_BYTES: u64 = 144;
/// The page the reference rounds a worker's memory share to when GetSystemInfo cannot answer.
pub const PAGE_BYTES: u64 = 4096;

/// One worker's share of /memory, rounded down to whole pages with the remainder handed to the
/// first workers: the reference's ces_worker_memory_budget.
pub fn worker_memory_budget(
    memory_bytes: u64,
    worker_count: u32,
    worker_index: u32,
    page: u64,
) -> u64 {
    if worker_count == 0 || page == 0 {
        return 0;
    }
    let pages = memory_bytes / page;
    let share = pages / u64::from(worker_count);
    let extra = u64::from(worker_index) < pages % u64::from(worker_count);
    (share + u64::from(extra)) * page
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

/// The bounded accept window in the current baseline: two operations per worker, at
/// least eight and at most 128.
pub fn accept_operation_count(worker_count: u32) -> u32 {
    worker_count.saturating_mul(2).clamp(8, 128)
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
    let offset = if bytes.len() > 2 && bytes[0] == b'-' && bytes[1] == b'-' {
        2
    } else {
        1
    };
    let first = bytes[offset].to_ascii_lowercase();
    if first.is_ascii_lowercase() {
        Some(offset)
    } else {
        None
    }
}

fn numeric(value: &str) -> Result<u64, ArgumentError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ArgumentError(token::INVALID_NUMBER.to_string()));
    }
    value
        .parse::<u64>()
        .map_err(|_| ArgumentError(crate::contract::token::INVALID_NUMBER.to_string()))
}

/// Strict parser: unknown switches, empty values, positional arguments and
/// out-of-range numbers are usage errors, and /h never masks a malformed command line.
pub fn parse(arguments: &[String]) -> Result<Options, ArgumentError> {
    let decoded: Vec<Argument> = arguments
        .iter()
        .map(|value| Argument {
            text: Ok(value.clone()),
            is_switch: switch_offset(value).is_some(),
            empty: value.is_empty(),
        })
        .collect();
    parse_arguments(&decoded)
}

struct Argument {
    text: Result<String, ArgumentError>,
    is_switch: bool,
    empty: bool,
}

/// Keeps UTF-16 validation in the same order as the wide-argv parser, including the
/// missing-value check that precedes validation of a following switch-shaped token.
pub fn parse_wide(arguments: &[Vec<u16>]) -> Result<Options, ArgumentError> {
    let decoded: Vec<Argument> = arguments
        .iter()
        .map(|value| {
            let offset =
                if value.len() > 2 && value[0] == u16::from(b'-') && value[1] == u16::from(b'-') {
                    2
                } else {
                    1
                };
            let is_switch = value.len() >= 2
                && matches!(value[0], 45 | 47)
                && value
                    .get(offset)
                    .is_some_and(|first| matches!(*first, 65..=90 | 97..=122));
            Argument {
                text: String::from_utf16(value)
                    .map_err(|_| ArgumentError(token::INVALID_UTF16.to_string())),
                is_switch,
                empty: value.is_empty(),
            }
        })
        .collect();
    parse_arguments(&decoded)
}

fn parse_arguments(arguments: &[Argument]) -> Result<Options, ArgumentError> {
    if arguments.is_empty() {
        return Err(ArgumentError("invalid parser arguments".to_string()));
    }
    let mut options = Options::default();
    let mut saw_timeout = false;
    let mut saw_udp_depth = false;
    let mut saw_rio_buffer = false;
    let mut saw_workers = false;
    let mut index = 1;
    while index < arguments.len() {
        let token = arguments[index].text.as_ref().map_err(Clone::clone)?;
        index += 1;
        let Some(offset) = switch_offset(token) else {
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
            return Err(ArgumentError(
                crate::contract::token::UNKNOWN_SWITCH.to_string(),
            ));
        }
        let value = match inline {
            Some(value) if !value.is_empty() => value,
            Some(_) => return Err(ArgumentError(token::MISSING_VALUE.to_string())),
            None => {
                if index >= arguments.len() || arguments[index].empty || arguments[index].is_switch
                {
                    return Err(ArgumentError(token::MISSING_VALUE.to_string()));
                }
                let value = arguments[index]
                    .text
                    .as_ref()
                    .map_err(Clone::clone)?
                    .clone();
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
            "t" => 1..=u64::from(u32::MAX),
            "w" => 0..=u64::from(u32::MAX),
            "b" => 0..=2_147_483_647,
            "k" => 1..=65_536,
            "threads" => 0..=64,
            "rio-buffer" => 512..=1_048_576,
            "cq" => 64..=1_048_576,
            _ => 1_048_576..=u64::MAX,
        };
        if !range.contains(&number) {
            return Err(ArgumentError(
                crate::contract::token::OUT_OF_RANGE.to_string(),
            ));
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
            "threads" => {
                options.worker_count = number as u32;
                saw_workers = true;
            }
            "rio-buffer" => {
                options.rio_buffer_bytes = number as u32;
                saw_rio_buffer = true;
            }
            "cq" => options.cq_capacity = number as u32,
            _ => options.memory_bytes = number,
        }
    }
    if options.protocol == Protocol::Tcp && saw_udp_depth {
        return Err(ArgumentError(
            crate::contract::token::PROTOCOL_OPTION.to_string(),
        ));
    }
    if options.protocol == Protocol::Udp && (saw_timeout) {
        return Err(ArgumentError(
            crate::contract::token::PROTOCOL_OPTION.to_string(),
        ));
    }
    if options.protocol == Protocol::Udp && saw_workers && options.worker_count > 1 {
        return Err(ArgumentError(token::PROTOCOL_OPTION.to_string()));
    }
    // Option validation precedes the help short-circuit, exactly like the reference: /h never
    // masks a malformed command line.
    // Capacity is validated before the help short-circuit, exactly like the reference: /h never
    // masks a budget the run could not satisfy, only the mandatory-protocol check.
    if options.protocol == Protocol::Udp {
        // The datagram path is single-threaded in the reference whatever /threads says.
        options.worker_count = 1;
        if !saw_rio_buffer {
            // UDP defaults to one maximum-sized datagram per slot; the depth keeps its
            // own default.
            options.rio_buffer_bytes = MAXIMUM_UDP_PAYLOAD_BYTES as u32;
        } else if u64::from(options.rio_buffer_bytes) < MAXIMUM_UDP_PAYLOAD_BYTES {
            return Err(ArgumentError(token::PAYLOAD_SIZE.to_string()));
        }
        // Each datagram slot reserves a queue entry per direction.
        if options.udp_depth > options.cq_capacity / 2 {
            return Err(ArgumentError(token::CQ_CAPACITY.to_string()));
        }
        let stride = u64::from(options.rio_buffer_bytes) + UDP_ADDRESS_BYTES;
        match checked_arena_bytes(u64::from(options.udp_depth), stride, options.memory_bytes) {
            Some(bytes) if bytes <= u64::from(u32::MAX) => {}
            _ => return Err(ArgumentError(token::MEMORY_CAPACITY.to_string())),
        }
    }
    if options.protocol == Protocol::Tcp {
        // Every worker needs a page-rounded share of /memory that can hold at least one slot;
        // otherwise it cannot register its arena at all.
        let workers = if options.worker_count == 0 {
            crate::types::resolved_worker_count(
                options.worker_count,
                crate::native::active_processor_count(),
            )
        } else {
            options.worker_count
        };
        let page = crate::native::page_bytes();
        for index in 0..workers {
            let budget = worker_memory_budget(options.memory_bytes, workers, index, page);
            let slots = (u64::from(options.cq_capacity) / 2)
                .min(budget / u64::from(options.rio_buffer_bytes));
            if slots == 0 {
                return Err(ArgumentError(token::MEMORY_CAPACITY.to_string()));
            }
        }
    }
    if options.help {
        return Ok(options);
    }
    if options.protocol == Protocol::None {
        return Err(ArgumentError(token::MISSING_PROTOCOL.to_string()));
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
        assert_eq!(accept_operation_count(1), 8);
        assert_eq!(accept_operation_count(2), 8);
        assert_eq!(accept_operation_count(5), 10);
        assert_eq!(accept_operation_count(64), 128);
        assert_eq!(accept_operation_count(u32::MAX), 128);
    }

    #[test]
    fn explicit_zero_run_time_and_workers_match_the_baseline() {
        let tcp = parse(&args(&["/p", "tcp", "/w", "0", "/threads", "0"])).unwrap();
        assert_eq!(tcp.run_seconds, 0);
        assert_eq!(tcp.worker_count, 0);
        let udp = parse(&args(&["/p", "udp", "/threads", "0"])).unwrap();
        assert_eq!(udp.worker_count, 1);
        assert_eq!(
            parse(&args(&["/p", "udp", "/threads", "2"])).unwrap_err().0,
            token::PROTOCOL_OPTION
        );
    }

    #[test]
    fn numeric_values_require_ascii_digits_without_a_sign() {
        for value in ["+7", "-7", " 7", "7 ", "７", "18446744073709551616"] {
            assert_eq!(
                parse(&args(&["/p", "tcp", "/s", value])).unwrap_err().0,
                token::INVALID_NUMBER
            );
        }
        assert_eq!(parse(&args(&["/p", "tcp", "/s", "0007"])).unwrap().port, 7);
    }

    #[test]
    fn wide_arguments_reject_unpaired_surrogates_in_parse_order() {
        fn wide(values: &[&str]) -> Vec<Vec<u16>> {
            args(values)
                .iter()
                .map(|value| value.encode_utf16().collect())
                .collect()
        }
        let mut arguments = wide(&["/p", "tcp", "/h"]);
        arguments.push(vec![0xd800]);
        assert_eq!(parse_wide(&arguments).unwrap_err().0, token::INVALID_UTF16);
        let mut value = wide(&["/p", "tcp", "/s"]);
        value.push(vec![0xdc00]);
        assert_eq!(parse_wide(&value).unwrap_err().0, token::INVALID_UTF16);
        let mut switch = wide(&["/p", "tcp", "/s"]);
        switch.push(vec![b'/' as u16, b'h' as u16, 0xd800]);
        assert_eq!(parse_wide(&switch).unwrap_err().0, token::MISSING_VALUE);
        let mut prior_error = wide(&["/bogus"]);
        prior_error.push(vec![0xd800]);
        assert_eq!(
            parse_wide(&prior_error).unwrap_err().0,
            token::UNKNOWN_SWITCH
        );
    }

    #[test]
    fn page_remainder_is_distributed_to_first_workers() {
        assert_eq!(worker_memory_budget(5 * 4096 + 17, 3, 0, 4096), 8192);
        assert_eq!(worker_memory_budget(5 * 4096 + 17, 3, 1, 4096), 8192);
        assert_eq!(worker_memory_budget(5 * 4096 + 17, 3, 2, 4096), 4096);
        assert_eq!(worker_memory_budget(u64::MAX, 64, 63, 4096) % 4096, 0);
    }
}
