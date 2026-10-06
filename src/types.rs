//! Shared server vocabulary: protocol, exit codes, parsed options, worker lifecycle and
//! the engine statistics the report is derived from.
//!
//! Every name mirrors the C++ baseline (ces_types.h / internal.h) and the
//! Swift port (CESTypes.swift / CESEngineInternal.swift) so the three servers share one
//! contract.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    None,
    Tcp,
    Udp,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    Usage = 1,
    Network = 2,
    // Declared for parity with the C++ baseline exit-code contract; the server never
    // classifies a run as an echo failure.
    EchoFailure = 3,
    Internal = 4,
}

#[derive(Clone, Debug)]
pub struct ArgumentError(pub String);

pub const DEFAULT_PORT: u16 = 7;
pub const DEFAULT_TCP_TIMEOUT_SECONDS: u32 = 300;
pub const DEFAULT_UDP_DEPTH: u32 = 256;
pub const DEFAULT_RIO_BUFFER_BYTES: u32 = 16_384;
pub const DEFAULT_CQ_CAPACITY: u32 = 4_096;
pub const DEFAULT_MEMORY_BYTES: u64 = 1_073_741_824;
pub const MAXIMUM_UDP_PAYLOAD_BYTES: u64 = 65_507;
pub const COMPLETION_BATCH_SIZE: usize = 256;

/// A saturated peer can keep a completion queue non-empty indefinitely, so a drain
/// yields to the control path after this many batches.
pub const COMPLETION_DRAIN_BATCHES: u32 = 64;
/// AcceptEx operations per worker thread.
pub const ACCEPTS_PER_WORKER: u32 = 32;
/// Upper bound on pre-posted AcceptEx operations, whatever the worker count.
pub const MAXIMUM_ACCEPTS: u32 = 1_024;
/// AcceptEx requires a SOCKADDR_STORAGE (128 bytes) plus 16 bytes of padding per address.
pub const SOCKADDR_STORAGE_BYTES: usize = 128;
pub const ACCEPT_ADDRESS_BYTES: usize = SOCKADDR_STORAGE_BYTES + 16;
pub const ACCEPT_OPERATION_BYTES: usize = ACCEPT_ADDRESS_BYTES * 2;
pub const UDP_ADDRESS_BYTES: usize = SOCKADDR_STORAGE_BYTES + 16;
/// Worker-count bounds: /threads accepts 1..=64 and the automatic count is capped at 32.
pub const MAXIMUM_WORKERS: u32 = 64;
pub const AUTOMATIC_WORKER_CAP: u32 = 32;

/// IOCP completion keys that are not accept operations. An accept operation is
/// identified by its own address, which is always larger than both control keys.
pub const STOP_KEY: usize = 1;
pub const ADMISSION_CLOSED_KEY: usize = 2;

/// Native status codes referenced by name. Values come from winerror.h and winsock2.h.
pub const ERROR_SUCCESS: i32 = 0;
pub const ERROR_NOT_ENOUGH_MEMORY: i32 = 8;
pub const ERROR_INVALID_DATA: i32 = 13;
pub const ERROR_NETNAME_DELETED: u32 = 64;
pub const ERROR_IO_PENDING: i32 = 997;
pub const ERROR_IO_INCOMPLETE: i32 = 996;
pub const WSAECONNRESET: i32 = 10_054;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 258;
/// winbase.h INFINITE, passed to GetQueuedCompletionStatus.
pub const INFINITE: u32 = u32::MAX;

#[derive(Clone, Debug)]
pub struct Options {
    pub protocol: Protocol,
    pub port: u16,
    pub timeout_seconds: u32,
    pub run_seconds: u32,
    pub socket_buffer_bytes: u32,
    pub udp_depth: u32,
    pub worker_count: u32,
    pub rio_buffer_bytes: u32,
    pub cq_capacity: u32,
    pub memory_bytes: u64,
    /// Accepted for CLI parity with the baseline, which also never reads it: the server
    /// prints nothing outside /stats.
    pub quiet: bool,
    pub stats: bool,
    pub help: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            protocol: Protocol::None,
            port: DEFAULT_PORT,
            timeout_seconds: DEFAULT_TCP_TIMEOUT_SECONDS,
            run_seconds: 0,
            socket_buffer_bytes: 0,
            udp_depth: DEFAULT_UDP_DEPTH,
            worker_count: 0,
            rio_buffer_bytes: DEFAULT_RIO_BUFFER_BYTES,
            cq_capacity: DEFAULT_CQ_CAPACITY,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            quiet: false,
            stats: false,
            help: false,
        }
    }
}
/// Resolves /threads, or the automatic count when it is absent. The processor count is
/// passed in so the rule is testable without querying the machine.
pub fn resolved_worker_count(worker_count: u32, processors: u32) -> u32 {
    if worker_count != 0 {
        return worker_count;
    }
    processors.clamp(1, AUTOMATIC_WORKER_CAP)
}

/// Per-worker connection index (TCP) or slot (UDP) timer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerNode {
    pub deadline: u64,
    pub connection_index: u32,
}

/// Worker lifecycle states in the baseline's order. Every phase at or past
/// `AdmissionClosed` releases the worker from the admission barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkerPhase {
    Starting = 0,
    Running = 1,
    Quiescing = 2,
    AdmissionClosed = 3,
    Draining = 4,
    Stopped = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerLifecycle {
    pub phase: WorkerPhase,
    pub active_connections: u32,
    pub pending_handoffs: u32,
    pub notification_armed: bool,
}

/// A worker may only be released once admission is closed and every accepted socket
/// and pending handoff has been drained.
pub fn worker_may_exit(lifecycle: &WorkerLifecycle) -> bool {
    lifecycle.phase >= WorkerPhase::AdmissionClosed
        && lifecycle.active_connections == 0
        && lifecycle.pending_handoffs == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UdpPhase {
    Running = 0,
    Draining = 1,
    Stopped = 2,
}

/// Registered UDP storage is released only after the phase reached `Stopped` and every
/// posted request has completed.
pub fn udp_may_release(phase: UdpPhase, outstanding: u32) -> bool {
    phase == UdpPhase::Stopped && outstanding == 0
}

/// What a completion belongs to. The operation travels in the RIO request context, so a
/// completion for a connection that was already closed is still classified correctly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineOperation {
    Receive,
    Send,
}
/// Counters accumulated by one worker (TCP) or by the single UDP engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub accepted: u64,
    pub completions: u64,
    pub receives: u64,
    pub sends: u64,
    pub bytes: u64,
}

impl Statistics {
    /// Wrapping addition: the baseline reports exact 64-bit totals, so a counter that
    /// saturated would silently under-report.
    pub fn merge(&mut self, other: &Statistics) {
        self.accepted = self.accepted.wrapping_add(other.accepted);
        self.completions = self.completions.wrapping_add(other.completions);
        self.receives = self.receives.wrapping_add(other.receives);
        self.sends = self.sends.wrapping_add(other.sends);
        self.bytes = self.bytes.wrapping_add(other.bytes);
    }

    /// One line per TCP worker, printed after that worker has joined.
    pub fn worker_line(&self, worker_index: u32, active: u32) -> String {
        format!(
            "[worker {}] accepted={} completions={} receives={} sends={} bytes={} active={}",
            worker_index, self.accepted, self.completions, self.receives, self.sends, self.bytes, active
        )
    }

    /// The aggregate terminal line. TCP reports the connections still active, UDP the
    /// requests still outstanding; the rate is guarded against a zero-millisecond run.
    pub fn final_line(&self, protocol: Protocol, elapsed_milliseconds: u64, terminal_count: u32) -> String {
        let guarded = elapsed_milliseconds.max(1);
        let rate = self.bytes as f64 / (1024.0 * 1024.0) / (guarded as f64 / 1000.0);
        match protocol {
            Protocol::Udp => format!(
                "final protocol=udp elapsed_ms={} completions={} receives={} sends={} bytes={} MiB_per_sec={:.2} outstanding={}",
                elapsed_milliseconds, self.completions, self.receives, self.sends, self.bytes, rate, terminal_count
            ),
            _ => format!(
                "final protocol=tcp elapsed_ms={} accepted={} completions={} receives={} sends={} bytes={} MiB_per_sec={:.2} active={}",
                elapsed_milliseconds, self.accepted, self.completions, self.receives, self.sends, self.bytes, rate,
                terminal_count
            ),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_count_resolution_matches_the_baseline_bounds() {
        assert_eq!(resolved_worker_count(4, 8), 4);
        assert_eq!(resolved_worker_count(0, 16), 16);
        assert_eq!(resolved_worker_count(0, 0), 1);
        assert_eq!(resolved_worker_count(0, 128), AUTOMATIC_WORKER_CAP);
        assert_eq!(resolved_worker_count(MAXIMUM_WORKERS, 128), MAXIMUM_WORKERS);
    }

    #[test]
    fn lifecycle_requires_the_admission_barrier_and_a_full_drain() {
        let mut lifecycle = WorkerLifecycle {
            phase: WorkerPhase::Quiescing,
            active_connections: 0,
            pending_handoffs: 0,
            notification_armed: true,
        };
        assert!(!worker_may_exit(&lifecycle));
        lifecycle.phase = WorkerPhase::AdmissionClosed;
        assert!(worker_may_exit(&lifecycle));
        lifecycle.pending_handoffs = 1;
        assert!(!worker_may_exit(&lifecycle));
        lifecycle.pending_handoffs = 0;
        lifecycle.active_connections = 1;
        assert!(!worker_may_exit(&lifecycle));
        lifecycle.active_connections = 0;
        lifecycle.phase = WorkerPhase::Stopped;
        assert!(worker_may_exit(&lifecycle));
    }

    #[test]
    fn udp_storage_is_released_only_after_the_final_completion() {
        assert!(!udp_may_release(UdpPhase::Running, 0));
        assert!(!udp_may_release(UdpPhase::Draining, 0));
        assert!(!udp_may_release(UdpPhase::Stopped, 1));
        assert!(udp_may_release(UdpPhase::Stopped, 0));
    }

    #[test]
    fn statistics_aggregate_exactly_and_format_like_the_baseline() {
        let mut total = Statistics::default();
        total.merge(&Statistics { accepted: 3, completions: 11, receives: 5, sends: 6, bytes: 4096 });
        total.merge(&Statistics { accepted: 7, completions: 19, receives: 9, sends: 10, bytes: 8192 });
        assert_eq!(total.accepted, 10);
        assert_eq!(total.completions, 30);
        assert_eq!(total.receives, 14);
        assert_eq!(total.sends, 16);
        assert_eq!(total.bytes, 12_288);
        assert_eq!(
            total.worker_line(1, 0),
            "[worker 1] accepted=10 completions=30 receives=14 sends=16 bytes=12288 active=0"
        );
        assert_eq!(
            total.final_line(Protocol::Tcp, 500, 0),
            "final protocol=tcp elapsed_ms=500 accepted=10 completions=30 receives=14 sends=16 bytes=12288 MiB_per_sec=0.02 active=0"
        );
        assert_eq!(
            total.final_line(Protocol::Udp, 0, 0),
            // A zero-millisecond run is guarded to 1 ms, so the rate is 12288 bytes per millisecond.
            "final protocol=udp elapsed_ms=0 completions=30 receives=14 sends=16 bytes=12288 MiB_per_sec=11.72 outstanding=0"
        );

        // Large values wrap exactly instead of saturating, matching the C++ counters.
        let mut large = Statistics { accepted: u64::MAX - 100, bytes: u64::MAX - 4096, ..Statistics::default() };
        large.merge(&Statistics { accepted: 100, bytes: 4096, ..Statistics::default() });
        assert_eq!(large.accepted, u64::MAX);
        assert_eq!(large.bytes, u64::MAX);
    }
}


