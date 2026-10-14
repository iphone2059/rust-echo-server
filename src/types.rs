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

#[derive(Clone, Copy, Debug)]
pub struct ArgumentError(pub &'static str);

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
/// AcceptEx requires a SOCKADDR_STORAGE (128 bytes) plus 16 bytes of padding per address.
pub const SOCKADDR_STORAGE_BYTES: usize = 128;
pub const ACCEPT_ADDRESS_BYTES: usize = SOCKADDR_STORAGE_BYTES + 16;
pub const ACCEPT_OPERATION_BYTES: usize = ACCEPT_ADDRESS_BYTES * 2;
pub const UDP_ADDRESS_BYTES: usize = SOCKADDR_STORAGE_BYTES + 16;
/// /threads accepts 0..=64; zero uses the active processor count capped at 64.
pub const MAXIMUM_WORKERS: u32 = 64;
pub const AUTOMATIC_WORKER_CAP: u32 = MAXIMUM_WORKERS;

/// IOCP completion keys that are not accept operations. An accept operation is
/// identified by its own address, which is always larger than both control keys.
pub const STOP_KEY: usize = 1;
pub const ADMISSION_CLOSED_KEY: usize = 2;

/// Native status codes referenced by name. Values come from winerror.h and winsock2.h.
pub const ERROR_SUCCESS: i32 = 0;
pub const ERROR_NOT_ENOUGH_MEMORY: i32 = 8;
pub const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
pub const ERROR_INVALID_DATA: i32 = 13;
pub const ERROR_NETNAME_DELETED: u32 = 64;
pub const ERROR_IO_PENDING: i32 = 997;
pub const ERROR_IO_INCOMPLETE: i32 = 996;
pub const WSAECONNRESET: i32 = 10_054;
pub const WSAECONNABORTED: i32 = 10_053;
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
    /// RIO requests must retire before the completion queue can be closed; a pending
    /// notification delivery does not hold the worker open once this reaches zero.
    pub rio_outstanding: u32,
    pub notification_armed: bool,
}

/// A worker may only be released once admission is closed and every accepted socket
/// and pending handoff has been drained and every RIO request has retired.
pub fn worker_may_exit(lifecycle: &WorkerLifecycle) -> bool {
    lifecycle.phase >= WorkerPhase::AdmissionClosed
        && lifecycle.active_connections == 0
        && lifecycle.pending_handoffs == 0
        && lifecycle.rio_outstanding == 0
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
    /// Bytes reported by successful native receive completions.
    pub received_bytes: u64,
    /// Bytes reported by successful native send completions.
    pub sent_bytes: u64,
    pub bytes: u64,
    /// Failures at the connection or accept layer, and the connects refused for capacity. The
    /// reference keeps them apart from the protocol counters for exactly that reason.
    pub network_errors: u64,
    pub rejected: u64,
}

/// Optional notification observability, copied only once the owning loop has stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotifySnapshot {
    pub worker: u32,
    pub arms: u64,
    pub deliveries: u64,
    pub timeout_wakeups: u64,
}

impl NotifySnapshot {
    pub fn valid(&self) -> bool {
        self.timeout_wakeups == 0
            && self.arms >= self.deliveries
            && self.arms - self.deliveries <= 1
    }

    pub fn line(&self, protocol: Protocol) -> String {
        self.display(protocol).to_string()
    }

    pub fn display(&self, protocol: Protocol) -> NotifyLine<'_> {
        NotifyLine {
            snapshot: self,
            protocol,
        }
    }
}

pub struct NotifyLine<'a> {
    snapshot: &'a NotifySnapshot,
    protocol: Protocol,
}

impl core::fmt::Display for NotifyLine<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let snapshot = self.snapshot;
        let protocol = self.protocol;
        let name = if protocol == Protocol::Udp {
            "udp"
        } else {
            "tcp"
        };
        write!(
            formatter,
            "role=server protocol={} worker={} notify_arms={} notify_deliveries={} notify_gap={} timeout_wakeups_while_outstanding={}\n",
            name,
            snapshot.worker,
            snapshot.arms,
            snapshot.deliveries,
            snapshot.arms.saturating_sub(snapshot.deliveries),
            snapshot.timeout_wakeups
        )
    }
}

impl Statistics {
    /// Wrapping addition: the baseline reports exact 64-bit totals, so a counter that
    /// saturated would silently under-report.
    pub fn merge(&mut self, other: &Statistics) {
        self.accepted = self.accepted.wrapping_add(other.accepted);
        self.completions = self.completions.wrapping_add(other.completions);
        self.receives = self.receives.wrapping_add(other.receives);
        self.sends = self.sends.wrapping_add(other.sends);
        self.received_bytes = self.received_bytes.wrapping_add(other.received_bytes);
        self.sent_bytes = self.sent_bytes.wrapping_add(other.sent_bytes);
        self.bytes = self.bytes.wrapping_add(other.bytes);
        self.network_errors = self.network_errors.wrapping_add(other.network_errors);
        self.rejected = self.rejected.wrapping_add(other.rejected);
    }

    /// The aggregate terminal line, in the reference's field order for both protocols: the only
    /// differences between them are the protocol name and the value of `outstanding`. `active` is
    /// reported as the reference reports it, which is always zero because every worker has joined
    /// before the line is printed. The rate is guarded against a zero-millisecond run.
    pub fn final_line(
        &self,
        protocol: Protocol,
        elapsed_milliseconds: u64,
        worker_count: u32,
        outstanding: u32,
    ) -> String {
        self.display(protocol, elapsed_milliseconds, worker_count, outstanding)
            .to_string()
    }

    pub fn display(
        &self,
        protocol: Protocol,
        elapsed_milliseconds: u64,
        worker_count: u32,
        outstanding: u32,
    ) -> StatisticsLine<'_> {
        StatisticsLine {
            statistics: self,
            protocol,
            elapsed_milliseconds,
            worker_count,
            outstanding,
        }
    }
}

pub struct StatisticsLine<'a> {
    statistics: &'a Statistics,
    protocol: Protocol,
    elapsed_milliseconds: u64,
    worker_count: u32,
    outstanding: u32,
}

impl core::fmt::Display for StatisticsLine<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let statistics = self.statistics;
        let guarded = self.elapsed_milliseconds.max(1);
        let rate = statistics.bytes as f64 / (1024.0 * 1024.0) / (guarded as f64 / 1000.0);
        let name = match self.protocol {
            Protocol::Udp => "udp",
            _ => "tcp",
        };
        write!(
            formatter,
            "final protocol={} elapsed_ms={} workers={} accepted={} active=0 outstanding={} completions={} \
receives={} sends={} received_bytes={} sent_bytes={} bytes={} network_errors={} rejected={} MiB_per_sec={:.2}",
            name,
            self.elapsed_milliseconds,
            self.worker_count,
            statistics.accepted,
            self.outstanding,
            statistics.completions,
            statistics.receives,
            statistics.sends,
            statistics.received_bytes,
            statistics.sent_bytes,
            statistics.bytes,
            statistics.network_errors,
            statistics.rejected,
            rate
        )
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
            rio_outstanding: 0,
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
        lifecycle.rio_outstanding = 1;
        assert!(!worker_may_exit(&lifecycle));
        lifecycle.phase = WorkerPhase::Stopped;
        assert!(!worker_may_exit(&lifecycle));
        lifecycle.rio_outstanding = 0;
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
        total.merge(&Statistics {
            accepted: 3,
            completions: 11,
            receives: 5,
            sends: 6,
            bytes: 4096,
            ..Statistics::default()
        });
        total.merge(&Statistics {
            accepted: 7,
            completions: 19,
            receives: 9,
            sends: 10,
            bytes: 8192,
            ..Statistics::default()
        });
        assert_eq!(total.accepted, 10);
        assert_eq!(total.completions, 30);
        assert_eq!(total.receives, 14);
        assert_eq!(total.sends, 16);
        assert_eq!(total.bytes, 12_288);
        assert_eq!(
            total.final_line(Protocol::Tcp, 500, 4, 0),
            "final protocol=tcp elapsed_ms=500 workers=4 accepted=10 active=0 outstanding=0 \
completions=30 receives=14 sends=16 received_bytes=0 sent_bytes=0 bytes=12288 network_errors=0 rejected=0 \
MiB_per_sec=0.02"
        );
        assert_eq!(
            total.final_line(Protocol::Udp, 0, 1, 3),
            // A zero-millisecond run is guarded to 1 ms, so the rate is 12288 bytes per millisecond.
            "final protocol=udp elapsed_ms=0 workers=1 accepted=10 active=0 outstanding=3 \
completions=30 receives=14 sends=16 received_bytes=0 sent_bytes=0 bytes=12288 network_errors=0 rejected=0 \
MiB_per_sec=11.72"
        );

        // Large values wrap exactly instead of saturating, matching the C++ counters.
        let mut large = Statistics {
            accepted: u64::MAX - 100,
            bytes: u64::MAX - 4096,
            ..Statistics::default()
        };
        large.merge(&Statistics {
            accepted: 100,
            bytes: 4096,
            ..Statistics::default()
        });
        assert_eq!(large.accepted, u64::MAX);
        assert_eq!(large.bytes, u64::MAX);
    }

    #[test]
    fn notification_snapshot_allows_only_one_pending_real_delivery() {
        let mut snapshot = NotifySnapshot {
            worker: 3,
            arms: 7,
            deliveries: 6,
            timeout_wakeups: 0,
        };
        assert!(snapshot.valid());
        assert_eq!(
            snapshot.line(Protocol::Udp),
            "role=server protocol=udp worker=3 notify_arms=7 notify_deliveries=6 notify_gap=1 timeout_wakeups_while_outstanding=0\n"
        );
        snapshot.deliveries = 5;
        assert!(!snapshot.valid());
        snapshot.deliveries = 8;
        assert!(!snapshot.valid());
        snapshot.deliveries = 7;
        snapshot.timeout_wakeups = 1;
        assert!(!snapshot.valid());
    }
}

/// Failure metadata shared by pure engines and their runtimes. Native ownership faults are fatal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    Network,
    Invariant,
    DrainTimeout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureDomain {
    Win32,
    Winsock,
    Allocation,
    Invariant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub classification: FailureClass,
    pub domain: FailureDomain,
    pub stage: &'static str,
    pub code: i32,
}

impl Failure {
    pub const fn allocation(stage: &'static str) -> Self {
        Self {
            classification: FailureClass::Network,
            domain: FailureDomain::Allocation,
            stage,
            code: ERROR_NOT_ENOUGH_MEMORY,
        }
    }

    pub const fn invariant(stage: &'static str) -> Self {
        Self {
            classification: FailureClass::Invariant,
            domain: FailureDomain::Invariant,
            stage,
            code: 13,
        }
    }
    pub const fn timeout(stage: &'static str) -> Self {
        Self {
            classification: FailureClass::DrainTimeout,
            domain: FailureDomain::Win32,
            stage,
            code: 1460,
        }
    }
}

/// Reserve the whole production collection before any native operation or thread starts.
pub fn try_vec_with_capacity<T>(count: usize, stage: &'static str) -> Result<Vec<T>, Failure> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| Failure::allocation(stage))?;
    Ok(values)
}

pub fn try_vec_with<T>(
    count: usize,
    stage: &'static str,
    mut make: impl FnMut(usize) -> T,
) -> Result<Vec<T>, Failure> {
    let mut values = try_vec_with_capacity(count, stage)?;
    for index in 0..count {
        values.push(make(index));
    }
    Ok(values)
}

pub fn try_box<T>(value: T, stage: &'static str) -> Result<Box<T>, Failure> {
    Box::try_new(value).map_err(|_| Failure::allocation(stage))
}

pub fn try_arc<T>(value: T, stage: &'static str) -> Result<std::sync::Arc<T>, Failure> {
    std::sync::Arc::try_new(value).map_err(|_| Failure::allocation(stage))
}

/// Allocate the final stable slice directly; no infallible shrinking or conversion follows.
pub fn try_boxed_slice_with<T>(
    count: usize,
    stage: &'static str,
    mut make: impl FnMut(usize) -> T,
) -> Result<Box<[T]>, Failure> {
    struct Initializing<T> {
        values: Option<Box<[core::mem::MaybeUninit<T>]>>,
        initialized: usize,
    }
    impl<T> Drop for Initializing<T> {
        fn drop(&mut self) {
            if let Some(values) = &mut self.values {
                for value in &mut values[..self.initialized] {
                    // SAFETY: initialized counts only entries whose write completed.
                    unsafe { value.assume_init_drop() };
                }
            }
        }
    }
    let values = Box::<[T]>::try_new_uninit_slice(count).map_err(|_| Failure::allocation(stage))?;
    let mut owner = Initializing {
        values: Some(values),
        initialized: 0,
    };
    for index in 0..count {
        owner
            .values
            .as_mut()
            .ok_or_else(|| Failure::allocation(stage))?[index]
            .write(make(index));
        owner.initialized += 1;
    }
    let values = owner
        .values
        .take()
        .ok_or_else(|| Failure::allocation(stage))?;
    // SAFETY: every entry was initialized above; the guard no longer owns the slice.
    Ok(unsafe { values.assume_init() })
}

/// Native completion metadata after the transport has retired its provider-owned request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub index: u32,
    pub operation: EngineOperation,
    pub status: i32,
    pub bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Completion(Completion),
    PostFailed { index: u32, failure: Failure },
    Stop,
    AdmissionClosed,
    GenerationDrained,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpLifecycle {
    pub phase: UdpPhase,
    pub outstanding: u32,
    pub closing: bool,
    pub failed: bool,
}

#[cfg(test)]
mod allocation_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn impossible_extents_report_allocation_failure_before_initialization() {
        let expected = Failure::allocation("allocation probe");
        assert_eq!(
            try_vec_with_capacity::<u16>(usize::MAX, "allocation probe").unwrap_err(),
            expected,
        );
        let initialized = Cell::new(false);
        let result = try_boxed_slice_with(usize::MAX, "allocation probe", |_| {
            initialized.set(true);
            0u16
        });
        assert_eq!(result.unwrap_err(), expected);
        assert!(!initialized.get());
    }

    #[test]
    fn stable_slice_initialization_preserves_and_releases_every_owner() {
        struct Owner<'a>(&'a Cell<usize>, usize);
        impl Drop for Owner<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Cell::new(0);
        let values = try_boxed_slice_with(3, "allocation probe", |index| Owner(&drops, index))
            .ok()
            .unwrap();
        assert_eq!(values[2].1, 2);
        assert_eq!(drops.get(), 0);
        drop(values);
        assert_eq!(drops.get(), 3);

        // A constructor panic must retire initialized owners while ignoring uninitialized tail.
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = try_boxed_slice_with(3, "allocation probe", |index| {
                if index == 2 {
                    panic!("initialization probe");
                }
                Owner(&drops, index)
            });
        }));
        assert!(interrupted.is_err());
        assert_eq!(drops.get(), 5);
    }
}
