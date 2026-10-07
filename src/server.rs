//! Server entry point: Winsock, the RIO extension table and the protocol dispatch.
//!
//! This is the counterpart of `ces_run_server`: RIO is loaded once through a probe socket
//! and every protocol runs against that table. There is no fallback data path.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::native::{registered_socket, report, RioFunctions, Winsock};
use crate::worker::tcp::run_tcp;
use crate::types::{ExitCode, Options, Protocol};
use crate::udp::runtime::run_udp;

/// Runs one parsed command line. `stop_requested` is the console handler's flag: the
/// engine observes it between drain batches, not only between iterations.
pub fn run_server(options: &Options, stop_requested: &Arc<AtomicBool>) -> ExitCode {
    let winsock = match Winsock::start() {
        Ok(winsock) => winsock,
        Err(error) => {
            report(error.stage, error.code);
            return ExitCode::Network;
        }
    };
    // The probe only exists to resolve the extension table; the table stays valid while
    // Winsock is active, so the probe is closed before the engine starts.
    let probe = match registered_socket(Protocol::Tcp) {
        Ok(probe) => probe,
        Err(error) => {
            report(error.stage, error.code);
            return ExitCode::Network;
        }
    };
    let rio = match RioFunctions::load(probe.raw()) {
        Ok(rio) => rio,
        Err(error) => {
            report(error.stage, error.code);
            return ExitCode::Network;
        }
    };
    drop(probe);
    let result = match options.protocol {
        Protocol::Tcp => run_tcp(rio, options, stop_requested),
        Protocol::Udp => run_udp(rio, options, stop_requested),
        Protocol::None => ExitCode::Usage,
    };
    drop(winsock);
    result
}



