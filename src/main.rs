use std::process::ExitCode as ProcessExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use ces::contract::parse_native;
use ces::native::{NativeError, WideArguments, report, write_stderr, write_stdout};
use ces::server::run_server;
use ces::types::{ExitCode, Options, Protocol};

/// The console handler observes this flag; the engine polls it while draining, so a
/// saturated server still stops promptly.
static CONTROL: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// SetConsoleCtrlHandler callback. Returns TRUE for the events it consumes, exactly like
/// the baseline: CTRL_C, CTRL_BREAK and CTRL_CLOSE all request a controlled stop.
unsafe extern "system" fn console_handler(event: u32) -> windows::core::BOOL {
    let event = event as i32;
    if event == windows::Win32::consoleapi::CTRL_C_EVENT
        || event == windows::Win32::consoleapi::CTRL_BREAK_EVENT
        || event == windows::Win32::consoleapi::CTRL_CLOSE_EVENT
    {
        if let Some(control) = CONTROL.get() {
            control.store(true, Ordering::Release);
        }
        return true.into();
    }
    false.into()
}

fn help() {
    write_stdout(format_args!("{}\n", ces::contract::help_text()));
}

/// A malformed command line reports the diagnostic and the usage on stderr, exactly like the
/// reference: stdout stays empty so a caller can tell a usage error from a successful /h.
fn help_error() {
    write_stderr(format_args!("{}\n", ces::contract::help_text()));
}

fn run(options: &Options) -> ExitCode {
    match options.protocol {
        Protocol::None => ExitCode::Usage,
        Protocol::Tcp | Protocol::Udp => {
            let control =
                match ces::types::try_arc(AtomicBool::new(false), "server control allocation") {
                    Ok(control) => control,
                    Err(failure) => {
                        report(failure.stage, failure.code);
                        return ExitCode::Network;
                    }
                };
            // Only one server runs per process, so the first registration wins.
            let _ = CONTROL.set(Arc::clone(&control));
            let registered = unsafe {
                windows::Win32::consoleapi::SetConsoleCtrlHandler(Some(console_handler), true)
            };
            if !registered.as_bool() {
                let error = NativeError::last("SetConsoleCtrlHandler");
                write_stderr(format_args!(
                    "SetConsoleCtrlHandler failed: {}\n",
                    error.code as u32
                ));
                return ExitCode::Internal;
            }
            let result = run_server(options, &control);
            // Removal cannot fail for a handler that was just registered.
            unsafe {
                let _ =
                    windows::Win32::consoleapi::SetConsoleCtrlHandler(Some(console_handler), false);
            }
            result
        }
    }
}

fn main() -> ProcessExitCode {
    let arguments = match WideArguments::current() {
        Ok(arguments) => arguments,
        Err(error) => {
            report(error.stage, error.code);
            return ProcessExitCode::from(ExitCode::Network as u8);
        }
    };
    let options = match parse_native(&arguments) {
        Ok(options) => options,
        Err(error) => {
            write_stderr(format_args!("Invalid arguments: {}\n", error.0));
            help_error();
            return ProcessExitCode::from(ExitCode::Usage as u8);
        }
    };
    if options.help {
        help();
        return ProcessExitCode::from(ExitCode::Success as u8);
    }
    ProcessExitCode::from(run(&options) as u8)
}
