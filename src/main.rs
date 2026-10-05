use std::process::ExitCode as ProcessExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use ces::contract::parse;
use ces::native::{report, NativeError};
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
    println!("{}", ces::ces_contract::help_text());
}

fn run(options: &Options) -> ExitCode {
    match options.protocol {
        Protocol::None => ExitCode::Usage,
        Protocol::Tcp | Protocol::Udp => {
            let control = Arc::new(AtomicBool::new(false));
            // Only one server runs per process, so the first registration wins.
            let _ = CONTROL.set(Arc::clone(&control));
            let registered =
                unsafe { windows::Win32::consoleapi::SetConsoleCtrlHandler(Some(console_handler), true) };
            if !registered.as_bool() {
                let error = NativeError::last("SetConsoleCtrlHandler");
                report(error.stage, error.code);
                return ExitCode::Internal;
            }
            let result = run_server(options, &control);
            // Removal cannot fail for a handler that was just registered.
            unsafe {
                let _ = windows::Win32::consoleapi::SetConsoleCtrlHandler(Some(console_handler), false);
            }
            result
        }
    }
}

fn main() -> ProcessExitCode {
    // args_os plus a lossy conversion keeps an argument the platform cannot decode from
    // panicking the process: the wide-argv baselines treat it as an ordinary token.
    let arguments: Vec<String> = std::env::args_os()
        .map(|value| value.to_string_lossy().into_owned())
        .collect();
    let options = match parse(&arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("Invalid arguments: {}", error.0);
            help();
            return ProcessExitCode::from(ExitCode::Usage as u8);
        }
    };
    if options.help {
        help();
        return ProcessExitCode::from(ExitCode::Success as u8);
    }
    ProcessExitCode::from(run(&options) as u8)
}
