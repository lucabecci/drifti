// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tracer that launches a sleeper and then exits without detaching.
//!
//! `PTRACE_O_EXITKILL` must kill the tracee. `mem::forget` skips `Drop`, so
//! this process does not `SIGKILL` the tracee itself. `process::exit` also
//! skips destructors. The test observes whether the kernel killed the tracee.

#![deny(unsafe_code)]

fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("lifecycle-tracer requires Linux");
        std::process::exit(2);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::env;
    use std::io::{self, Write};
    use std::mem;
    use std::process;

    use drifti_observer::{CommandSpec, ExecutionId};
    use drifti_observer_linux::TraceSession;

    pub fn run() {
        let fixture = env::args().nth(1).unwrap_or_else(|| {
            eprintln!("usage: lifecycle-tracer <tracee>");
            process::exit(2);
        });
        let command =
            CommandSpec::try_new(fixture, ["sleep".to_string()], None).unwrap_or_else(|error| {
                eprintln!("{error}");
                process::exit(2);
            });
        let session =
            TraceSession::launch(ExecutionId::from_raw(47), command).unwrap_or_else(|error| {
                eprintln!("{error}");
                process::exit(1);
            });
        let pid = session.root_pid().unwrap_or_else(|| {
            eprintln!("missing root pid");
            process::exit(1);
        });
        println!("{pid}");
        let _ = io::stdout().flush();
        mem::forget(session);
        process::exit(0);
    }
}
