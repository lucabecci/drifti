// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Controlled tracee for lifecycle tests.
//!
//! Modes: `exit <code>`, `tree`, `syscall`, `threads`, `sleep`.

#![deny(unsafe_code)]

fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("lifecycle-tracee requires Linux");
        std::process::exit(2);
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use std::env;
    use std::io::Error;
    use std::process::exit;
    use std::thread;
    use std::time::Duration;

    pub fn run() {
        let mut args = env::args().skip(1);
        match args.next().as_deref() {
            Some("exit") => {
                let code = args
                    .next()
                    .and_then(|text| text.parse::<i32>().ok())
                    .unwrap_or(0);
                exit(code);
            }
            Some("tree") => tree(),
            Some("syscall") => syscall(),
            Some("threads") => threads(),
            Some("sleep") => thread::sleep(Duration::from_secs(60)),
            _ => exit(2),
        }
    }

    fn syscall() {
        // SAFETY: `SYS_getpid` is one syscall with no pointer arguments. The
        // libc wrapper can be served from the vDSO, so this calls `syscall`
        // directly. The return value is intentionally ignored.
        unsafe {
            libc::syscall(libc::SYS_getpid);
        }
    }

    fn threads() {
        let worker = thread::spawn(|| {
            // SAFETY: same as `syscall`. This runs on a second thread so the
            // tracer must keep a separate entry/exit slot for that tid.
            unsafe {
                libc::syscall(libc::SYS_getpid);
            }
        });
        syscall();
        worker.join().expect("worker thread joins");
    }

    fn tree() {
        // SAFETY: this fixture is single-threaded here. The child only calls
        // `fork`, `waitpid`, and `_exit`, which are async-signal-safe.
        let child = unsafe { libc::fork() };
        if child < 0 {
            exit(1);
        }
        if child == 0 {
            // SAFETY: the child is single-threaded. The grandchild only exits.
            let grand = unsafe { libc::fork() };
            if grand < 0 {
                // SAFETY: `_exit` does not run destructors in the forked child.
                unsafe { libc::_exit(1) };
            }
            if grand == 0 {
                // SAFETY: `_exit` does not run destructors in the grandchild.
                unsafe { libc::_exit(0) };
            }
            reap(grand);
            // SAFETY: `_exit` does not run destructors in the forked child.
            unsafe { libc::_exit(0) };
        }
        reap(child);
    }

    fn reap(pid: libc::pid_t) {
        let mut status = 0;
        loop {
            // SAFETY: waits for a child this fixture forked. `EINTR` is retried.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc >= 0 || Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
    }
}
