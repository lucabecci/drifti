// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux ptrace session.
//!
//! The only launch path is a [`CommandSpec`]. There is no attach-by-pid
//! constructor. The session holds an exclusive lock because it collects
//! child stops with `waitpid(-1)` and must not run beside another tracer
//! in the same process.
//!
//! `PTRACE_O_EXITKILL` is set on every tracee. Drop sends `SIGKILL` to
//! tracees that are still live and reaps them, including a tracee left in
//! ptrace-stop because the visitor returned before resume. A kill that does
//! not reap the tracee is [`TraceError::TraceeNotReaped`] from `drive` and is
//! not a successful report. A tracer that exits without running Drop relies
//! on the kernel option.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_char, CString};
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::unix::io::RawFd;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use drifti_observer::{CommandSpec, ExecutionId};

use crate::abi::SIGSTOP;
use crate::cleanup::{needs_kill_fallback, reap_step, PidfdSignal, ReapStep, REAP_BUDGET};
use crate::error::{ObservationGap, TraceError, TraceStop};
use crate::lifecycle::{apply_stop, ResumeAction, TraceVisitor};
use crate::lineage::ThreadLineage;
use crate::options::TraceOptions;
use crate::proc_status::{parse_tgid, MAX_PROC_STATUS};
use crate::report::TraceReport;
use crate::syscall::ParsedSyscall;
use crate::syscall_info::{exit_syscall_info_need, syscall_info_covers};
use crate::wait_status::{decode_wait_status, DecodedWait};

/// Bounds for one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    /// Maximum live and reaped threads remembered for the execution.
    pub max_tracees: usize,
    /// Maximum gaps stored on the lineage.
    pub max_gaps: usize,
    /// Maximum stops delivered to the visitor.
    pub max_stops: u64,
    /// When set, `wait` fails instead of blocking past this duration.
    pub max_wait: Option<Duration>,
}

impl SessionLimits {
    /// Limits used by [`super::LinuxObserver`].
    #[must_use]
    pub const fn production() -> Self {
        Self {
            max_tracees: 1024,
            max_gaps: 256,
            max_stops: 1_000_000,
            max_wait: None,
        }
    }
}

/// A running trace. Drop kills any tracee that is still live.
pub struct TraceSession {
    lineage: ThreadLineage,
    limits: SessionLimits,
    options: u32,
    pidfds: BTreeMap<u32, PidFd>,
    stops_delivered: u64,
    gaps_sent: usize,
    _lock: MutexGuard<'static, ()>,
}

impl TraceSession {
    /// Launches `command` as a tracee under [`SessionLimits::production`].
    pub fn launch(execution_id: ExecutionId, command: CommandSpec) -> Result<Self, TraceError> {
        Self::launch_with_limits(execution_id, command, SessionLimits::production())
    }

    /// Launches `command` with explicit limits.
    pub fn launch_with_limits(
        execution_id: ExecutionId,
        command: CommandSpec,
        limits: SessionLimits,
    ) -> Result<Self, TraceError> {
        let _lock = lock_tracer();
        let options = TraceOptions::lifecycle()
            .require_lifecycle()
            .expect("lifecycle options include every required bit")
            .bits();
        let (program, args, cwd) = prepare_command(&command)?;
        let mut argv = Vec::with_capacity(args.len() + 2);
        argv.push(program.as_ptr());
        for arg in &args {
            argv.push(arg.as_ptr());
        }
        argv.push(std::ptr::null());
        let cwd_ptr = cwd
            .as_ref()
            .map(|dir| dir.as_ptr())
            .unwrap_or(std::ptr::null());

        // SAFETY: the child calls only async-signal-safe functions (`chdir`,
        // `close`, `ptrace`, `kill`, `execve`, `_exit`) and then either
        // replaces its image or exits. It does not allocate, lock, or drop
        // Rust values. The parent keeps using this process.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(TraceError::Launch {
                errno: last_errno(),
            });
        }
        if pid == 0 {
            child_exec(program.as_ptr(), argv.as_ptr(), cwd_ptr);
        }

        let mut guard = ChildGuard::new(pid);
        let status = wait_pid(pid, limits.max_wait)?;
        match decode_wait_status(status) {
            DecodedWait::Exited { code } => {
                guard.note_reaped();
                return Err(TraceError::TraceeExitedBeforeAttach { code });
            }
            DecodedWait::Stopped { signal } if signal == SIGSTOP => {}
            _ => return Err(TraceError::UnexpectedFirstStop),
        }
        set_options(pid, options)?;
        let root = u32::try_from(pid).map_err(|_| TraceError::InvalidTid)?;
        let mut lineage = ThreadLineage::new(execution_id, limits.max_tracees, limits.max_gaps);
        lineage.attach_root(root)?;
        lineage.mark_options_applied(root)?;
        let mut pidfds = BTreeMap::new();
        match open_pidfd(pid) {
            Ok(fd) => {
                pidfds.insert(root, fd);
            }
            Err(_) => lineage.push_gap(ObservationGap::PidfdUnavailable { tid: root })?,
        }
        note_proc_tgid(&mut lineage, root)?;
        let pid = guard.disarm();
        let mut session = Self {
            lineage,
            limits,
            options,
            pidfds,
            stops_delivered: 0,
            gaps_sent: 0,
            _lock,
        };
        if let Err(error) = session.syscall_resume(pid, 0) {
            return Err(session.fail_closed(error));
        }
        Ok(session)
    }

    /// Root tracee pid.
    #[must_use]
    pub fn root_pid(&self) -> Option<u32> {
        self.lineage.root()
    }

    /// Drives the session until every tracee has been reaped.
    pub fn drive<V: TraceVisitor>(mut self, visitor: &mut V) -> Result<TraceReport, TraceError> {
        if let Err(error) = self.pump(visitor) {
            return Err(self.fail_closed(error));
        }
        self.finish()
    }

    fn pump<V: TraceVisitor>(&mut self, visitor: &mut V) -> Result<(), TraceError> {
        self.deliver_undelivered_gaps(visitor)?;
        while self.lineage.live_count() > 0 {
            let (pid, status) = wait_any(self.limits.max_wait)?;
            let tid = u32::try_from(pid).map_err(|_| TraceError::InvalidTid)?;
            let raw = self.read_raw(pid, status)?;
            let applied = match apply_stop(&mut self.lineage, tid, raw) {
                Err(TraceError::TraceeCapacity { tid: rejected }) => {
                    return Err(TraceError::TraceeCapacity { tid: rejected });
                }
                other => other?,
            };
            self.close_dead_pidfds();
            self.deliver_undelivered_gaps(visitor)?;
            if !matches!(applied.stop, TraceStop::Gap(_)) {
                self.deliver(applied.stop, visitor)?;
            }
            self.resume(tid, applied.action, visitor)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<TraceReport, TraceError> {
        if self.lineage.live_count() != 0 {
            return Err(self.fail_closed(TraceError::LiveTraceesRemain));
        }
        let stops_delivered = self.stops_delivered;
        let execution_id = self.lineage.execution_id();
        let lineage = mem::replace(&mut self.lineage, ThreadLineage::new(execution_id, 0, 0));
        Ok(TraceReport::new(lineage, stops_delivered))
    }

    fn read_raw(
        &self,
        pid: libc::pid_t,
        status: i32,
    ) -> Result<crate::lifecycle::RawStop, TraceError> {
        use crate::lifecycle::{PtraceEventKind, RawStop};
        match decode_wait_status(status) {
            DecodedWait::Syscall => Ok(RawStop::Syscall(read_parsed_syscall(pid)?)),
            DecodedWait::Event { event } => Ok(RawStop::Event {
                event: PtraceEventKind::from_raw(event),
                message: event_message(pid)?,
            }),
            DecodedWait::Stopped { signal } => Ok(RawStop::Stopped { signal }),
            DecodedWait::Exited { code } => Ok(RawStop::Exited { code }),
            DecodedWait::Signaled { signal } => Ok(RawStop::Signaled { signal }),
            DecodedWait::Continued => Ok(RawStop::Continued),
        }
    }

    fn resume<V: TraceVisitor>(
        &mut self,
        tid: u32,
        action: ResumeAction,
        visitor: &mut V,
    ) -> Result<(), TraceError> {
        match action {
            ResumeAction::Reaped | ResumeAction::AlreadyRunning => Ok(()),
            ResumeAction::AttachThenSyscall => {
                self.note_pidfd(tid)?;
                note_proc_tgid(&mut self.lineage, tid)?;
                self.deliver_undelivered_gaps(visitor)?;
                let pid = pid_of(tid)?;
                set_options(pid, self.options)?;
                self.lineage.mark_options_applied(tid)?;
                self.syscall_resume(pid, 0)
            }
            ResumeAction::Syscall { signal } => {
                let pid = pid_of(tid)?;
                self.syscall_resume(pid, signal)
            }
        }
    }

    fn note_pidfd(&mut self, tid: u32) -> Result<(), TraceError> {
        if self.pidfds.contains_key(&tid) {
            return Ok(());
        }
        let pid = pid_of(tid)?;
        match open_pidfd(pid) {
            Ok(fd) => {
                self.pidfds.insert(tid, fd);
                Ok(())
            }
            Err(_) => self
                .lineage
                .push_gap(ObservationGap::PidfdUnavailable { tid }),
        }
    }

    fn close_dead_pidfds(&mut self) {
        let live: BTreeSet<u32> = self.lineage.live_tids().collect();
        self.pidfds.retain(|tid, _| live.contains(tid));
    }

    fn deliver_undelivered_gaps<V: TraceVisitor>(
        &mut self,
        visitor: &mut V,
    ) -> Result<(), TraceError> {
        while self.gaps_sent < self.lineage.gaps().len() {
            let gap = self.lineage.gaps()[self.gaps_sent];
            self.deliver(TraceStop::Gap(gap), visitor)?;
            self.gaps_sent += 1;
        }
        Ok(())
    }

    fn deliver<V: TraceVisitor>(
        &mut self,
        stop: TraceStop,
        visitor: &mut V,
    ) -> Result<(), TraceError> {
        if self.stops_delivered >= self.limits.max_stops {
            return Err(TraceError::StopLimit {
                stop: Box::new(stop),
            });
        }
        visitor.on_stop(&stop, &self.lineage)?;
        self.stops_delivered += 1;
        Ok(())
    }

    fn syscall_resume(&self, pid: libc::pid_t, signal: i32) -> Result<(), TraceError> {
        ptrace_ok(
            libc::PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut(),
            signal as usize as *mut libc::c_void,
        )
    }

    /// Kills and reaps every live tracee, plus `extra` when it is not in the
    /// lineage (a capacity rejection). A tid that is still alive is not marked
    /// reaped.
    fn terminate_ids(&mut self, extra: Option<u32>) -> Result<(), (u32, i32)> {
        let mut tids: Vec<u32> = self.lineage.live_tids().collect();
        if let Some(extra) = extra {
            if !tids.contains(&extra) {
                tids.push(extra);
            }
        }
        let deadline = Instant::now() + REAP_BUDGET;
        let mut failure: Option<(u32, i32)> = None;
        for tid in tids {
            let pid = match pid_of(tid) {
                Ok(pid) => pid,
                Err(_) => {
                    failure.get_or_insert((tid, libc::EINVAL));
                    continue;
                }
            };
            let fd = self.pidfds.get(&tid).map(|slot| slot.0);
            if let Err(errno) = signal_and_reap(pid, fd, deadline) {
                failure.get_or_insert((tid, errno));
                continue;
            }
            if self.lineage.record(tid).is_some() && self.lineage.mark_reaped(tid).is_err() {
                failure.get_or_insert((tid, libc::EINVAL));
            }
        }
        self.close_dead_pidfds();
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Runs [`Self::terminate_ids`] and, when that fails, returns
    /// [`TraceError::TraceeNotReaped`] without dropping `prior`.
    fn fail_closed(&mut self, prior: TraceError) -> TraceError {
        let extra = match &prior {
            TraceError::TraceeCapacity { tid } => Some(*tid),
            _ => None,
        };
        match self.terminate_ids(extra) {
            Ok(()) => prior,
            Err((tid, errno)) => TraceError::TraceeNotReaped {
                tid,
                errno,
                prior: Some(Box::new(prior)),
            },
        }
    }
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        // `drive` reports `TraceeNotReaped` when it still owns the session.
        // This is the retry for that path and the only attempt when the
        // session is dropped without `drive`. A failure is not marked reaped
        // and does not build a report, so it is not `COMPLETE`.
        match self.terminate_ids(None) {
            Ok(()) => {}
            Err((tid, errno)) => {
                let _unreaped = (tid, errno);
            }
        }
    }
}

struct PidFd(RawFd);

impl Drop for PidFd {
    fn drop(&mut self) {
        // SAFETY: the descriptor was returned by `pidfd_open` and is owned here.
        unsafe { libc::close(self.0) };
    }
}

struct ChildGuard {
    pid: libc::pid_t,
    armed: bool,
}

impl ChildGuard {
    fn new(pid: libc::pid_t) -> Self {
        Self { pid, armed: true }
    }

    fn note_reaped(&mut self) {
        self.armed = false;
    }

    fn disarm(mut self) -> libc::pid_t {
        self.armed = false;
        let pid = self.pid;
        mem::forget(self);
        pid
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // The child may already be in the attach stop. A blocking `wait`
        // without resume does not reap that stop. There is no report yet:
        // the launch error is the caller's result.
        let deadline = Instant::now() + REAP_BUDGET;
        let _ = signal_and_reap(self.pid, None, deadline);
    }
}

fn lock_tracer() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn prepare_command(
    command: &CommandSpec,
) -> Result<(CString, Vec<CString>, Option<CString>), TraceError> {
    let program = CString::new(command.program()).map_err(|_| TraceError::Launch {
        errno: libc::EINVAL,
    })?;
    let mut args = Vec::with_capacity(command.args().len());
    for arg in command.args() {
        let arg = CString::new(arg.as_str()).map_err(|_| TraceError::Launch {
            errno: libc::EINVAL,
        })?;
        args.push(arg);
    }
    let cwd = match command.current_dir() {
        Some(dir) => Some(CString::new(dir).map_err(|_| TraceError::Launch {
            errno: libc::EINVAL,
        })?),
        None => None,
    };
    Ok((program, args, cwd))
}

fn child_exec(program: *const c_char, argv: *const *const c_char, cwd: *const c_char) -> ! {
    if !cwd.is_null() {
        // SAFETY: `cwd` is a NUL-terminated path inherited across `fork`.
        // `chdir` is async-signal-safe. Failure exits before any trace stop.
        if unsafe { libc::chdir(cwd) } != 0 {
            // SAFETY: `_exit` does not run destructors.
            unsafe { libc::_exit(126) };
        }
    }
    // Spawn hygiene so the tracee does not keep the tracer's incidental
    // descriptors open. This is not a sandbox and does not isolate the
    // process. Descriptors above 1023 stay inherited.
    for fd in 3..1024 {
        // SAFETY: `close` is async-signal-safe. `EBADF` is ignored.
        unsafe { libc::close(fd) };
    }
    // SAFETY: `PTRACE_TRACEME` takes no buffer. It only marks this child.
    let traced = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if traced != 0 {
        // SAFETY: `_exit` does not run destructors. `TRACEME` failed, so this
        // child is not attached and must not continue to `execve`.
        unsafe { libc::_exit(126) };
    }
    // SAFETY: `kill` is async-signal-safe. `SIGSTOP` stops this child until
    // the parent sets options and continues it. The child cannot reach
    // `execve` before that continue.
    if unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) } != 0 {
        // SAFETY: `_exit` does not run destructors. `SIGSTOP` failed, so the
        // parent would not observe the attach stop.
        unsafe { libc::_exit(126) };
    }
    // SAFETY: `environ` is the process environment block inherited across
    // `fork`. This reads the pointer and does not copy argument text.
    let envp = unsafe { libc::environ as *const *const c_char };
    // SAFETY: `program` and `argv` address CStrings allocated before `fork`
    // and inherited by this child. `argv` is NUL-terminated. `execve` does
    // not return on success and does not copy arguments into an event.
    unsafe { libc::execve(program, argv, envp) };
    // SAFETY: `_exit` does not run destructors. `execve` failed.
    unsafe { libc::_exit(127) };
}

fn note_proc_tgid(lineage: &mut ThreadLineage, tid: u32) -> Result<(), TraceError> {
    match read_tgid(tid) {
        Some(tgid) => lineage.set_tgid(tid, tgid),
        None => {
            let known = lineage.record(tid).and_then(|record| record.tgid());
            if known.is_none() {
                lineage.push_gap(ObservationGap::ProcStatusUnreadable { tid })?;
            }
            Ok(())
        }
    }
}

fn read_tgid(tid: u32) -> Option<u32> {
    let mut file = File::open(format!("/proc/{tid}/status")).ok()?;
    let mut buffer = vec![0_u8; MAX_PROC_STATUS];
    let read = file.read(&mut buffer).ok()?;
    let text = String::from_utf8_lossy(&buffer[..read]);
    parse_tgid(&text)
}

fn open_pidfd(pid: libc::pid_t) -> Result<PidFd, i32> {
    // SAFETY: `SYS_pidfd_open` returns a new descriptor for `pid` or -1. The
    // flags argument is 0. It does not write through a caller buffer.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        Err(last_errno())
    } else {
        Ok(PidFd(fd as RawFd))
    }
}

fn signal_pidfd(fd: RawFd) -> Result<(), i32> {
    // SAFETY: `fd` is an open pidfd owned by this session. `SIGKILL` is
    // delivered to that pidfd's process, not to a reused pid number. A null
    // siginfo asks the kernel to synthesize the signal. The flags argument
    // is 0. The return value is checked by the caller.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            crate::abi::SIGKILL,
            std::ptr::null_mut::<libc::siginfo_t>(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_errno())
    }
}

fn classify_pidfd(fd: Option<RawFd>) -> PidfdSignal {
    match fd {
        None => PidfdSignal::Unavailable,
        Some(fd) => match signal_pidfd(fd) {
            Ok(()) => PidfdSignal::Sent,
            Err(errno) if errno == libc::ESRCH => PidfdSignal::AlreadyGone,
            Err(_) => PidfdSignal::Failed,
        },
    }
}

fn kill_pid(pid: libc::pid_t) -> Result<(), i32> {
    // SAFETY: `pid` is a tracee of this session, or the child of a failed
    // launch. `SIGKILL` is cleanup. When pidfd_open failed, the pid number
    // can theoretically be reused; that miss is `PidfdUnavailable` on the
    // paths that tried to open a pidfd. The caller checks the return value
    // and does not treat a failure as a reap.
    let rc = unsafe { libc::kill(pid, crate::abi::SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        let errno = last_errno();
        if errno == libc::ESRCH {
            Ok(())
        } else {
            Err(errno)
        }
    }
}

fn resume_killed(pid: libc::pid_t) {
    // SAFETY: `pid` is a tracee of this session or the launch child.
    // `PTRACE_CONT` with `SIGKILL` resumes a ptrace-stop and delivers a
    // signal the tracee cannot block. A running or already-dead task makes
    // `ptrace` fail; that failure is not a reap. The caller keeps waiting.
    unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            crate::abi::SIGKILL as usize as *mut libc::c_void,
        );
    }
}

fn signal_and_reap(pid: libc::pid_t, pidfd: Option<RawFd>, deadline: Instant) -> Result<(), i32> {
    let signaled = classify_pidfd(pidfd);
    let kill_result = if needs_kill_fallback(signaled) {
        kill_pid(pid)
    } else {
        Ok(())
    };
    match (kill_result, reap_signaled(pid, deadline)) {
        (_, Ok(())) => Ok(()),
        (Err(errno), Err(_)) => Err(errno),
        (Ok(()), Err(errno)) => Err(errno),
    }
}

fn reap_signaled(pid: libc::pid_t, deadline: Instant) -> Result<(), i32> {
    loop {
        let mut status = 0;
        // SAFETY: waits for this tracee only. `__WALL` also collects clone
        // threads. `WNOHANG` keeps the deadline in this process. The status
        // word is a local `i32`.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
        if rc == pid {
            match reap_step(Some(decode_wait_status(status))) {
                ReapStep::Reaped => return Ok(()),
                ReapStep::Resume => resume_killed(pid),
            }
        } else if rc == 0 {
            debug_assert_eq!(reap_step(None), ReapStep::Resume);
            resume_killed(pid);
        } else {
            let errno = last_errno();
            if errno == libc::EINTR {
                continue;
            }
            // `ECHILD` means this tracer has no such child left to wait for.
            // A reused pid is not our child, so this is not a reason to
            // signal that number again.
            if errno == libc::ECHILD {
                return Ok(());
            }
            return Err(errno);
        }
        if Instant::now() >= deadline {
            return Err(0);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn set_options(pid: libc::pid_t, bits: u32) -> Result<(), TraceError> {
    ptrace_ok(
        libc::PTRACE_SETOPTIONS,
        pid,
        std::ptr::null_mut(),
        bits as usize as *mut libc::c_void,
    )
}

fn event_message(pid: libc::pid_t) -> Result<u64, TraceError> {
    let mut message: libc::c_ulong = 0;
    ptrace_ok(
        libc::PTRACE_GETEVENTMSG,
        pid,
        std::ptr::null_mut(),
        &mut message as *mut libc::c_ulong as *mut libc::c_void,
    )?;
    Ok(message as u64)
}

fn read_parsed_syscall(pid: libc::pid_t) -> Result<ParsedSyscall, TraceError> {
    // SAFETY: the value is a POD the kernel overwrites before it is read.
    // It is not interpreted until `ptrace` reports a full write.
    let mut info: libc::ptrace_syscall_info = unsafe { mem::zeroed() };
    let size = mem::size_of::<libc::ptrace_syscall_info>();
    let wrote = ptrace_raw(
        libc::PTRACE_GET_SYSCALL_INFO,
        pid,
        size as *mut libc::c_void,
        &mut info as *mut libc::ptrace_syscall_info as *mut libc::c_void,
    )?;
    // The kernel returns the size of the active member, not always
    // `size_of::<ptrace_syscall_info>()`. `op` is the first byte. The struct
    // was zeroed, so a short tail stays zero and is not read unless `wrote`
    // covers that member.
    if wrote < 1 {
        return Err(TraceError::SyscallInfoTruncated { wrote });
    }
    let member = mem::offset_of!(libc::ptrace_syscall_info, u);
    match info.op {
        libc::PTRACE_SYSCALL_INFO_ENTRY => {
            let need = member + mem::size_of::<libc::__c_anonymous_ptrace_syscall_info_entry>();
            if (wrote as usize) < need {
                return Err(TraceError::SyscallInfoTruncated { wrote });
            }
            // SAFETY: `op` is ENTRY and `wrote` covers the entry member, so
            // that is the member the kernel wrote.
            let entry = unsafe { info.u.entry };
            Ok(ParsedSyscall::Entry {
                number: entry.nr,
                args: entry.args,
            })
        }
        libc::PTRACE_SYSCALL_INFO_EXIT => {
            // The kernel returns `offsetofend(exit.is_error)` (33 on the
            // 64-bit layout). `sizeof` of the `{ i64, u8 }` member is 16
            // because of tail padding, and `member + 16` is 40, which rejects
            // that write. `is_error` is the last required byte; a shorter
            // write would leave the flag as the zeroed padding.
            let need = exit_syscall_info_need();
            if !syscall_info_covers(wrote, need) {
                return Err(TraceError::SyscallInfoTruncated { wrote });
            }
            // SAFETY: `op` is EXIT and `wrote` covers `sval` and `is_error`,
            // so that is the member the kernel wrote. Tail padding past
            // `is_error` is not part of the kernel's count and is not read.
            let exit = unsafe { info.u.exit };
            Ok(ParsedSyscall::Exit {
                return_value: exit.sval,
                is_error: exit.is_error != 0,
            })
        }
        libc::PTRACE_SYSCALL_INFO_SECCOMP => Ok(ParsedSyscall::Seccomp),
        _ => Ok(ParsedSyscall::Unavailable),
    }
}

fn ptrace_ok(
    request: libc::c_uint,
    pid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> Result<(), TraceError> {
    let wrote = ptrace_raw(request, pid, addr, data)?;
    if wrote < 0 {
        return Err(TraceError::Ptrace {
            errno: last_errno(),
        });
    }
    Ok(())
}

fn ptrace_raw(
    request: libc::c_uint,
    pid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> Result<i64, TraceError> {
    // SAFETY: `request` selects the kernel operation. Callers pass either a
    // null data pointer, an integer encoded as a pointer-sized value
    // (`SETOPTIONS`, `SYSCALL`), or a pointer to memory owned by this
    // function (`GETEVENTMSG`, `GET_SYSCALL_INFO`). A negative return is an
    // error and is not treated as a byte count.
    let rc = unsafe { libc::ptrace(request, pid, addr, data) };
    if rc == -1 {
        let errno = last_errno();
        return Err(match request {
            libc::PTRACE_GET_SYSCALL_INFO => TraceError::SyscallInfo { errno },
            _ => TraceError::Ptrace { errno },
        });
    }
    Ok(rc)
}

fn wait_pid(pid: libc::pid_t, max_wait: Option<Duration>) -> Result<i32, TraceError> {
    wait_internal(pid, max_wait).map(|(_, status)| status)
}

fn wait_any(max_wait: Option<Duration>) -> Result<(libc::pid_t, i32), TraceError> {
    wait_internal(-1, max_wait)
}

fn wait_internal(
    pid: libc::pid_t,
    max_wait: Option<Duration>,
) -> Result<(libc::pid_t, i32), TraceError> {
    let deadline = max_wait.map(|wait| Instant::now() + wait);
    loop {
        let mut status = 0;
        let mut flags = libc::__WALL;
        if deadline.is_some() {
            flags |= libc::WNOHANG;
        }
        // SAFETY: waits for `pid`, or for any child when `pid` is -1. The
        // session holds the tracer lock for the -1 case. The status word is
        // a local `i32`.
        let rc = unsafe { libc::waitpid(pid, &mut status, flags) };
        if rc > 0 {
            return Ok((rc, status));
        }
        if rc == 0 {
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return Err(TraceError::Wait { errno: 0 });
                }
            }
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        let errno = last_errno();
        if errno == libc::EINTR {
            continue;
        }
        return Err(TraceError::Wait { errno });
    }
}

fn pid_of(tid: u32) -> Result<libc::pid_t, TraceError> {
    i32::try_from(tid).map_err(|_| TraceError::InvalidTid)
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
