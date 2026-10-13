// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment diagnostics for the Linux observer.
//!
//! These checks describe launch compatibility. They do not certify complete
//! observation or imply that ptrace enforces isolation.

use std::fmt::{self, Display, Formatter};

/// One environment prerequisite or restriction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorCheck {
    /// Linux kernel support for the syscall information API.
    Kernel,
    /// `/proc` access required for process metadata and canonical resources.
    Proc,
    /// Whether a controlled child can be traced.
    Ptrace,
    /// Yama's ptrace policy, where exposed.
    Yama,
}

/// Result of one diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorStatus {
    /// The checked prerequisite is available.
    Available,
    /// A checked prerequisite is unavailable.
    Unavailable,
    /// The environment applies a relevant restriction.
    Restricted,
    /// The check could not establish an answer.
    Unknown,
}

/// One diagnostic with an explanation safe to present to a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorFinding {
    /// Prerequisite checked.
    pub check: DoctorCheck,
    /// Result of the check.
    pub status: DoctorStatus,
    /// Explanation without process arguments or remote memory.
    pub explanation: String,
}

/// Four diagnostics for the current host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    findings: Vec<DoctorFinding>,
}

impl DoctorReport {
    /// Runs checks on the current host. A successful check does not claim
    /// complete coverage or authority over the tracee.
    #[must_use]
    pub fn run() -> Self {
        Self {
            findings: vec![check_kernel(), check_proc(), check_ptrace(), check_yama()],
        }
    }

    /// Results in stable check order.
    #[must_use]
    pub fn findings(&self) -> &[DoctorFinding] {
        &self.findings
    }
}

impl Display for DoctorFinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?}: {:?}: {}",
            self.check, self.status, self.explanation
        )
    }
}

fn finding(check: DoctorCheck, status: DoctorStatus, explanation: &str) -> DoctorFinding {
    DoctorFinding {
        check,
        status,
        explanation: explanation.to_owned(),
    }
}

fn check_kernel() -> DoctorFinding {
    #[cfg(not(target_os = "linux"))]
    {
        finding(
            DoctorCheck::Kernel,
            DoctorStatus::Unavailable,
            "The ptrace observer requires Linux.",
        )
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
            return finding(
                DoctorCheck::Kernel,
                DoctorStatus::Unknown,
                "Kernel release could not be read; ptrace compatibility is unverified.",
            );
        };
        match parse_kernel_version(&release) {
            Some((major, minor)) if (major, minor) >= (5, 3) => finding(
                DoctorCheck::Kernel,
                DoctorStatus::Available,
                "Kernel version supports PTRACE_GET_SYSCALL_INFO in the standard Linux API.",
            ),
            Some(_) => finding(
                DoctorCheck::Kernel,
                DoctorStatus::Unknown,
                "Kernel predates PTRACE_GET_SYSCALL_INFO; vendor backports are unverified.",
            ),
            None => finding(
                DoctorCheck::Kernel,
                DoctorStatus::Unknown,
                "Kernel release format is unrecognized; ptrace compatibility is unverified.",
            ),
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

fn check_proc() -> DoctorFinding {
    #[cfg(not(target_os = "linux"))]
    {
        finding(
            DoctorCheck::Proc,
            DoctorStatus::Unavailable,
            "/proc requires Linux.",
        )
    }
    #[cfg(target_os = "linux")]
    {
        if std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| crate::proc_status::parse_tgid(&status))
            .is_some()
        {
            finding(
                DoctorCheck::Proc,
                DoctorStatus::Available,
                "/proc/self/status exposes process identity.",
            )
        } else {
            finding(
                DoctorCheck::Proc,
                DoctorStatus::Unavailable,
                "/proc/self/status is unavailable or lacks process identity.",
            )
        }
    }
}

fn check_ptrace() -> DoctorFinding {
    #[cfg(not(target_os = "linux"))]
    {
        finding(
            DoctorCheck::Ptrace,
            DoctorStatus::Unavailable,
            "ptrace launch is unavailable outside Linux.",
        )
    }
    #[cfg(target_os = "linux")]
    {
        use std::time::Duration;

        use drifti_observer::{CommandSpec, ExecutionId};

        use crate::lifecycle::AcknowledgeStops;
        use crate::session::{SessionLimits, TraceSession};

        let Ok(command) = CommandSpec::try_new("/usr/bin/true", Vec::<String>::new(), None) else {
            return finding(
                DoctorCheck::Ptrace,
                DoctorStatus::Unknown,
                "Probe setup failed.",
            );
        };
        let limits = SessionLimits {
            max_wait: Some(Duration::from_secs(2)),
            ..SessionLimits::production()
        };
        match TraceSession::launch_with_limits(ExecutionId::from_raw(1), command, limits)
            .and_then(|session| session.drive(&mut AcknowledgeStops))
        {
            Ok(_) => finding(
                DoctorCheck::Ptrace,
                DoctorStatus::Available,
                "A controlled child completed a ptrace observation probe.",
            ),
            Err(_) => finding(
                DoctorCheck::Ptrace,
                DoctorStatus::Unavailable,
                "A controlled child could not complete a ptrace observation probe.",
            ),
        }
    }
}

fn check_yama() -> DoctorFinding {
    #[cfg(not(target_os = "linux"))]
    {
        finding(
            DoctorCheck::Yama,
            DoctorStatus::Unknown,
            "Yama is Linux-specific.",
        )
    }
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            Ok(scope) => classify_yama(scope.trim()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => finding(
                DoctorCheck::Yama,
                DoctorStatus::Unknown,
                "Yama ptrace_scope is not exposed on this kernel.",
            ),
            Err(_) => finding(
                DoctorCheck::Yama,
                DoctorStatus::Unknown,
                "Yama ptrace_scope could not be read.",
            ),
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
fn classify_yama(value: &str) -> DoctorFinding {
    match value {
        "0" => finding(DoctorCheck::Yama, DoctorStatus::Available, "Yama adds no ptrace restriction."),
        "1" => finding(DoctorCheck::Yama, DoctorStatus::Restricted, "Yama restricts attach; tracing a launched child must be probed separately."),
        "2" => finding(DoctorCheck::Yama, DoctorStatus::Restricted, "Yama requires elevated ptrace permission; tracing a launched child must be probed separately."),
        "3" => finding(DoctorCheck::Yama, DoctorStatus::Unavailable, "Yama blocks ptrace; the observer cannot trace a launched child."),
        _ => finding(DoctorCheck::Yama, DoctorStatus::Unknown, "Yama ptrace_scope value is unrecognized."),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_yama, parse_kernel_version, DoctorCheck, DoctorStatus};

    #[test]
    fn yama_restrictions_are_explained_without_claiming_coverage() {
        assert_eq!(classify_yama("0").status, DoctorStatus::Available);
        assert_eq!(classify_yama("1").status, DoctorStatus::Restricted);
        assert_eq!(classify_yama("2").status, DoctorStatus::Restricted);
        assert_eq!(classify_yama("3").status, DoctorStatus::Unavailable);
        let unknown = classify_yama("7");
        assert_eq!(unknown.check, DoctorCheck::Yama);
        assert_eq!(unknown.status, DoctorStatus::Unknown);
    }

    #[test]
    fn kernel_version_parsing_is_conservative() {
        assert_eq!(parse_kernel_version("6.8.0-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("unknown"), None);
    }
}
