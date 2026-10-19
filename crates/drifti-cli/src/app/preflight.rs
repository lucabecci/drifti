// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observer launch preflight (SPEC-010 failure precedence).

use drifti_observer_linux::{DoctorCheck, DoctorReport, DoctorStatus};

use super::AppError;

/// Whether the Linux observer can attempt a traced launch on this host.
#[must_use]
pub fn observer_launch_ready(report: &DoctorReport) -> bool {
    report.findings().iter().all(|finding| {
        matches!(
            (finding.check, finding.status),
            (DoctorCheck::Kernel, DoctorStatus::Available)
                | (DoctorCheck::Proc, DoctorStatus::Available)
                | (DoctorCheck::Ptrace, DoctorStatus::Available)
                | (
                    DoctorCheck::Yama,
                    DoctorStatus::Available | DoctorStatus::Restricted
                )
                | (DoctorCheck::Yama, DoctorStatus::Unknown)
        ) || finding.status == DoctorStatus::Restricted
    }) && report.findings().iter().any(|finding| {
        finding.check == DoctorCheck::Ptrace && finding.status == DoctorStatus::Available
    })
}

/// Blocks observe/verify launch when ptrace prerequisites are missing.
pub fn ensure_observer_preflight() -> Result<(), AppError> {
    let report = DoctorReport::run();
    if observer_launch_ready(&report) {
        return Ok(());
    }
    let reasons: Vec<_> = report
        .findings()
        .iter()
        .filter(|finding| {
            matches!(
                finding.status,
                DoctorStatus::Unavailable | DoctorStatus::Unknown
            ) && finding.check != DoctorCheck::Yama
        })
        .map(|finding| finding.explanation.as_str())
        .collect();
    let detail = if reasons.is_empty() {
        "ptrace is not available on this host".to_owned()
    } else {
        reasons.join("; ")
    };
    Err(AppError::Internal {
        message: format!("observer preflight failed: {detail}"),
    })
}
