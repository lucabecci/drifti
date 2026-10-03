// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Result of one tracee lifecycle.
//!
//! Semantic decoders are not part of this layer. Coverage is therefore
//! [`ExecutionCoverage::no_events_seen`]: `INCOMPLETE`, never `COMPLETE`.

use drifti_observer::{ExecutionCoverage, ExecutionId};

use crate::lineage::ThreadLineage;

/// Lifecycle summary for one execution.
///
/// There is no field that stores `COMPLETE`. [`Self::bootstrap_coverage`]
/// always returns incomplete coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceReport {
    lineage: ThreadLineage,
    stops_delivered: u64,
}

impl TraceReport {
    /// Builds a report from the lineage captured for one execution.
    #[must_use]
    pub fn new(lineage: ThreadLineage, stops_delivered: u64) -> Self {
        Self {
            lineage,
            stops_delivered,
        }
    }

    /// Execution this lineage belongs to.
    #[must_use]
    pub const fn execution_id(&self) -> ExecutionId {
        self.lineage.execution_id()
    }

    /// Lineage, including reaped threads.
    #[must_use]
    pub const fn lineage(&self) -> &ThreadLineage {
        &self.lineage
    }

    /// Stops handed to the visitor.
    #[must_use]
    pub const fn stops_delivered(&self) -> u64 {
        self.stops_delivered
    }

    /// Exit code of the root tracee, when it exited.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.lineage.root_exit()
    }

    /// Signal that killed the root tracee, when it died by signal.
    #[must_use]
    pub const fn root_signal(&self) -> Option<i32> {
        self.lineage.root_signal()
    }

    /// Coverage of a lifecycle that has not decoded semantic events.
    ///
    /// The status is `INCOMPLETE`. It is not `COMPLETE` and it is not
    /// `UNSUPPORTED`.
    #[must_use]
    pub const fn bootstrap_coverage(&self) -> ExecutionCoverage {
        ExecutionCoverage::no_events_seen()
    }
}

#[cfg(test)]
mod tests {
    use drifti_observer::{ExecutionId, ObservationCoverage};

    use super::TraceReport;
    use crate::lineage::ThreadLineage;

    #[test]
    fn bootstrap_coverage_is_never_complete() {
        let lineage = ThreadLineage::new(ExecutionId::from_raw(7), 4, 4);
        let report = TraceReport::new(lineage, 0);
        let coverage = report.bootstrap_coverage();
        assert_eq!(coverage.status(), ObservationCoverage::Incomplete);
        assert!(!coverage.is_complete());
        assert_ne!(coverage.status(), ObservationCoverage::Complete);
        assert_ne!(coverage.status(), ObservationCoverage::Unsupported);
    }
}
