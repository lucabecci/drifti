// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Presentation classes for aggregated capability profiles.
//!
//! STABLE, COMMON, RARE, and NEW describe how often a capability appeared
//! across eligible runs. They are metadata for review. They are not
//! [`Decision::Allowed`](crate::policy::Decision::Allowed) and they do not
//! edit or accept a contract.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use crate::capability::Capability;
use crate::diff::CapabilityKey;
use crate::learning::{AggregatedProfile, ProfileStatistics};
/// How often a capability showed up across eligible runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PresentationClass {
    /// Seen in one eligible run while more than one run was eligible.
    New,
    /// Seen often enough to treat as established for the selection.
    Stable,
    /// Seen in a meaningful share of runs, but not stable.
    Common,
    /// Exercised at least once, but infrequently.
    Rare,
}

impl PresentationClass {
    /// Stable class name for logs and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Stable => "stable",
            Self::Common => "common",
            Self::Rare => "rare",
        }
    }
}

impl Display for PresentationClass {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Thresholds that map run statistics to a [`PresentationClass`].
///
/// Percent values use integer math: `runs_observed * 100 / total_eligible_runs`.
/// Changing these thresholds only changes presentation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationThresholds {
    /// Minimum run share for [`PresentationClass::Stable`].
    pub stable_min_run_percent: u64,
    /// Stable also requires at least this many distinct runs.
    pub stable_min_runs_observed: u64,
    /// Minimum run share for [`PresentationClass::Common`].
    pub common_min_run_percent: u64,
}

impl Default for PresentationThresholds {
    fn default() -> Self {
        Self {
            stable_min_run_percent: 80,
            stable_min_runs_observed: 2,
            common_min_run_percent: 25,
        }
    }
}

impl PresentationThresholds {
    /// Rejects inverted percent boundaries.
    pub fn validate(self) -> Result<Self, PresentationError> {
        if self.stable_min_run_percent > 100 || self.common_min_run_percent > 100 {
            return Err(PresentationError::RunPercentOutOfRange);
        }
        if self.common_min_run_percent > self.stable_min_run_percent {
            return Err(PresentationError::CommonAboveStable);
        }
        Ok(self)
    }
}

/// One capability with counts and a presentation class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedCapability {
    capability: Capability,
    statistics: ProfileStatistics,
    class: PresentationClass,
}

impl PresentedCapability {
    /// Capability identity.
    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    /// Aggregated counts for this capability.
    #[must_use]
    pub const fn statistics(&self) -> ProfileStatistics {
        self.statistics
    }

    /// Presentation class from the configured thresholds.
    #[must_use]
    pub const fn class(&self) -> PresentationClass {
        self.class
    }
}

/// Profile entries with presentation classes in capability identity order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedProfile {
    total_eligible_runs: u64,
    entries: BTreeMap<CapabilityKey, PresentedCapability>,
}

impl PresentedProfile {
    /// Distinct eligible runs in the source aggregation.
    #[must_use]
    pub const fn total_eligible_runs(&self) -> u64 {
        self.total_eligible_runs
    }

    /// Classified capabilities in identity order.
    pub fn entries(&self) -> impl Iterator<Item = &PresentedCapability> {
        self.entries.values()
    }

    /// Class for one capability when it was exercised.
    #[must_use]
    pub fn class_of(&self, capability: &Capability) -> Option<PresentationClass> {
        self.entries
            .get(&CapabilityKey::new(capability.clone()))
            .map(PresentedCapability::class)
    }
}

impl AggregatedProfile {
    /// Assigns presentation classes using caller thresholds.
    pub fn present(
        &self,
        thresholds: PresentationThresholds,
    ) -> Result<PresentedProfile, PresentationError> {
        thresholds.validate()?;
        let mut entries = BTreeMap::new();
        for (capability, statistics) in self.capability_statistics() {
            let class = classify_presentation(statistics, self.total_eligible_runs(), thresholds);
            entries.insert(
                CapabilityKey::new(capability.clone()),
                PresentedCapability {
                    capability: capability.clone(),
                    statistics,
                    class,
                },
            );
        }
        Ok(PresentedProfile {
            total_eligible_runs: self.total_eligible_runs(),
            entries,
        })
    }
}

/// Maps one aggregated row to a presentation class.
#[must_use]
pub fn classify_presentation(
    statistics: ProfileStatistics,
    total_eligible_runs: u64,
    thresholds: PresentationThresholds,
) -> PresentationClass {
    let runs = statistics.runs_observed();
    if runs == 0 || total_eligible_runs == 0 {
        return PresentationClass::Rare;
    }
    if runs == 1 {
        return PresentationClass::New;
    }
    let run_percent = runs.saturating_mul(100) / total_eligible_runs;
    if run_percent >= thresholds.stable_min_run_percent
        && runs >= thresholds.stable_min_runs_observed
    {
        PresentationClass::Stable
    } else if run_percent >= thresholds.common_min_run_percent {
        PresentationClass::Common
    } else {
        PresentationClass::Rare
    }
}

/// Invalid threshold configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationError {
    /// A run-percent threshold was above 100.
    RunPercentOutOfRange,
    /// Common minimum exceeded stable minimum.
    CommonAboveStable,
}

impl Display for PresentationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunPercentOutOfRange => {
                formatter.write_str("run percent threshold must be at most 100")
            }
            Self::CommonAboveStable => formatter
                .write_str("common minimum run percent must not exceed stable minimum run percent"),
        }
    }
}

impl std::error::Error for PresentationError {}

#[cfg(test)]
mod tests {
    use super::{classify_presentation, PresentationClass, PresentationThresholds};
    use crate::capability::Capability;
    use crate::learning::{
        CapabilityAttempt, EligibleExecution, EligibleExecutionId, LearningInput, ProfileStatistics,
    };
    use crate::observation::Outcome;
    use crate::policy::Decision;
    use crate::resource::{FileResource, FilesystemAnchor};

    fn read(path: &str) -> Capability {
        Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    fn stats(runs: u64, observations: u64, first: u64, last: u64) -> ProfileStatistics {
        ProfileStatistics::from_counts(runs, observations, first, last)
    }

    fn execution(
        id: &str,
        attempts: impl IntoIterator<Item = CapabilityAttempt>,
    ) -> EligibleExecution {
        EligibleExecution::new(
            EligibleExecutionId::new(id).expect("execution id"),
            attempts,
        )
    }

    const THRESHOLDS: PresentationThresholds = PresentationThresholds {
        stable_min_run_percent: 80,
        stable_min_runs_observed: 2,
        common_min_run_percent: 25,
    };

    #[test]
    fn threshold_boundaries_are_deterministic() {
        assert_eq!(
            classify_presentation(stats(1, 1, 0, 0), 4, THRESHOLDS),
            PresentationClass::New
        );
        assert_eq!(
            classify_presentation(stats(2, 2, 0, 1), 4, THRESHOLDS),
            PresentationClass::Common
        );
        assert_eq!(
            classify_presentation(stats(2, 2, 0, 1), 9, THRESHOLDS),
            PresentationClass::Rare
        );
        assert_eq!(
            classify_presentation(stats(4, 4, 0, 3), 4, THRESHOLDS),
            PresentationClass::Stable
        );
        assert_eq!(
            classify_presentation(stats(3, 3, 0, 2), 3, THRESHOLDS),
            PresentationClass::Stable
        );
    }

    #[test]
    fn stable_requires_minimum_runs_even_at_full_share() {
        assert_eq!(
            classify_presentation(stats(1, 1, 0, 0), 1, THRESHOLDS),
            PresentationClass::New
        );
    }

    #[test]
    fn presented_profile_order_matches_capability_identity() {
        let a = read("src/a.rs");
        let b = read("src/b.rs");
        let input = LearningInput::select([
            execution(
                "run-1",
                [CapabilityAttempt::at(a.clone(), Outcome::Success, 0)],
            ),
            execution(
                "run-2",
                [CapabilityAttempt::at(a.clone(), Outcome::Success, 1)],
            ),
            execution(
                "run-3",
                [CapabilityAttempt::at(a.clone(), Outcome::Success, 2)],
            ),
            execution(
                "run-4",
                [
                    CapabilityAttempt::at(a.clone(), Outcome::Success, 3),
                    CapabilityAttempt::at(b.clone(), Outcome::Success, 3),
                ],
            ),
        ]);
        let presented = input.aggregate().present(THRESHOLDS).expect("thresholds");
        assert_eq!(
            presented
                .entries()
                .map(|entry| entry.capability().resource().clone())
                .collect::<Vec<_>>(),
            vec![a.resource().clone(), b.resource().clone()]
        );
        assert_eq!(presented.class_of(&a), Some(PresentationClass::Stable));
        assert_eq!(presented.class_of(&b), Some(PresentationClass::New));
    }

    #[test]
    fn presentation_metadata_is_not_a_policy_decision() {
        let rendered = format!(
            "{:?}{}{}",
            PresentationClass::Stable,
            Decision::Allowed.as_str(),
            classify_presentation(stats(4, 4, 0, 3), 4, THRESHOLDS)
        );
        assert!(rendered.contains(PresentationClass::Stable.as_str()));
        for decision in Decision::ALL {
            assert_ne!(PresentationClass::Stable.as_str(), decision.as_str());
        }
    }

    #[test]
    fn inverted_thresholds_are_rejected() {
        assert!(PresentationThresholds {
            stable_min_run_percent: 50,
            stable_min_runs_observed: 2,
            common_min_run_percent: 60,
        }
        .validate()
        .is_err());
    }
}
