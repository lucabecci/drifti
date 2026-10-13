// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Eligible executions selected as learning input.
//!
//! A caller supplies executions it already chose. This module does not query a
//! repository and does not issue SQL. A store adapter can build
//! [`EligibleExecution`] values later; it does not live here.
//!
//! The same set of executions produces the same [`LearningInput`] from any
//! input order. Successfully exercised capabilities collapse by identity into
//! the baseline before a later aggregation. A failed attempt stays in
//! [`LearningInput::failed_evidence`] and does not enter that baseline.
//! Duplicate successes become one baseline capability.
//! [`LearningInput::aggregate`] then counts runs and observations and records
//! the caller-supplied first and last seen keys. Those counts are not a
//! policy decision and do not assign a presentation class.
//!
//! No field is [`Decision::Allowed`](crate::policy::Decision::Allowed).
//! Learning does not grant authority and does not read or write an accepted
//! contract.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::capability::Capability;
use crate::diff::{CapabilityKey, NormalizedCapabilitySet};
use crate::observation::Outcome;
use crate::profile::{CapabilityProfile, ProfileEntry};
use crate::resource::{FilesystemAnchor, NetworkAddress, NetworkProtocol, Resource};

/// Presence of one collapsed capability.
///
/// Duplicate successes become one entry before aggregation. This marker is not
/// an observation count, a run count, or a policy decision.
const COLLAPSED_PRESENCE: u64 = 1;

/// Identity of one execution in a learning selection.
///
/// The text is the caller's key. Canonical store ids sort in this same text
/// order when an adapter copies them. This type does not parse a database key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EligibleExecutionId(String);

impl EligibleExecutionId {
    /// Builds an execution id. Empty text and an embedded NUL are rejected.
    pub fn new(text: impl Into<String>) -> Result<Self, LearningInputError> {
        let text = text.into();
        if text.is_empty() {
            return Err(LearningInputError::EmptyExecutionId);
        }
        if text.contains('\0') {
            return Err(LearningInputError::EmbeddedNul);
        }
        Ok(Self(text))
    }

    /// Identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One normalized capability that an execution attempted.
///
/// [`Outcome::Success`] was exercised. [`Outcome::Failure`] was attempted and
/// is evidence only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAttempt {
    capability: Capability,
    outcome: Outcome,
    seen: u64,
}

impl CapabilityAttempt {
    /// Records one attempt of an already normalized capability.
    #[must_use]
    pub const fn new(capability: Capability, outcome: Outcome) -> Self {
        Self::at(capability, outcome, 0)
    }

    /// Records one attempt at a caller-supplied monotonic key.
    ///
    /// `seen` is not a clock reading. Aggregation uses it only to order
    /// successful observations.
    #[must_use]
    pub const fn at(capability: Capability, outcome: Outcome, seen: u64) -> Self {
        Self {
            capability,
            outcome,
            seen,
        }
    }

    /// Capability that was attempted.
    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    /// Whether the attempt exercised the capability or failed.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Whether this attempt exercised the capability.
    #[must_use]
    pub const fn was_exercised(&self) -> bool {
        matches!(self.outcome, Outcome::Success)
    }

    /// Caller-supplied monotonic key for this attempt.
    #[must_use]
    pub const fn seen(&self) -> u64 {
        self.seen
    }
}

/// One execution the caller selected for learning.
///
/// Selection happens before this value is built. Passing it here does not
/// decide that the execution is authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibleExecution {
    id: EligibleExecutionId,
    attempts: Vec<CapabilityAttempt>,
}

impl EligibleExecution {
    /// One selected execution and the attempts observed in it.
    #[must_use]
    pub fn new(
        id: EligibleExecutionId,
        attempts: impl IntoIterator<Item = CapabilityAttempt>,
    ) -> Self {
        Self {
            id,
            attempts: attempts.into_iter().collect(),
        }
    }

    /// Execution identity.
    #[must_use]
    pub fn id(&self) -> &EligibleExecutionId {
        &self.id
    }

    /// Attempts in the order the caller supplied.
    #[must_use]
    pub fn attempts(&self) -> &[CapabilityAttempt] {
        &self.attempts
    }
}

/// A failed attempt kept for inspection.
///
/// This value is not learned authority and not a policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedEvidence {
    execution: EligibleExecutionId,
    capability: Capability,
}

impl FailedEvidence {
    /// Execution in which the attempt failed.
    #[must_use]
    pub fn execution(&self) -> &EligibleExecutionId {
        &self.execution
    }

    /// Capability that was attempted and not exercised.
    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }
}

/// One successful observation of a capability inside a single execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ObservationTally {
    count: u64,
    first_seen: u64,
    last_seen: u64,
}

/// Capabilities collapsed inside one selected execution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ExecutionContribution {
    exercised: BTreeSet<CapabilityKey>,
    failed: BTreeSet<CapabilityKey>,
    observations: BTreeMap<CapabilityKey, ObservationTally>,
}

/// Ordered learning input for one selected execution set.
///
/// Executions are ordered by [`EligibleExecutionId`]. Exercised capabilities
/// in the baseline are ordered by capability identity. Failed evidence is
/// ordered by execution id, then capability identity. Two selections with the
/// same attempts compare equal after any permutation of that input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningInput {
    executions: BTreeMap<EligibleExecutionId, ExecutionContribution>,
}

impl LearningInput {
    /// Collapses a selected execution set into one ordered learning input.
    ///
    /// The same execution id may appear more than once. Its attempts are
    /// united. Order of executions and order of attempts do not change the
    /// result. A successful duplicate of one capability occupies one baseline
    /// entry. A failure is recorded as evidence and does not add a baseline
    /// entry by itself.
    #[must_use]
    pub fn select(executions: impl IntoIterator<Item = EligibleExecution>) -> Self {
        let mut grouped: BTreeMap<EligibleExecutionId, ExecutionContribution> = BTreeMap::new();
        for execution in executions {
            let EligibleExecution { id, attempts } = execution;
            let contribution = grouped.entry(id).or_default();
            for attempt in attempts {
                let CapabilityAttempt {
                    capability,
                    outcome,
                    seen,
                } = attempt;
                let key = CapabilityKey::new(capability);
                match outcome {
                    Outcome::Success => {
                        contribution.exercised.insert(key.clone());
                        let tally =
                            contribution
                                .observations
                                .entry(key)
                                .or_insert(ObservationTally {
                                    count: 0,
                                    first_seen: seen,
                                    last_seen: seen,
                                });
                        tally.count = tally.count.saturating_add(1);
                        tally.first_seen = tally.first_seen.min(seen);
                        tally.last_seen = tally.last_seen.max(seen);
                    }
                    Outcome::Failure => {
                        contribution.failed.insert(key);
                    }
                }
            }
        }
        Self {
            executions: grouped,
        }
    }

    /// Whether the selection contains no executions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.executions.is_empty()
    }

    /// Selected execution ids, in id order.
    pub fn execution_ids(&self) -> impl Iterator<Item = &EligibleExecutionId> {
        self.executions.keys()
    }

    /// Capabilities exercised in one selected execution, in identity order.
    ///
    /// [`None`] means that execution was not in the selection. An execution
    /// that was selected and only failed returns an empty iterator.
    #[must_use]
    pub fn exercised<'a>(
        &'a self,
        execution: &EligibleExecutionId,
    ) -> Option<impl Iterator<Item = &'a Capability> + 'a> {
        self.executions
            .get(execution)
            .map(|contribution| contribution.exercised.iter().map(CapabilityKey::capability))
    }

    /// Capabilities that failed in one selected execution, in identity order.
    ///
    /// [`None`] means that execution was not in the selection.
    #[must_use]
    pub fn failures<'a>(
        &'a self,
        execution: &EligibleExecutionId,
    ) -> Option<impl Iterator<Item = &'a Capability> + 'a> {
        self.executions
            .get(execution)
            .map(|contribution| contribution.failed.iter().map(CapabilityKey::capability))
    }

    /// Successfully exercised capabilities, collapsed and ordered.
    ///
    /// A capability enters this set only when at least one selected attempt
    /// exercised it. Failures do not. Duplicate identities are one entry.
    /// This set is the baseline a later aggregation may consume. It is not a
    /// policy decision.
    #[must_use]
    pub fn baseline(&self) -> NormalizedCapabilitySet {
        NormalizedCapabilitySet::normalize(self.executions.values().flat_map(|contribution| {
            contribution
                .exercised
                .iter()
                .map(|key| key.capability().clone())
        }))
    }

    /// Profile of the collapsed baseline.
    ///
    /// Each frequency is `1`: the capability is present after duplicate
    /// collapse. The frequency is not how many times it was seen, and it is
    /// not [`Decision::Allowed`](crate::policy::Decision::Allowed).
    #[must_use]
    pub fn baseline_profile(&self) -> CapabilityProfile {
        CapabilityProfile::from_entries(
            self.baseline()
                .iter()
                .cloned()
                .map(|capability| ProfileEntry::new(capability, COLLAPSED_PRESENCE)),
        )
    }

    /// Failed attempts, ordered by execution id and then capability identity.
    ///
    /// The same capability failing twice in one execution is one item. A
    /// failure that also succeeded stays here and also appears in the baseline
    /// because of the success. The failure itself is not authority.
    pub fn failed_evidence(&self) -> impl Iterator<Item = FailedEvidence> + '_ {
        self.executions
            .iter()
            .flat_map(|(execution, contribution)| {
                let execution = execution.clone();
                contribution.failed.iter().map(move |key| FailedEvidence {
                    execution: execution.clone(),
                    capability: key.capability().clone(),
                })
            })
    }

    /// Counts exercised observations across the selected executions.
    ///
    /// `runs_observed` is the number of executions in which the capability
    /// succeeded at least once. `observation_count` counts every successful
    /// attempt, including duplicates inside one execution. A failure increments
    /// neither. `first_seen` and `last_seen` are the minimum and maximum
    /// caller-supplied keys of those successes. The counts are not
    /// [`Decision::Allowed`](crate::policy::Decision::Allowed).
    #[must_use]
    pub fn aggregate(&self) -> AggregatedProfile {
        let mut entries: BTreeMap<CapabilityKey, ProfileStatistics> = BTreeMap::new();
        for contribution in self.executions.values() {
            for (key, tally) in &contribution.observations {
                let stats = entries.entry(key.clone()).or_insert(ProfileStatistics {
                    runs_observed: 0,
                    observation_count: 0,
                    first_seen: tally.first_seen,
                    last_seen: tally.last_seen,
                });
                stats.runs_observed = stats.runs_observed.saturating_add(1);
                stats.observation_count = stats.observation_count.saturating_add(tally.count);
                stats.first_seen = stats.first_seen.min(tally.first_seen);
                stats.last_seen = stats.last_seen.max(tally.last_seen);
            }
        }
        AggregatedProfile {
            total_eligible_runs: self.executions.len() as u64,
            entries,
        }
    }
}

/// Counts for one capability identity.
///
/// These fields sit beside identity. They are not an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileStatistics {
    runs_observed: u64,
    observation_count: u64,
    first_seen: u64,
    last_seen: u64,
}

impl ProfileStatistics {
    /// Executions in which this capability was exercised at least once.
    #[must_use]
    pub const fn runs_observed(self) -> u64 {
        self.runs_observed
    }

    /// Successful attempts, including more than one inside a single execution.
    #[must_use]
    pub const fn observation_count(self) -> u64 {
        self.observation_count
    }

    /// Smallest caller-supplied key among successful attempts.
    #[must_use]
    pub const fn first_seen(self) -> u64 {
        self.first_seen
    }

    /// Largest caller-supplied key among successful attempts.
    #[must_use]
    pub const fn last_seen(self) -> u64 {
        self.last_seen
    }

    #[doc(hidden)]
    pub const fn from_counts(
        runs_observed: u64,
        observation_count: u64,
        first_seen: u64,
        last_seen: u64,
    ) -> Self {
        Self {
            runs_observed,
            observation_count,
            first_seen,
            last_seen,
        }
    }
}

/// Deterministic profile counts for one learning selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedProfile {
    total_eligible_runs: u64,
    entries: BTreeMap<CapabilityKey, ProfileStatistics>,
}

impl AggregatedProfile {
    /// Distinct selected executions, not the number of attempts.
    #[must_use]
    pub const fn total_eligible_runs(&self) -> u64 {
        self.total_eligible_runs
    }

    /// Statistics for one capability, when it was exercised.
    #[must_use]
    pub fn statistics(&self, capability: &Capability) -> Option<ProfileStatistics> {
        self.entries
            .get(&CapabilityKey::new(capability.clone()))
            .copied()
    }

    /// Exercised capabilities in identity order.
    pub fn capabilities(&self) -> impl Iterator<Item = &Capability> {
        self.entries.keys().map(CapabilityKey::capability)
    }

    /// Exercised capabilities with their aggregated statistics, in identity order.
    pub fn capability_statistics(
        &self,
    ) -> impl Iterator<Item = (&Capability, ProfileStatistics)> + '_ {
        self.entries
            .iter()
            .map(|(key, stats)| (key.capability(), *stats))
    }

    /// Stable text for this profile. Identical histories produce the same bytes.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        let mut text = format!("total_eligible_runs {}\n", self.total_eligible_runs);
        for (key, stats) in &self.entries {
            let capability = key.capability();
            text.push_str(&format!(
                "{} {} {} {} {} {}\n",
                capability.action().as_str(),
                resource_identity(capability.resource()),
                stats.runs_observed,
                stats.observation_count,
                stats.first_seen,
                stats.last_seen,
            ));
        }
        text
    }
}

fn resource_identity(resource: &Resource) -> String {
    match resource {
        Resource::File(file) => {
            let anchor = match file.anchor() {
                FilesystemAnchor::Repo => "repo",
                FilesystemAnchor::Home => "home",
                FilesystemAnchor::Temp => "temp",
                FilesystemAnchor::Absolute => "abs",
            };
            format!("file {anchor} {}", file.file_path())
        }
        Resource::Executable(executable) => format!("executable {}", executable.identity()),
        Resource::Network(network) => {
            let protocol = match network.protocol() {
                NetworkProtocol::Tcp => "tcp",
                NetworkProtocol::Udp => "udp",
            };
            let address = match network.address() {
                NetworkAddress::Ip(address) => address.to_string(),
                NetworkAddress::Cidr(cidr) => {
                    format!("{}/{}", cidr.address(), cidr.prefix_length())
                }
            };
            format!("network {protocol} {address} {}", network.port())
        }
    }
}

/// An execution id could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningInputError {
    /// Execution id text was empty.
    EmptyExecutionId,
    /// Execution id text contained a NUL byte.
    EmbeddedNul,
}

impl Display for LearningInputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExecutionId => formatter.write_str("execution id text is empty"),
            Self::EmbeddedNul => formatter.write_str("execution id text contains a NUL byte"),
        }
    }
}

impl Error for LearningInputError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;
    use proptest::test_runner::{TestRng, TestRunner};

    use super::{
        CapabilityAttempt, EligibleExecution, EligibleExecutionId, LearningInput,
        LearningInputError, COLLAPSED_PRESENCE,
    };
    use crate::capability::Capability;
    use crate::diff::{CapabilityKey, NormalizedCapabilitySet};
    use crate::observation::Outcome;
    use crate::policy::Decision;
    use crate::profile::{CapabilityProfile, ProfileEntry};
    use crate::resource::{ExecutableResource, FileResource, FilesystemAnchor};

    fn execution_id(text: &str) -> EligibleExecutionId {
        EligibleExecutionId::new(text).expect("execution id")
    }

    fn read(path: &str) -> Capability {
        Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    fn success(capability: Capability) -> CapabilityAttempt {
        CapabilityAttempt::new(capability, Outcome::Success)
    }

    fn failure(capability: Capability) -> CapabilityAttempt {
        CapabilityAttempt::new(capability, Outcome::Failure)
    }

    fn execution(
        id: &str,
        attempts: impl IntoIterator<Item = CapabilityAttempt>,
    ) -> EligibleExecution {
        EligibleExecution::new(execution_id(id), attempts)
    }

    fn not_a_policy_decision(profile: &CapabilityProfile) {
        trait NotAPolicyDecision {}
        impl NotAPolicyDecision for CapabilityProfile {}

        fn witness<T: NotAPolicyDecision>(_: &T) {}
        witness(profile);
    }

    fn deterministic_runner() -> TestRunner {
        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm))
    }

    fn arb_attempt() -> impl Strategy<Value = CapabilityAttempt> {
        (0..4u8, 0..2u8).prop_map(|(resource, outcome_bit)| {
            let file_path =
                ["src/a.rs", "src/b.rs", "src/c.rs", "src/./a.rs"][usize::from(resource)];
            let capability = read(file_path);
            let outcome = if outcome_bit == 0 {
                Outcome::Success
            } else {
                Outcome::Failure
            };
            CapabilityAttempt::new(capability, outcome)
        })
    }

    fn arb_execution() -> impl Strategy<Value = EligibleExecution> {
        (
            prop_oneof![Just("a"), Just("b"), Just("c")],
            proptest::collection::vec(arb_attempt(), 0..=4),
        )
            .prop_map(|(id, attempts)| execution(id, attempts))
    }

    fn permute(
        executions: &[EligibleExecution],
        execution_order: &[u64],
        attempt_order: &[u64],
    ) -> Vec<EligibleExecution> {
        let mut items: Vec<(usize, EligibleExecution)> =
            executions.iter().cloned().enumerate().collect();
        items.sort_by(|left, right| {
            let left_key = execution_order.get(left.0).copied().unwrap_or(0);
            let right_key = execution_order.get(right.0).copied().unwrap_or(0);
            left_key.cmp(&right_key).then(left.0.cmp(&right.0))
        });
        items
            .into_iter()
            .map(|(index, execution)| {
                let mut attempts: Vec<(usize, CapabilityAttempt)> =
                    execution.attempts().iter().cloned().enumerate().collect();
                let salt = execution_order.get(index).copied().unwrap_or(0);
                attempts.sort_by(|left, right| {
                    let left_key = attempt_order.get(left.0).copied().unwrap_or(0) ^ salt;
                    let right_key = attempt_order.get(right.0).copied().unwrap_or(0) ^ salt;
                    left_key.cmp(&right_key).then(left.0.cmp(&right.0))
                });
                EligibleExecution::new(
                    execution.id().clone(),
                    attempts.into_iter().map(|(_, attempt)| attempt),
                )
            })
            .collect()
    }

    #[test]
    fn execution_id_rejects_empty_text_and_nul() {
        assert_eq!(
            EligibleExecutionId::new(""),
            Err(LearningInputError::EmptyExecutionId)
        );
        assert_eq!(
            EligibleExecutionId::new("run\0"),
            Err(LearningInputError::EmbeddedNul)
        );
    }

    #[test]
    fn empty_selection_has_an_empty_baseline() {
        let input = LearningInput::select([]);
        assert!(input.is_empty());
        assert!(input.baseline().is_empty());
        assert_eq!(input.failed_evidence().count(), 0);
        assert!(input.baseline_profile().capabilities().next().is_none());
        not_a_policy_decision(&input.baseline_profile());
    }

    #[test]
    fn failed_attempt_stays_out_of_the_baseline() {
        let exercised = read("src/lib.rs");
        let failed = read("src/secret.rs");
        let input = LearningInput::select([execution(
            "run",
            [
                success(exercised.clone()),
                failure(failed.clone()),
                failure(failed.clone()),
            ],
        )]);

        assert_eq!(
            input.baseline().iter().cloned().collect::<Vec<_>>(),
            vec![exercised]
        );
        let evidence: Vec<_> = input.failed_evidence().collect();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].execution().as_str(), "run");
        assert_eq!(evidence[0].capability(), &failed);
        assert!(input
            .baseline()
            .iter()
            .all(|capability| capability != &failed));
        assert_eq!(
            input.failures(&execution_id("run")).expect("run").count(),
            1
        );
        assert!(input.exercised(&execution_id("other")).is_none());
    }

    #[test]
    fn duplicate_successes_collapse_before_aggregation() {
        let capability = read("src/lib.rs");
        let other = Capability::process_execute(ExecutableResource::new("git").expect("git"));
        let input = LearningInput::select([
            execution(
                "b",
                [
                    success(other.clone()),
                    success(capability.clone()),
                    success(capability.clone()),
                ],
            ),
            execution(
                "a",
                [success(capability.clone()), success(read("src/./lib.rs"))],
            ),
        ]);

        assert_eq!(input.baseline().len(), 2);
        assert_eq!(
            input.baseline().iter().cloned().collect::<Vec<_>>(),
            vec![capability.clone(), other]
        );
        assert_eq!(
            input
                .execution_ids()
                .map(EligibleExecutionId::as_str)
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(input.exercised(&execution_id("a")).expect("a").count(), 1);
        assert_eq!(input.exercised(&execution_id("b")).expect("b").count(), 2);
        let profile = input.baseline_profile();
        assert_eq!(profile.frequency_of(&capability), Some(1));
        assert_eq!(
            COLLAPSED_PRESENCE,
            profile.frequency_of(&capability).expect("present")
        );
    }

    #[test]
    fn a_failure_does_not_erase_or_explain_a_success() {
        let capability = read("src/lib.rs");
        let input = LearningInput::select([execution(
            "run",
            [
                failure(capability.clone()),
                success(capability.clone()),
                failure(capability.clone()),
            ],
        )]);

        assert_eq!(
            input.baseline().iter().cloned().collect::<Vec<_>>(),
            vec![capability.clone()]
        );
        let evidence: Vec<_> = input.failed_evidence().collect();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].capability(), &capability);
        let rendered = format!("{input:?}");
        assert!(!rendered.contains("intent"));
        assert!(!rendered.contains(Decision::Allowed.as_str()));
    }

    #[test]
    fn the_same_execution_id_merges_in_id_order() {
        let read_cap = read("src/a.rs");
        let write_cap = Capability::filesystem_write(
            FileResource::new(FilesystemAnchor::Repo, "src/a.rs").expect("file"),
        );
        let forward = LearningInput::select([
            execution("run", [failure(write_cap.clone())]),
            execution("run", [success(read_cap.clone())]),
        ]);
        let reverse = LearningInput::select([
            execution("run", [success(read_cap.clone())]),
            execution("run", [failure(write_cap.clone())]),
        ]);
        assert_eq!(forward, reverse);
        assert_eq!(
            forward.baseline().iter().cloned().collect::<Vec<_>>(),
            vec![read_cap]
        );
        assert_eq!(forward.failed_evidence().count(), 1);
        assert!(forward
            .baseline()
            .iter()
            .all(|capability| capability != &write_cap));
    }

    #[test]
    fn input_order_does_not_change_the_learning_input() {
        let first = read("src/a.rs");
        let second = read("src/b.rs");
        let failed = read("src/c.rs");
        let left = LearningInput::select([
            execution("b", [failure(failed.clone()), success(second.clone())]),
            execution("a", [success(first.clone())]),
        ]);
        let right = LearningInput::select([
            execution("a", [success(first.clone())]),
            execution("b", [success(second.clone()), failure(failed.clone())]),
        ]);
        assert_eq!(left, right);
        let evidence: Vec<_> = left.failed_evidence().collect();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].execution().as_str(), "b");
        assert_eq!(evidence[0].capability(), &failed);
        assert_eq!(
            left.baseline().iter().cloned().collect::<Vec<_>>(),
            vec![first, second]
        );
    }

    #[test]
    fn baseline_profile_is_not_a_policy_decision() {
        let capability = read("src/lib.rs");
        let input = LearningInput::select([execution("run", [success(capability.clone())])]);
        let profile = input.baseline_profile();
        not_a_policy_decision(&profile);
        assert_eq!(
            profile,
            CapabilityProfile::from_entries([ProfileEntry::new(capability.clone(), 1)])
        );
        assert_eq!(
            profile,
            CapabilityProfile::from_entries([ProfileEntry::new(capability, u64::MAX)])
        );
        let rendered = format!("{input:?}{profile:?}");
        for decision in Decision::ALL {
            assert!(
                !rendered.contains(decision.as_str()),
                "{}",
                decision.as_str()
            );
        }
    }

    #[test]
    fn aggregate_counts_successes_and_ignores_failures() {
        let repeated = read("src/a.rs");
        let once = read("src/b.rs");
        let failed = Capability::filesystem_write(
            FileResource::new(FilesystemAnchor::Repo, "src/a.rs").expect("file"),
        );
        let forward = LearningInput::select([
            execution(
                "run-b",
                [
                    CapabilityAttempt::at(repeated.clone(), Outcome::Success, 10),
                    CapabilityAttempt::at(repeated.clone(), Outcome::Success, 4),
                    CapabilityAttempt::at(failed.clone(), Outcome::Failure, 99),
                ],
            ),
            execution(
                "run-a",
                [
                    CapabilityAttempt::at(repeated.clone(), Outcome::Success, 7),
                    CapabilityAttempt::at(repeated.clone(), Outcome::Failure, 8),
                    CapabilityAttempt::at(once.clone(), Outcome::Success, 1),
                ],
            ),
            execution(
                "run-c",
                [CapabilityAttempt::at(failed.clone(), Outcome::Failure, 2)],
            ),
        ]);
        let reverse = LearningInput::select([
            execution(
                "run-c",
                [CapabilityAttempt::at(failed.clone(), Outcome::Failure, 2)],
            ),
            execution(
                "run-a",
                [
                    CapabilityAttempt::at(once.clone(), Outcome::Success, 1),
                    CapabilityAttempt::at(repeated.clone(), Outcome::Failure, 8),
                    CapabilityAttempt::at(repeated.clone(), Outcome::Success, 7),
                ],
            ),
            execution(
                "run-b",
                [
                    CapabilityAttempt::at(failed.clone(), Outcome::Failure, 99),
                    CapabilityAttempt::at(repeated.clone(), Outcome::Success, 4),
                    CapabilityAttempt::at(repeated.clone(), Outcome::Success, 10),
                ],
            ),
        ]);

        let profile = forward.aggregate();
        assert_eq!(
            profile.canonical_text(),
            reverse.aggregate().canonical_text()
        );
        assert_eq!(profile.total_eligible_runs(), 3);
        assert_eq!(
            profile.canonical_text(),
            "\
total_eligible_runs 3
filesystem.read file repo src/a.rs 2 3 4 10
filesystem.read file repo src/b.rs 1 1 1 1
"
        );
        assert_eq!(
            profile.capabilities().cloned().collect::<Vec<_>>(),
            vec![repeated.clone(), once.clone()]
        );

        let repeated_stats = profile.statistics(&repeated).expect("repeated");
        assert_eq!(repeated_stats.runs_observed(), 2);
        assert_eq!(repeated_stats.observation_count(), 3);
        assert_eq!(repeated_stats.first_seen(), 4);
        assert_eq!(repeated_stats.last_seen(), 10);

        let once_stats = profile.statistics(&once).expect("once");
        assert_eq!(once_stats.runs_observed(), 1);
        assert_eq!(once_stats.observation_count(), 1);
        assert_eq!(once_stats.first_seen(), 1);
        assert_eq!(once_stats.last_seen(), 1);
        assert!(profile.statistics(&failed).is_none());
        assert!(forward
            .failed_evidence()
            .any(|item| item.capability() == &repeated && item.execution().as_str() == "run-a"));

        assert_eq!(forward.baseline_profile().frequency_of(&repeated), Some(1));
        let rendered = format!("{profile:?}{}", profile.canonical_text());
        for decision in Decision::ALL {
            assert!(
                !rendered.contains(decision.as_str()),
                "{}",
                decision.as_str()
            );
        }
    }

    #[test]
    fn permuting_the_input_keeps_failures_out_of_the_baseline() {
        let mut runner = deterministic_runner();
        let strategy = (
            proptest::collection::vec(arb_execution(), 0..=5),
            proptest::collection::vec(any::<u64>(), 8),
            proptest::collection::vec(any::<u64>(), 8),
        );
        runner
            .run(&strategy, |(executions, execution_order, attempt_order)| {
                let selected = LearningInput::select(executions.clone());
                let permuted = permute(&executions, &execution_order, &attempt_order);
                let reordered = LearningInput::select(permuted);
                prop_assert_eq!(&selected, &reordered);

                let mut successes = BTreeSet::new();
                let mut failure_only = BTreeSet::new();
                let mut failure_pairs = BTreeSet::new();
                for execution in &executions {
                    for attempt in execution.attempts() {
                        let key = CapabilityKey::new(attempt.capability().clone());
                        if attempt.was_exercised() {
                            successes.insert(key);
                        } else {
                            failure_pairs.insert((execution.id().clone(), key.clone()));
                            failure_only.insert(key);
                        }
                    }
                }
                failure_only.retain(|key| !successes.contains(key));

                let baseline = selected.baseline();
                let expected = NormalizedCapabilitySet::normalize(
                    successes.iter().map(|key| key.capability().clone()),
                );
                prop_assert_eq!(&baseline, &expected);
                for key in &failure_only {
                    prop_assert!(baseline
                        .iter()
                        .all(|capability| capability != key.capability()));
                }
                let evidence: Vec<_> = selected.failed_evidence().collect();
                prop_assert_eq!(evidence.len(), failure_pairs.len());
                for (execution, key) in &failure_pairs {
                    let found = evidence.iter().any(|item| {
                        item.execution() == execution && item.capability() == key.capability()
                    });
                    prop_assert!(found);
                }

                prop_assert_eq!(
                    selected.aggregate().canonical_text(),
                    reordered.aggregate().canonical_text()
                );
                for key in &failure_only {
                    prop_assert!(selected.aggregate().statistics(key.capability()).is_none());
                }

                let profile = selected.baseline_profile();
                not_a_policy_decision(&profile);
                prop_assert_eq!(
                    profile.capabilities().collect::<Vec<_>>(),
                    baseline.iter().cloned().collect::<Vec<_>>()
                );
                for capability in baseline.iter() {
                    prop_assert_eq!(profile.frequency_of(capability), Some(COLLAPSED_PRESENCE));
                }
                let rendered = format!("{profile:?}{selected:?}");
                prop_assert!(!rendered.contains(Decision::Allowed.as_str()));
                Ok(())
            })
            .expect("learning input");
    }
}
