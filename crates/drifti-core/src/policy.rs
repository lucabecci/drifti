// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy decisions, allow and deny rules, and evaluation results.
//!
//! A rule names one [`Capability`](crate::capability::Capability). It matches
//! another capability when the actions are equal and the rule resource contains
//! the other resource. Deny precedence and coverage are later tasks.
//! This module does not read YAML, traces, or a terminal.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::capability::Capability;

/// Outcome of comparing one capability with a compiled policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// `ALLOWED`
    Allowed,
    /// `DENIED`
    Denied,
    /// `UNKNOWN`
    Unknown,
    /// `INDETERMINATE`
    Indeterminate,
}

impl Decision {
    /// Every policy decision.
    pub const ALL: [Self; 4] = [
        Self::Allowed,
        Self::Denied,
        Self::Unknown,
        Self::Indeterminate,
    ];

    /// Stable decision name from SPEC-002.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "ALLOWED",
            Self::Denied => "DENIED",
            Self::Unknown => "UNKNOWN",
            Self::Indeterminate => "INDETERMINATE",
        }
    }
}

/// Whether a rule grants or refuses a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleEffect {
    /// The rule grants the capability it names.
    Allow,
    /// The rule refuses the capability it names.
    Deny,
}

impl RuleEffect {
    /// Stable effect name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Identifier of one policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(String);

impl RuleId {
    /// Builds a rule identifier. An empty value or an embedded NUL is rejected.
    pub fn new(text: impl Into<String>) -> Result<Self, PolicyError> {
        let text = text.into();
        if text.is_empty() {
            return Err(PolicyError::EmptyRuleId);
        }
        if text.contains('\0') {
            return Err(PolicyError::EmbeddedNul);
        }
        Ok(Self(text))
    }

    /// Identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One allow or deny rule over a typed capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    id: RuleId,
    effect: RuleEffect,
    capability: Capability,
}

impl Rule {
    /// Allow rule for one capability.
    #[must_use]
    pub fn allow(id: RuleId, capability: Capability) -> Self {
        Self {
            id,
            effect: RuleEffect::Allow,
            capability,
        }
    }

    /// Deny rule for one capability.
    #[must_use]
    pub fn deny(id: RuleId, capability: Capability) -> Self {
        Self {
            id,
            effect: RuleEffect::Deny,
            capability,
        }
    }

    /// Rule identifier.
    #[must_use]
    pub fn id(&self) -> &RuleId {
        &self.id
    }

    /// Allow or deny.
    #[must_use]
    pub fn effect(&self) -> RuleEffect {
        self.effect
    }

    /// Capability this rule names.
    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    /// Whether this rule covers `capability`.
    ///
    /// The actions must be equal. The rule resource must contain the capability
    /// resource: an exact rule covers only itself, and a recursive prefix covers
    /// that path and its descendants. Allow and deny use the same match.
    #[must_use]
    pub fn matches(&self, capability: &Capability) -> bool {
        self.capability.action() == capability.action()
            && self.capability.resource().contains(capability.resource())
    }
}

/// Rules compiled into the form the policy engine consumes.
///
/// Rule order is preserved. This type does not parse YAML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    rules: Vec<Rule>,
}

impl CompiledPolicy {
    /// Builds a policy from already typed rules.
    #[must_use]
    pub fn new(rules: impl Into<Vec<Rule>>) -> Self {
        Self {
            rules: rules.into(),
        }
    }

    /// Rules in the order they were supplied.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Rules that cover `capability`, in policy order.
    ///
    /// Deny precedence and coverage are not applied here.
    #[must_use]
    pub fn matching_rules(&self, capability: &Capability) -> Vec<MatchedRule> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(capability))
            .map(MatchedRule::from_rule)
            .collect()
    }
}

/// A rule cited as evidence for a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    id: RuleId,
    effect: RuleEffect,
}

impl MatchedRule {
    /// Evidence copied from a rule, without its capability body.
    #[must_use]
    pub fn from_rule(rule: &Rule) -> Self {
        Self {
            id: rule.id.clone(),
            effect: rule.effect,
        }
    }

    /// Cited rule identifier.
    #[must_use]
    pub fn id(&self) -> &RuleId {
        &self.id
    }

    /// Effect of the cited rule.
    #[must_use]
    pub fn effect(&self) -> RuleEffect {
        self.effect
    }
}

/// Why an evaluation did not produce allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvaluationReason {
    /// No rule covers the capability.
    NoMatchingRule,
    /// The caller supplied incomplete observation coverage.
    InsufficientCoverage,
}

impl EvaluationReason {
    /// Stable reason name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMatchingRule => "no_matching_rule",
            Self::InsufficientCoverage => "insufficient_coverage",
        }
    }
}

/// Decision plus the matched-rule evidence behind it.
///
/// `ALLOWED` cites only allow rules. `DENIED` cites only deny rules.
/// `UNKNOWN` and `INDETERMINATE` cite no rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    decision: Decision,
    matched_rules: Vec<MatchedRule>,
    reason: Option<EvaluationReason>,
}

impl Evaluation {
    /// `ALLOWED` backed by one or more allow rules.
    pub fn allowed(matched_rules: Vec<MatchedRule>) -> Result<Self, PolicyError> {
        checked(Decision::Allowed, RuleEffect::Allow, matched_rules, None)
    }

    /// `DENIED` backed by one or more deny rules.
    pub fn denied(matched_rules: Vec<MatchedRule>) -> Result<Self, PolicyError> {
        checked(Decision::Denied, RuleEffect::Deny, matched_rules, None)
    }

    /// `UNKNOWN` because no rule covers the capability.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            decision: Decision::Unknown,
            matched_rules: Vec::new(),
            reason: Some(EvaluationReason::NoMatchingRule),
        }
    }

    /// `INDETERMINATE` because coverage was incomplete.
    ///
    /// This constructor does not inspect observation data. The caller supplies
    /// the conclusion that coverage was insufficient.
    #[must_use]
    pub fn indeterminate() -> Self {
        Self {
            decision: Decision::Indeterminate,
            matched_rules: Vec::new(),
            reason: Some(EvaluationReason::InsufficientCoverage),
        }
    }

    /// Decision half of the result.
    #[must_use]
    pub fn decision(&self) -> Decision {
        self.decision
    }

    /// Rules cited for `ALLOWED` or `DENIED`.
    #[must_use]
    pub fn matched_rules(&self) -> &[MatchedRule] {
        &self.matched_rules
    }

    /// Reason for `UNKNOWN` or `INDETERMINATE`.
    #[must_use]
    pub fn reason(&self) -> Option<EvaluationReason> {
        self.reason
    }
}

/// Rejected policy value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// Rule identifier text was empty.
    EmptyRuleId,
    /// Rule identifier text contained a NUL byte.
    EmbeddedNul,
    /// `ALLOWED` or `DENIED` was built without a matched rule.
    MissingMatchedRule,
    /// A matched rule effect does not agree with the decision.
    MismatchedEffect,
}

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRuleId => formatter.write_str("rule identifier text is empty"),
            Self::EmbeddedNul => formatter.write_str("rule identifier text contains a NUL byte"),
            Self::MissingMatchedRule => {
                formatter.write_str("allowed and denied results cite a matched rule")
            }
            Self::MismatchedEffect => {
                formatter.write_str("matched rule effect does not agree with the decision")
            }
        }
    }
}

impl Error for PolicyError {}

fn checked(
    decision: Decision,
    effect: RuleEffect,
    matched_rules: Vec<MatchedRule>,
    reason: Option<EvaluationReason>,
) -> Result<Evaluation, PolicyError> {
    if matched_rules.is_empty() {
        return Err(PolicyError::MissingMatchedRule);
    }
    if matched_rules.iter().any(|rule| rule.effect() != effect) {
        return Err(PolicyError::MismatchedEffect);
    }
    Ok(Evaluation {
        decision,
        matched_rules,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CompiledPolicy, Decision, Evaluation, EvaluationReason, MatchedRule, PolicyError, Rule,
        RuleEffect, RuleId,
    };
    use crate::capability::Capability;
    use crate::resource::{
        ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn read_src() -> Capability {
        let resource = FileResource::new(FilesystemAnchor::Repo, "src/**").expect("file");
        Capability::filesystem_read(resource)
    }

    fn rule_id(text: &str) -> RuleId {
        RuleId::new(text).expect("rule id")
    }

    #[test]
    fn every_decision_has_a_distinct_name() {
        let names: Vec<_> = Decision::ALL
            .iter()
            .copied()
            .map(Decision::as_str)
            .collect();
        assert_eq!(names, ["ALLOWED", "DENIED", "UNKNOWN", "INDETERMINATE"]);
        assert_ne!(Decision::Unknown, Decision::Denied);
        assert_ne!(Decision::Unknown.as_str(), Decision::Denied.as_str());
    }

    #[test]
    fn allow_and_deny_rules_keep_the_typed_capability() {
        let capability = read_src();
        let allow = Rule::allow(rule_id("read-src"), capability.clone());
        let deny = Rule::deny(rule_id("read-src-deny"), capability.clone());
        assert_eq!(allow.effect(), RuleEffect::Allow);
        assert_eq!(deny.effect(), RuleEffect::Deny);
        assert_eq!(allow.capability(), &capability);
        assert_eq!(deny.capability(), &capability);
        assert_ne!(allow, deny);
        let policy = CompiledPolicy::new(vec![allow.clone(), deny.clone()]);
        assert_eq!(policy.rules(), &[allow, deny]);
    }

    #[test]
    fn rule_identifiers_reject_empty_text_and_nul() {
        assert_eq!(RuleId::new(""), Err(PolicyError::EmptyRuleId));
        assert_eq!(RuleId::new("a\0b"), Err(PolicyError::EmbeddedNul));
    }

    #[test]
    fn evaluation_results_represent_every_decision() {
        let allow = Rule::allow(rule_id("allow-src"), read_src());
        let deny = Rule::deny(rule_id("deny-src"), read_src());
        let allowed = Evaluation::allowed(vec![MatchedRule::from_rule(&allow)]).expect("allowed");
        let denied = Evaluation::denied(vec![MatchedRule::from_rule(&deny)]).expect("denied");
        let unknown = Evaluation::unknown();
        let indeterminate = Evaluation::indeterminate();

        assert_eq!(allowed.decision(), Decision::Allowed);
        assert_eq!(allowed.matched_rules()[0].id().as_str(), "allow-src");
        assert_eq!(allowed.matched_rules()[0].effect(), RuleEffect::Allow);
        assert_eq!(allowed.reason(), None);

        assert_eq!(denied.decision(), Decision::Denied);
        assert_eq!(denied.matched_rules()[0].effect(), RuleEffect::Deny);
        assert_eq!(denied.reason(), None);

        assert_eq!(unknown.decision(), Decision::Unknown);
        assert!(unknown.matched_rules().is_empty());
        assert_eq!(unknown.reason(), Some(EvaluationReason::NoMatchingRule));

        assert_eq!(indeterminate.decision(), Decision::Indeterminate);
        assert!(indeterminate.matched_rules().is_empty());
        assert_eq!(
            indeterminate.reason(),
            Some(EvaluationReason::InsufficientCoverage)
        );
        assert_ne!(unknown, indeterminate);
        assert_ne!(unknown.decision(), denied.decision());
    }

    #[test]
    fn allowed_and_denied_results_require_matching_evidence() {
        assert_eq!(
            Evaluation::allowed(Vec::new()),
            Err(PolicyError::MissingMatchedRule)
        );
        assert_eq!(
            Evaluation::denied(Vec::new()),
            Err(PolicyError::MissingMatchedRule)
        );
        let allow = MatchedRule::from_rule(&Rule::allow(rule_id("allow-src"), read_src()));
        let deny = MatchedRule::from_rule(&Rule::deny(rule_id("deny-src"), read_src()));
        assert_eq!(
            Evaluation::allowed(vec![deny]),
            Err(PolicyError::MismatchedEffect)
        );
        assert_eq!(
            Evaluation::denied(vec![allow]),
            Err(PolicyError::MismatchedEffect)
        );
    }

    fn repo_read(file_path: &str) -> Capability {
        let resource = FileResource::new(FilesystemAnchor::Repo, file_path).expect("file");
        Capability::filesystem_read(resource)
    }

    fn repo_write(file_path: &str) -> Capability {
        let resource = FileResource::new(FilesystemAnchor::Repo, file_path).expect("file");
        Capability::filesystem_write(resource)
    }

    #[test]
    fn exact_and_recursive_rules_match_by_containment() {
        let exact = Rule::allow(rule_id("exact"), repo_read("src/lib.rs"));
        let prefix = Rule::deny(rule_id("prefix"), repo_read("src/**"));
        let child = Rule::allow(rule_id("child"), repo_read("src/domain/**"));
        let observed = repo_read("src/domain/mod.rs");

        assert!(exact.matches(&repo_read("src/lib.rs")));
        assert!(!exact.matches(&repo_read("src/main.rs")));
        assert!(prefix.matches(&observed));
        assert!(prefix.matches(&repo_read("src")));
        assert!(child.matches(&observed));
        assert!(!child.matches(&repo_read("src/**")));
        assert!(!prefix.matches(&repo_read("srcdir/lib.rs")));
        assert!(!repo_read_rule("src/**").matches(&repo_read_home("src/lib.rs")));

        let policy = CompiledPolicy::new(vec![exact, prefix.clone(), child]);
        let matched = policy.matching_rules(&observed);
        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].id().as_str(), "prefix");
        assert_eq!(matched[0].effect(), RuleEffect::Deny);
        assert_eq!(matched[1].id().as_str(), "child");
        assert_eq!(matched[1].effect(), RuleEffect::Allow);
        assert!(prefix.matches(&observed));
        assert_eq!(
            Rule::allow(rule_id("same"), repo_read("src/**")).matches(&observed),
            prefix.matches(&observed)
        );
    }

    fn repo_read_rule(file_path: &str) -> Rule {
        Rule::deny(rule_id("anchor"), repo_read(file_path))
    }

    fn repo_read_home(file_path: &str) -> Capability {
        let resource = FileResource::new(FilesystemAnchor::Home, file_path).expect("file");
        Capability::filesystem_read(resource)
    }

    #[test]
    fn action_and_resource_domain_mismatches_never_match() {
        let read_rule = Rule::allow(rule_id("read"), repo_read("src/**"));
        assert!(!read_rule.matches(&repo_write("src/lib.rs")));

        let executable =
            Capability::process_execute(ExecutableResource::new("git").expect("executable"));
        let other_executable =
            Capability::process_execute(ExecutableResource::new("git-lfs").expect("executable"));
        let execute_rule = Rule::allow(rule_id("git"), executable.clone());
        assert!(execute_rule.matches(&executable));
        assert!(!execute_rule.matches(&other_executable));
        assert!(!read_rule.matches(&executable));
        assert!(!execute_rule.matches(&repo_read("git")));

        let address = NetworkAddress::ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        let host =
            Capability::network_connect(NetworkResource::new(NetworkProtocol::Tcp, address, 443));
        let cidr = NetworkAddress::cidr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("cidr");
        let network =
            Capability::network_connect(NetworkResource::new(NetworkProtocol::Tcp, cidr, 443));
        let network_rule = Rule::deny(rule_id("net"), network.clone());
        assert!(network_rule.matches(&network));
        assert!(!network_rule.matches(&host));
        assert!(!network_rule.matches(&executable));
    }

    #[test]
    fn matching_follows_action_equality_and_resource_containment() {
        use proptest::prelude::*;
        use proptest::test_runner::{TestRng, TestRunner};

        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
        let parts = proptest::collection::vec(
            prop_oneof![Just("src"), Just("domain"), Just("lib.rs"), Just("a")],
            0..=3,
        );
        let pattern = (parts, any::<bool>(), any::<bool>());
        runner
            .run(
                &(pattern.clone(), pattern),
                |(
                    (rule_parts, rule_recursive, rule_read),
                    (subject_parts, subject_recursive, subject_read),
                )| {
                    let rule_capability = generated_read(rule_read, &rule_parts, rule_recursive);
                    let subject = generated_read(subject_read, &subject_parts, subject_recursive);
                    let allow = Rule::allow(rule_id("allow"), rule_capability.clone());
                    let deny = Rule::deny(rule_id("deny"), rule_capability.clone());
                    let expected = rule_read == subject_read
                        && rule_capability.resource().contains(subject.resource());
                    prop_assert_eq!(allow.matches(&subject), expected);
                    prop_assert_eq!(deny.matches(&subject), expected);
                    Ok(())
                },
            )
            .expect("matching");
    }

    fn generated_read(read: bool, parts: &[&str], recursive: bool) -> Capability {
        let joined = if parts.is_empty() {
            if recursive {
                "**".to_owned()
            } else {
                ".".to_owned()
            }
        } else {
            let body = parts.join("/");
            if recursive {
                format!("{body}/**")
            } else {
                body
            }
        };
        let resource = FileResource::new(FilesystemAnchor::Repo, joined).expect("file");
        if read {
            Capability::filesystem_read(resource)
        } else {
            Capability::filesystem_write(resource)
        }
    }
}
