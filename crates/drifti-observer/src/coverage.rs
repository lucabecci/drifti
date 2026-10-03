// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an observer can see, and the coverage it declares for one execution.
//!
//! These types are not policy decisions. `COMPLETE` is stored only when the
//! caller declares it and does not also mark a domain unsupported. Absence
//! of events is not represented here; callers must not treat that absence as
//! `UNSUPPORTED` or as `COMPLETE`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// Quality of observation for one execution or domain.
///
/// There is no [`Default`] implementation. A missing value must stay missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationCoverage {
    /// The backend declared that it covered the advertised domains.
    Complete,
    /// The backend declared that coverage is partial.
    Incomplete,
    /// The backend declared that it cannot observe a domain.
    Unsupported,
}

impl ObservationCoverage {
    /// Every coverage status from SPEC-004.
    pub const ALL: [Self; 3] = [Self::Complete, Self::Incomplete, Self::Unsupported];

    /// Stable coverage name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Incomplete => "INCOMPLETE",
            Self::Unsupported => "UNSUPPORTED",
        }
    }

    /// Whether this status is the explicit `COMPLETE` declaration.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Observation family an observer may advertise.
///
/// These names follow the SPEC-001 capability families. Advertising a domain
/// does not authorize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDomain {
    /// Filesystem operations.
    Filesystem,
    /// Process execution.
    Process,
    /// Network endpoints.
    Network,
}

impl CapabilityDomain {
    /// Every domain this crate can name.
    pub const ALL: [Self; 3] = [Self::Filesystem, Self::Process, Self::Network];

    /// Stable domain name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Process => "process",
            Self::Network => "network",
        }
    }
}

/// Domains a backend says it is able to observe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverCapabilities {
    domains: BTreeSet<CapabilityDomain>,
}

impl ObserverCapabilities {
    /// Builds the advertised set. Duplicates collapse. An empty set is honest:
    /// the observer advertises nothing, which is not `COMPLETE`.
    #[must_use]
    pub fn new(domains: impl IntoIterator<Item = CapabilityDomain>) -> Self {
        Self {
            domains: domains.into_iter().collect(),
        }
    }

    /// Advertised domains, in deterministic order.
    #[must_use]
    pub fn domains(&self) -> &BTreeSet<CapabilityDomain> {
        &self.domains
    }

    /// Whether `domain` was advertised.
    #[must_use]
    pub fn observes(&self, domain: CapabilityDomain) -> bool {
        self.domains.contains(&domain)
    }
}

/// Coverage declared for one execution.
///
/// `status` is the caller's declaration. Unsupported domains stay in their
/// own set so "cannot observe" is distinct from "no events were emitted".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionCoverage {
    status: ObservationCoverage,
    unsupported_domains: BTreeSet<CapabilityDomain>,
}

impl ExecutionCoverage {
    /// Records an explicit declaration.
    ///
    /// `COMPLETE` together with any unsupported domain is rejected. The
    /// constructor does not rewrite that pair into another status.
    pub fn declared(
        status: ObservationCoverage,
        unsupported_domains: impl IntoIterator<Item = CapabilityDomain>,
    ) -> Result<Self, CoverageError> {
        let unsupported_domains: BTreeSet<CapabilityDomain> =
            unsupported_domains.into_iter().collect();
        if status.is_complete() && !unsupported_domains.is_empty() {
            return Err(CoverageError::CompleteWhileUnsupported);
        }
        Ok(Self {
            status,
            unsupported_domains,
        })
    }

    /// Declared status. This is not inferred from events.
    ///
    /// A stored `COMPLETE` beside an unsupported domain is not reported as
    /// `COMPLETE`. [`Self::is_complete`] rejects that pair, and copying this
    /// status into policy coverage must not turn it into a successful result.
    #[must_use]
    pub fn status(&self) -> ObservationCoverage {
        if self.status.is_complete() && !self.unsupported_domains.is_empty() {
            ObservationCoverage::Incomplete
        } else {
            self.status
        }
    }

    /// Domains the backend marked unsupported for this execution.
    #[must_use]
    pub fn unsupported_domains(&self) -> &BTreeSet<CapabilityDomain> {
        &self.unsupported_domains
    }

    /// `true` only for an explicit `COMPLETE` declaration with no unsupported domain.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.status.is_complete() && self.unsupported_domains.is_empty()
    }
}

/// Rejected coverage declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageError {
    /// `COMPLETE` was paired with at least one unsupported domain.
    CompleteWhileUnsupported,
}

impl Display for CoverageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompleteWhileUnsupported => {
                formatter.write_str("COMPLETE coverage cannot include an unsupported domain")
            }
        }
    }
}

impl Error for CoverageError {}

impl<'de> Deserialize<'de> for ExecutionCoverage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawExecutionCoverage {
            status: ObservationCoverage,
            unsupported_domains: BTreeSet<CapabilityDomain>,
        }

        let raw = RawExecutionCoverage::deserialize(deserializer)?;
        Self::declared(raw.status, raw.unsupported_domains).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{CapabilityDomain, ExecutionCoverage, ObservationCoverage};

    #[test]
    fn status_does_not_report_complete_when_is_complete_rejects_it() {
        let illegal = ExecutionCoverage {
            status: ObservationCoverage::Complete,
            unsupported_domains: BTreeSet::from([CapabilityDomain::Network]),
        };
        assert!(!illegal.is_complete());
        assert_eq!(illegal.status(), ObservationCoverage::Incomplete);
        assert_ne!(illegal.status(), ObservationCoverage::Complete);
    }
}
