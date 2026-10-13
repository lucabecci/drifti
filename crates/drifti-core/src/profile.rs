// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capability Profile values learned from observation.
//!
//! Frequency metadata sits beside capability identity. It does not participate
//! in profile equality and does not change structural drift comparison.

use std::collections::BTreeMap;

use crate::capability::Capability;
use crate::diff::{diff, CapabilityKey, DriftDiff};

/// One capability in a profile with non-authoritative frequency metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEntry {
    capability: Capability,
    frequency: u64,
}

impl ProfileEntry {
    /// Stores one capability and how often it was seen while learning.
    #[must_use]
    pub const fn new(capability: Capability, frequency: u64) -> Self {
        Self {
            capability,
            frequency,
        }
    }

    /// Capability identity.
    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    /// Observed frequency. This is not part of capability identity.
    #[must_use]
    pub const fn frequency(&self) -> u64 {
        self.frequency
    }
}

/// Learned capability set with frequency metadata per identity.
#[derive(Debug, Clone, Eq)]
pub struct CapabilityProfile {
    entries: BTreeMap<CapabilityKey, u64>,
}

impl CapabilityProfile {
    /// Builds a profile from entries. Duplicate identities keep the last frequency.
    #[must_use]
    pub fn from_entries(entries: impl IntoIterator<Item = ProfileEntry>) -> Self {
        let mut map = BTreeMap::new();
        for entry in entries {
            map.insert(CapabilityKey::new(entry.capability), entry.frequency);
        }
        Self { entries: map }
    }

    /// Capabilities in identity order. Frequency is not exposed here.
    pub fn capabilities(&self) -> impl Iterator<Item = Capability> + '_ {
        self.entries.keys().map(|key| key.capability().clone())
    }

    /// Frequency for one capability identity, when present.
    #[must_use]
    pub fn frequency_of(&self, capability: &Capability) -> Option<u64> {
        self.entries
            .get(&CapabilityKey::new(capability.clone()))
            .copied()
    }

    /// Compares structural authority with another profile through the shared diff.
    #[must_use]
    pub fn diff_with(&self, current: &Self) -> DriftDiff {
        diff(self.capabilities(), current.capabilities())
    }
}

impl PartialEq for CapabilityProfile {
    fn eq(&self, other: &Self) -> bool {
        self.entries.keys().eq(other.entries.keys())
    }
}
