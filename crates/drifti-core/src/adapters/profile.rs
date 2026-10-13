// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Profile-to-profile drift.

use crate::diff::DriftDiff;
use crate::profile::CapabilityProfile;

/// Compares two capability profiles through the shared diff.
#[must_use]
pub fn diff_profiles(reference: &CapabilityProfile, current: &CapabilityProfile) -> DriftDiff {
    reference.diff_with(current)
}
