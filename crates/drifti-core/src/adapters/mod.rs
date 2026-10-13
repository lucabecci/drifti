// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drift adapters for run, profile, and contract comparison modes.
//!
//! Each adapter projects one capability state into comparable capabilities and
//! calls [`crate::diff::diff`]. Containment and normalization stay in
//! [`crate::diff`]; adapters do not compare resource text by prefix.

mod contract;
mod profile;
mod run;

pub use contract::{diff_contracts, ContractDrift};
pub use profile::diff_profiles;
pub use run::{diff_runs, exercised_capabilities_from_events};
