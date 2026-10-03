// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable domain model for Drifti.
//!
//! This crate owns capability identity, policy, learning, and drift.
//! It does not observe processes, persist traces, or render a terminal.
//!
//! [`capability`] and [`resource`] are the MVP action and resource model.
//! Normalization, containment, and the capability serialization contract are
//! later tasks. [`foundation`] is the serde boundary the domain types use.

#![forbid(unsafe_code)]

pub mod capability;
pub mod contract;
pub mod diff;
pub mod drift;
pub mod foundation;
pub mod generalization;
pub mod learning;
pub mod policy;
pub mod profile;
pub mod resource;
