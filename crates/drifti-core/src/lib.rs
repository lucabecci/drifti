// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable domain model for Drifti.
//!
//! This crate owns capability identity, policy, learning, and drift.
//! It does not observe processes, persist traces, or render a terminal.
//!
//! [`capability`] and [`resource`] are the MVP action and resource model.
//! Filesystem paths, executable identity, and network addresses are normalized.
//! Capability identity is the action plus that normalized resource.
//! A trailing `**` is a recursive prefix for containment.
//! [`policy`] names `ALLOWED`, `DENIED`, `UNKNOWN`, and `INDETERMINATE`,
//! matches a rule when its resource contains the capability, and evaluates
//! with deny-over-allow precedence when coverage is `COMPLETE`. Any other
//! coverage yields `INDETERMINATE` unless an explicit deny matches. The
//! engine does not infer coverage.
//! [`contract`] is the version-1 contract document. Its version is mandatory.
//! Parsing and compilation are later tasks.
//! [`foundation`] is the serde boundary the domain types use.

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
