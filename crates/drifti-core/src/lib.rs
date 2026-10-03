// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable domain model for Drifti.
//!
//! This crate owns capability identity, policy, learning, and drift.
//! It does not observe processes, persist traces, or render a terminal.
//!
//! The public modules are the layout for that model. Concrete capability
//! types are added by later tasks. [`foundation`] is the serde boundary
//! those types use.

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
