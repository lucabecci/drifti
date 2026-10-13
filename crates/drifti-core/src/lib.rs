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
//! [`contract::parse_contract`] reads one document and rejects every other
//! version. [`contract::serialize_contract`] writes the document as stable
//! YAML and does not accept it. A generated document is a
//! [`contract::ContractProposal`] until [`contract::ContractProposal::accept`]
//! or [`contract::ContractWriteRequest::accept_written`]. An already accepted
//! document enters through [`contract::AcceptedContract::loaded`]. Only an
//! [`contract::AcceptedContract`] compiles into policy rules. None of these
//! paths renders a terminal.
//! [`adapters`] project run, profile, and contract states into comparable
//! capabilities and call [`diff::diff`]. [`observation`] names the exercised
//! event vocabulary the run adapter maps into capabilities.
//! [`profile::CapabilityProfile`] carries frequency metadata beside identity.
//! [`learning`] selects one ordered learning input from eligible executions.
//! Input order does not change that input. Only successfully exercised
//! capabilities enter the baseline, after duplicate identities collapse.
//! A failed attempt stays inspectable evidence and is not learned authority.
//! The baseline is capability identity with a presence marker.
//! [`learning::LearningInput::aggregate`] counts runs and successful
//! observations beside that identity.
//! [`presentation`] assigns STABLE, COMMON, RARE, and NEW labels from those
//! counts. No learning field is
//! [`policy::Decision::Allowed`]. Learning does not query a store
//! and does not accept a contract.
//! [`diff::diff`] normalizes a reference set and a current set, then groups
//! each side by capability identity. The same canonical set yields an empty
//! [`drift::DriftResult`]. A capability present only in the current set is
//! [`drift::DriftKind::Added`]. One present only in the reference set is
//! [`drift::DriftKind::Removed`]. Action is part of that identity, so a
//! different action is removal plus addition. The same action classifies
//! typed containment as [`drift::DriftKind::Expanded`] or
//! [`drift::DriftKind::Reduced`]. Resource text is not compared by prefix.
//! A [`drift::DriftFinding`] may carry severity metadata later. This
//! comparison leaves severity unset and does not infer intent.
//! [`severity::classify`] attaches deterministic severity in a separate step;
//! [`diff::diff`] still leaves severity unset on structural findings.
//! [`foundation`] is the serde boundary the domain types use.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod capability;
pub mod contract;
pub mod diff;
pub mod drift;
pub mod foundation;
pub mod generalization;
pub mod learning;
pub mod observation;
pub mod policy;
pub mod presentation;
pub mod profile;
pub mod resource;
pub mod severity;
