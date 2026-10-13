// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structured results for learn, generate, and diff (shared by text and JSON).

use serde::{Deserialize, Serialize};

use drifti_core::capability::Capability;

pub const STATUS_OK: &str = "ok";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Ok,
}

impl ResultStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => STATUS_OK,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum IntelligenceResult {
    Learn(LearnResult),
    Generate(GenerateResult),
    Diff(DiffResult),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCapabilityView {
    pub capability: Capability,
    /// Presentation label (stable/common/rare/new). Not authorization.
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnResult {
    pub status: ResultStatus,
    /// Explicit marker for consumers: this is a learned profile, not a contract.
    pub artifact: String,
    pub executions_considered: usize,
    pub capability_count: usize,
    pub profile: Vec<ProfileCapabilityView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateResult {
    pub status: ResultStatus,
    pub proposal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yaml_preview: Option<String>,
    pub wrote_contract: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftFindingView {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffResult {
    pub status: ResultStatus,
    pub contract_present: bool,
    pub findings: Vec<DriftFindingView>,
}
