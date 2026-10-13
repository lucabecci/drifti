// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structured command results shared by text and JSON renderers.

use serde::{Deserialize, Serialize};

use drifti_core::capability::Capability;

use crate::exit::CommandExitClass;

pub const STATUS_OK: &str = "ok";
pub const STATUS_VIOLATION: &str = "violation";
pub const STATUS_INCOMPLETE: &str = "incomplete";
pub const STATUS_INVALID_CONTRACT: &str = "invalid_contract";

/// Semantic outcome for renderers and JSON consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Ok,
    Violation,
    Incomplete,
    InvalidContract,
    NotReady,
}

impl ResultStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => STATUS_OK,
            Self::Violation => STATUS_VIOLATION,
            Self::Incomplete => STATUS_INCOMPLETE,
            Self::InvalidContract => STATUS_INVALID_CONTRACT,
            Self::NotReady => "not_ready",
        }
    }

    #[must_use]
    pub const fn from_exit_class(class: CommandExitClass) -> Self {
        match class {
            CommandExitClass::Success => Self::Ok,
            CommandExitClass::Violation => Self::Violation,
            CommandExitClass::Incomplete => Self::Incomplete,
            CommandExitClass::InvalidContract => Self::InvalidContract,
        }
    }
}

/// One rendered command outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum CommandResult {
    Init(InitResult),
    Doctor(DoctorResult),
    Observe(ObserveResult),
    Verify(VerifyResult),
    Learn(LearnResult),
    Generate(GenerateResult),
    Diff(DiffResult),
}

fn status_to_exit(status: ResultStatus) -> CommandExitClass {
    if status == ResultStatus::InvalidContract {
        CommandExitClass::InvalidContract
    } else {
        CommandExitClass::Success
    }
}

impl CommandResult {
    #[must_use]
    pub fn exit_class(&self) -> CommandExitClass {
        match self {
            Self::Init(result) => status_to_exit(result.status),
            Self::Learn(result) => status_to_exit(result.status),
            Self::Diff(result) => status_to_exit(result.status),
            Self::Doctor(_) => CommandExitClass::Success,
            Self::Generate(result) => match result.status {
                ResultStatus::Ok => CommandExitClass::Success,
                ResultStatus::InvalidContract => CommandExitClass::InvalidContract,
                _ => CommandExitClass::Success,
            },
            Self::Observe(result) => match result.status {
                ResultStatus::Ok => CommandExitClass::Success,
                ResultStatus::Incomplete => CommandExitClass::Incomplete,
                _ => CommandExitClass::Success,
            },
            Self::Verify(result) => match result.status {
                ResultStatus::Ok => CommandExitClass::Success,
                ResultStatus::Violation => CommandExitClass::Violation,
                ResultStatus::Incomplete => CommandExitClass::Incomplete,
                ResultStatus::InvalidContract => CommandExitClass::InvalidContract,
                ResultStatus::NotReady => CommandExitClass::Success,
            },
        }
    }

    #[must_use]
    pub fn process_exit(&self) -> Option<u8> {
        match self {
            Self::Observe(result) => result.child_exit,
            Self::Verify(result) => result.child_exit,
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitResult {
    pub status: ResultStatus,
    pub state_dir: String,
    pub contract_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorFindingView {
    pub check: String,
    pub status: String,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorResult {
    pub status: ResultStatus,
    pub ready: bool,
    pub store_open: bool,
    pub contract_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_valid: Option<bool>,
    pub findings: Vec<DoctorFindingView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveResult {
    pub status: ResultStatus,
    pub execution_id: String,
    pub coverage: String,
    pub child_exit: Option<u8>,
    pub events_persisted: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported_domains: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyEvaluationView {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub status: ResultStatus,
    pub coverage: String,
    pub child_exit: Option<u8>,
    pub evaluations: Vec<VerifyEvaluationView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCapabilityView {
    pub capability: Capability,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnResult {
    pub status: ResultStatus,
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
