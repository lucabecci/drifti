// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux verify: observe, then evaluate compiled policy.

use std::fs;

use drifti_core::adapters::exercised_capabilities_from_events;
use drifti_core::contract::{parse_contract, AcceptedContract};
use drifti_core::policy::{CompiledPolicy, Coverage};
use drifti_store::{CoverageStatus, ReadRepository, Store};

use super::evaluate::{apply_coverage_guard, evaluate_exercised};
use super::exit_code::{process_exit_for_verify, VerifyRun};
use crate::app::events::core_event_from_observer;
use crate::app::observe::linux::{run_observe_execution, ObserveExecution};
use crate::app::workspace::{contract_path, invalid_contract, store_error, workspace_roots};
use crate::app::{AppError, CommandContext, VerifyExit};

pub fn verify_on_linux(ctx: &CommandContext, command: &[String]) -> Result<VerifyExit, AppError> {
    let policy = load_policy(ctx)?;
    let ObserveExecution { run, execution_id } = run_observe_execution(ctx, command)?;
    let store = Store::open(&ctx.cwd).map_err(store_error)?;
    let history = store
        .execution_history(&execution_id)
        .map_err(store_error)?;
    let roots = workspace_roots(&ctx.cwd)?;
    let capabilities = exercised_capabilities_from_events(
        history
            .events()
            .iter()
            .cloned()
            .filter_map(core_event_from_observer),
        &roots,
    );
    let coverage = map_policy_coverage(history.execution().coverage());
    let summary = apply_coverage_guard(
        evaluate_exercised(&policy, capabilities, coverage),
        coverage,
    );
    Ok(process_exit_for_verify(VerifyRun {
        denied: summary.denied,
        indeterminate: summary.indeterminate,
        child_exit: run.child_exit,
        observation_complete: run.coverage_complete,
    }))
}

fn load_policy(ctx: &CommandContext) -> Result<CompiledPolicy, AppError> {
    let path = contract_path(&ctx.cwd);
    if !path.is_file() {
        return Err(AppError::User {
            message: "drifti.yaml is required for verify".into(),
        });
    }
    let yaml = fs::read_to_string(&path).map_err(|error| AppError::Internal {
        message: format!("read drifti.yaml: {error}"),
    })?;
    let document = parse_contract(&yaml).map_err(|error| {
        invalid_contract(format!(
            "drifti.yaml is not a valid capability contract: {error}"
        ))
    })?;
    let contract = AcceptedContract::loaded(document);
    contract.compile().map_err(|error| {
        invalid_contract(format!("drifti.yaml does not compile into policy: {error}"))
    })
}

fn map_policy_coverage(coverage: Option<CoverageStatus>) -> Coverage {
    match coverage {
        Some(CoverageStatus::Complete) => Coverage::Complete,
        Some(CoverageStatus::Unsupported) => Coverage::Unsupported,
        Some(CoverageStatus::Incomplete) | None => Coverage::Incomplete,
    }
}
