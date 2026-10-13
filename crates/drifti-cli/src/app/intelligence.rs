// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Learn, generate, and diff command orchestration.

use std::fs;
use std::io;

use drifti_core::contract::{
    parse_contract, resolve_comparable_capabilities, AcceptedContract, ContractProposal,
};
use drifti_core::diff::diff as diff_capabilities;
use drifti_core::policy::RuleEffect;
use drifti_core::presentation::{classify_presentation, PresentationThresholds};
use drifti_store::Store;

use super::generate::proposal_document;
use super::store_learning::learning_input_from_store;
use super::workspace::{contract_path, invalid_contract, store_error, workspace_roots};
use super::{AppError, CommandContext};
use crate::render::render_intelligence;
use crate::result::{
    DiffResult, DriftFindingView, GenerateResult, IntelligenceResult, LearnResult,
    ProfileCapabilityView, ResultStatus,
};

const LEARNED_PROFILE_ARTIFACT: &str = "learned_profile";

pub fn learn(ctx: &CommandContext) -> Result<(), AppError> {
    let store = Store::open(&ctx.cwd).map_err(store_error)?;
    let roots = workspace_roots(&ctx.cwd)?;
    let input = learning_input_from_store(&store, &roots)?;
    let aggregated = input.aggregate();
    let profile = input.baseline_profile();
    let total_runs = aggregated.total_eligible_runs();
    let entries: Vec<ProfileCapabilityView> = profile
        .capabilities()
        .map(|capability| {
            let stats = aggregated
                .statistics(&capability)
                .expect("capability in baseline has statistics");
            let label = classify_presentation(stats, total_runs, PresentationThresholds::default())
                .as_str()
                .to_owned();
            ProfileCapabilityView { capability, label }
        })
        .collect();
    let result = IntelligenceResult::Learn(LearnResult {
        status: ResultStatus::Ok,
        artifact: LEARNED_PROFILE_ARTIFACT.to_owned(),
        executions_considered: usize::try_from(total_runs).unwrap_or(usize::MAX),
        capability_count: entries.len(),
        profile: entries,
    });
    render_intelligence(&result, &ctx.output, &mut io::stdout()).map_err(|error| {
        AppError::Internal {
            message: format!("stdout: {error}"),
        }
    })?;
    Ok(())
}

pub fn generate(ctx: &CommandContext, write: bool) -> Result<(), AppError> {
    let store = Store::open(&ctx.cwd).map_err(store_error)?;
    let roots = workspace_roots(&ctx.cwd)?;
    let input = learning_input_from_store(&store, &roots)?;
    let profile = input.baseline_profile();
    let document = proposal_document(&profile)?;
    let proposal = ContractProposal::generated(document);
    let yaml_preview = proposal.yaml();
    let mut wrote_contract = false;
    if write {
        let request = proposal.write_request();
        fs::write(contract_path(&ctx.cwd), request.yaml()).map_err(|error| AppError::Internal {
            message: format!("write drifti.yaml: {error}"),
        })?;
        wrote_contract = true;
    }
    let result = IntelligenceResult::Generate(GenerateResult {
        status: ResultStatus::Ok,
        proposal: true,
        yaml_preview: if write { None } else { Some(yaml_preview) },
        wrote_contract,
    });
    render_intelligence(&result, &ctx.output, &mut io::stdout()).map_err(|error| {
        AppError::Internal {
            message: format!("stdout: {error}"),
        }
    })?;
    Ok(())
}

pub fn diff(ctx: &CommandContext) -> Result<(), AppError> {
    let path = contract_path(&ctx.cwd);
    if !path.is_file() {
        return Err(AppError::User {
            message: "drifti.yaml is required for diff; run drifti generate --write after learning"
                .to_owned(),
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
    let (reference, _) = resolve_comparable_capabilities(contract.document(), RuleEffect::Allow);
    let store = Store::open(&ctx.cwd).map_err(store_error)?;
    let roots = workspace_roots(&ctx.cwd)?;
    let input = learning_input_from_store(&store, &roots)?;
    let current = input.baseline_profile();
    let drift = diff_capabilities(reference, current.capabilities());
    let findings = drift
        .findings()
        .map(|result| {
            result
                .findings()
                .iter()
                .map(|finding| DriftFindingView {
                    kind: finding.kind().as_str().to_owned(),
                    reference: finding.reference().cloned(),
                    current: finding.current().cloned(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let result = IntelligenceResult::Diff(DiffResult {
        status: ResultStatus::Ok,
        contract_present: true,
        findings,
    });
    render_intelligence(&result, &ctx.output, &mut io::stdout()).map_err(|error| {
        AppError::Internal {
            message: format!("stdout: {error}"),
        }
    })?;
    Ok(())
}
