// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Map store execution histories into core learning input.

use drifti_core::learning::{
    CapabilityAttempt, EligibleExecution, EligibleExecutionId, LearningInput,
};
use drifti_core::observation::{
    capability_from_observation, ObservedResource as CoreResource, Operation as CoreOperation,
    Outcome as CoreOutcome,
};
use drifti_core::resource::FilesystemRoots;
use drifti_observer::{
    ObservedResource as ObserverResource, Operation as ObserverOperation,
    Outcome as ObserverOutcome,
};
use drifti_store::{ExecutionRecord, Store};

use super::AppError;

pub fn learning_input_from_store(
    store: &Store,
    roots: &FilesystemRoots,
) -> Result<LearningInput, AppError> {
    let executions = store.list_executions().map_err(store_internal)?;
    let mut eligible = Vec::new();
    for record in executions {
        if record.lifecycle() != drifti_store::Lifecycle::Finished {
            continue;
        }
        let execution_id = record.id().clone();
        let Some(attempts) = attempts_for_execution(store, roots, &record)? else {
            continue;
        };
        if attempts.is_empty() {
            continue;
        }
        let id = EligibleExecutionId::new(execution_id.as_str()).map_err(|error| {
            AppError::Internal {
                message: format!("invalid execution id for learning: {error}"),
            }
        })?;
        eligible.push(EligibleExecution::new(id, attempts));
    }
    if eligible.is_empty() {
        return Err(AppError::User {
            message: "no finished executions with mappable observations; run drifti observe first"
                .to_owned(),
        });
    }
    Ok(LearningInput::select(eligible))
}

fn attempts_for_execution(
    store: &Store,
    roots: &FilesystemRoots,
    record: &ExecutionRecord,
) -> Result<Option<Vec<CapabilityAttempt>>, AppError> {
    let events = store
        .events_for_execution(record.id())
        .map_err(store_internal)?;
    if events.is_empty() {
        return Ok(None);
    }
    let mut attempts = Vec::new();
    for (index, event) in events.into_iter().enumerate() {
        let Some((operation, resource)) = map_event(event.operation(), event.resource()) else {
            continue;
        };
        let capability = match capability_from_observation(operation, &resource, roots) {
            Ok(capability) => capability,
            Err(_) => continue,
        };
        let outcome = map_outcome(event.outcome(), event.was_exercised());
        attempts.push(CapabilityAttempt::at(
            capability,
            outcome,
            u64::try_from(index).unwrap_or(u64::MAX),
        ));
    }
    Ok(Some(attempts))
}

fn map_event(
    operation: ObserverOperation,
    resource: &ObserverResource,
) -> Option<(CoreOperation, CoreResource)> {
    let operation = match operation {
        ObserverOperation::FilesystemRead => CoreOperation::FilesystemRead,
        ObserverOperation::FilesystemWrite => CoreOperation::FilesystemWrite,
        ObserverOperation::FilesystemMetadata => CoreOperation::FilesystemMetadata,
        ObserverOperation::ProcessExecute => CoreOperation::ProcessExecute,
        ObserverOperation::NetworkConnect => CoreOperation::NetworkConnect,
        ObserverOperation::NetworkListen => CoreOperation::NetworkListen,
    };
    let resource = match resource {
        ObserverResource::File { path } => CoreResource::file(path.clone()).ok()?,
        ObserverResource::Executable { identity } => {
            CoreResource::executable(identity.clone()).ok()?
        }
        ObserverResource::Network { host, port, .. } => {
            CoreResource::network(host.clone(), *port).ok()?
        }
    };
    Some((operation, resource))
}

fn map_outcome(_outcome: &ObserverOutcome, exercised: bool) -> CoreOutcome {
    if exercised {
        CoreOutcome::Success
    } else {
        CoreOutcome::Failure
    }
}

fn store_internal(error: drifti_store::StoreError) -> AppError {
    AppError::Internal {
        message: format!("store error: {error}"),
    }
}
