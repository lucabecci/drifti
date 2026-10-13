// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Map observer events into core observation vocabulary.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use drifti_core::observation::{
    ObservedEvent as CoreEvent, ObservedResource as CoreResource, Operation as CoreOperation,
    Outcome as CoreOutcome,
};
use drifti_observer::{
    ObservedEvent as ObserverEvent, ObservedResource as ObserverResource,
    Operation as ObserverOperation,
};

#[must_use]
pub fn core_event_from_observer(event: ObserverEvent) -> Option<CoreEvent> {
    let operation = map_operation(event.operation())?;
    let resource = map_resource(event.resource().clone())?;
    let outcome = if event.was_exercised() {
        CoreOutcome::Success
    } else {
        CoreOutcome::Failure
    };
    Some(CoreEvent::new(operation, resource, outcome))
}

fn map_operation(operation: ObserverOperation) -> Option<CoreOperation> {
    Some(match operation {
        ObserverOperation::FilesystemRead => CoreOperation::FilesystemRead,
        ObserverOperation::FilesystemWrite => CoreOperation::FilesystemWrite,
        ObserverOperation::FilesystemMetadata => CoreOperation::FilesystemMetadata,
        ObserverOperation::ProcessExecute => CoreOperation::ProcessExecute,
        ObserverOperation::NetworkConnect => CoreOperation::NetworkConnect,
        ObserverOperation::NetworkListen => CoreOperation::NetworkListen,
    })
}

fn map_resource(resource: ObserverResource) -> Option<CoreResource> {
    match resource {
        ObserverResource::File { path } => CoreResource::file(path).ok(),
        ObserverResource::Executable { identity } => CoreResource::executable(identity).ok(),
        ObserverResource::Network { host, port, .. } => CoreResource::network(host, port).ok(),
    }
}
