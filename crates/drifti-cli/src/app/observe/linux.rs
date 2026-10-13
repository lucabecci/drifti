// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux observe orchestration: observer, store, and lifecycle.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::thread;

use drifti_observer::{
    CapabilityDomain as ObserverDomain, CommandSpec, CursorError, EventSink,
    ExecutionId as ObserverExecutionId, Observer,
};
use drifti_observer_linux::LinuxObserver;
use drifti_store::{
    bounded_event_channel, CapabilityDomain, CommandMetadata, CoverageStatus, EventBatchWriter,
    ExecutionRepository, FinishExecution, Store,
};

use super::exit_code::{process_exit_for_observe, ObserveRun};
use crate::app::workspace::store_error;
use crate::app::{AppError, CommandContext, ObserveExit};

pub fn observe_on_linux(ctx: &CommandContext, command: &[String]) -> Result<ObserveExit, AppError> {
    let run = run_linux(ctx, command)?;
    Ok(process_exit_for_observe(run))
}

fn run_linux(ctx: &CommandContext, command: &[String]) -> Result<ObserveRun, AppError> {
    let program = command.first().ok_or_else(|| AppError::User {
        message: "observe requires a command after `--`".into(),
    })?;
    let mut store = Store::open(&ctx.cwd).map_err(store_error)?;
    let metadata =
        CommandMetadata::try_new(program, command.len().saturating_sub(1)).map_err(|error| {
            AppError::Internal {
                message: error.to_string(),
            }
        })?;
    let record = store
        .create_execution(Some(metadata))
        .map_err(store_error)?;
    let store_id = record.id().clone();
    let observer_id = ObserverExecutionId::from_raw(store_id.to_raw());

    let (sink, cursor) = bounded_event_channel(NonZeroUsize::new(128).expect("capacity"));
    let collector = thread::spawn(move || collect_events(cursor));

    let spec = CommandSpec::try_new(
        program,
        command.iter().skip(1).cloned(),
        Some(
            ctx.cwd
                .to_str()
                .ok_or_else(|| AppError::User {
                    message: "current directory is not valid UTF-8".into(),
                })?
                .to_owned(),
        ),
    )
    .map_err(observer_start_error)?;

    let observer = LinuxObserver::new(observer_id);
    let (returned_sink, result) = observer.run(spec, sink);
    drop(returned_sink);
    let mut events = collector.join().map_err(|_| AppError::Internal {
        message: "observe event collector panicked".into(),
    })?;

    let execution_result = result.map_err(observer_run_error)?;
    let writer = EventBatchWriter::with_default_limit();
    let mut coverage_complete = execution_result.coverage().is_complete();
    if let Err(error) = writer.write_batch(&mut store, &store_id, events.drain(..).collect()) {
        coverage_complete = false;
        let _ = error;
    }

    let (coverage, unsupported) = store_coverage(execution_result.coverage());
    let finish = FinishExecution::try_new(
        coverage,
        unsupported,
        execution_result.exit_code(),
        Some("1"),
        Some(env!("CARGO_PKG_VERSION")),
    )
    .map_err(|error| AppError::Internal {
        message: error.to_string(),
    })?;
    store
        .finish_execution(&store_id, finish)
        .map_err(store_error)?;

    Ok(ObserveRun {
        child_exit: execution_result.exit_code(),
        coverage_complete,
    })
}

fn collect_events(cursor: drifti_observer::EventCursor) -> Vec<drifti_observer::ObservedEvent> {
    let mut events = Vec::new();
    loop {
        match cursor.recv() {
            Ok(event) => events.push(event),
            Err(CursorError::Disconnected) => break,
            Err(CursorError::Empty | CursorError::TimedOut) => {}
        }
    }
    events
}

fn store_coverage(
    coverage: &drifti_observer::ExecutionCoverage,
) -> (CoverageStatus, BTreeSet<CapabilityDomain>) {
    let status = match coverage.status() {
        drifti_observer::ObservationCoverage::Complete => CoverageStatus::Complete,
        drifti_observer::ObservationCoverage::Incomplete => CoverageStatus::Incomplete,
        drifti_observer::ObservationCoverage::Unsupported => CoverageStatus::Unsupported,
    };
    let unsupported = coverage
        .unsupported_domains()
        .iter()
        .copied()
        .map(map_domain)
        .collect();
    (status, unsupported)
}

fn map_domain(domain: ObserverDomain) -> CapabilityDomain {
    match domain {
        ObserverDomain::Filesystem => CapabilityDomain::Filesystem,
        ObserverDomain::Network => CapabilityDomain::Network,
        ObserverDomain::Process => CapabilityDomain::Process,
    }
}

fn observer_start_error(error: drifti_observer::ObserverError) -> AppError {
    AppError::User {
        message: error.to_string(),
    }
}

fn observer_run_error(error: drifti_observer::ObserverError) -> AppError {
    AppError::Internal {
        message: error.to_string(),
    }
}
