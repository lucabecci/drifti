// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Default production wiring for MVP commands.

use std::fs;
use std::path::{Path, PathBuf};

use drifti_core::contract::{
    parse_contract, resolve_comparable_capabilities, AcceptedContract, ContractProposal,
};
use drifti_core::diff::diff;
use drifti_core::policy::{Coverage, RuleEffect};
use drifti_core::presentation::{classify_presentation, PresentationThresholds};
use drifti_core::resource::FilesystemRoots;
use drifti_observer_linux::{DoctorCheck, DoctorReport, DoctorStatus};
use drifti_store::{CoverageStatus, Store, STATE_DIR};

use super::generate::proposal_document;
use super::preflight::{ensure_observer_preflight, observer_launch_ready};
use super::store_learning::learning_input_from_store;
use super::{AppError, ApplicationServices, CommandContext, ProcessOutcome};
use crate::result::{
    CommandResult, DiffResult, DoctorFindingView, DoctorResult, DriftFindingView, GenerateResult,
    InitResult, LearnResult, ProfileCapabilityView, ResultStatus,
};

const CONTRACT_FILE: &str = "drifti.yaml";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MvpApplicationServices;

impl ApplicationServices for MvpApplicationServices {
    fn init(&self, ctx: &CommandContext) -> Result<CommandResult, AppError> {
        let store = Store::open(&ctx.cwd).map_err(store_error)?;
        let state_dir = ctx.cwd.join(STATE_DIR);
        Ok(CommandResult::Init(InitResult {
            status: ResultStatus::Ok,
            state_dir: state_dir.display().to_string(),
            contract_present: contract_path(&ctx.cwd).is_file(),
            store_path: Some(store.path().display().to_string()),
        }))
    }

    fn observe(
        &self,
        ctx: &CommandContext,
        command: &[String],
    ) -> Result<ProcessOutcome, AppError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ctx, command);
            return Err(AppError::User {
                message: "observation requires Linux".to_owned(),
            });
        }
        #[cfg(target_os = "linux")]
        {
            observe_linux(ctx, command, ObservationRunOptions::default())
        }
    }

    fn learn(&self, ctx: &CommandContext) -> Result<CommandResult, AppError> {
        let store = Store::open(&ctx.cwd).map_err(store_error)?;
        let roots = workspace_roots(&ctx.cwd)?;
        let input = learning_input_from_store(&store, &roots)?;
        let aggregated = input.aggregate();
        let profile = input.baseline_profile();
        let total_runs = aggregated.total_eligible_runs();
        let entries: Vec<ProfileCapabilityView> = profile
            .capabilities()
            .map(|capability| {
                let stats = aggregated.statistics(&capability).expect("stats");
                let label =
                    classify_presentation(stats, total_runs, PresentationThresholds::default())
                        .as_str()
                        .to_owned();
                ProfileCapabilityView { capability, label }
            })
            .collect();
        Ok(CommandResult::Learn(LearnResult {
            status: ResultStatus::Ok,
            executions_considered: usize::try_from(total_runs).unwrap_or(usize::MAX),
            capability_count: entries.len(),
            profile: entries,
        }))
    }

    fn generate(&self, ctx: &CommandContext, write: bool) -> Result<CommandResult, AppError> {
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
            fs::write(contract_path(&ctx.cwd), request.yaml()).map_err(|error| {
                AppError::Internal {
                    message: format!("write drifti.yaml: {error}"),
                }
            })?;
            wrote_contract = true;
        }
        Ok(CommandResult::Generate(GenerateResult {
            status: ResultStatus::Ok,
            proposal: true,
            yaml_preview: if write { None } else { Some(yaml_preview) },
            wrote_contract,
        }))
    }

    fn verify(&self, ctx: &CommandContext, command: &[String]) -> Result<ProcessOutcome, AppError> {
        let contract_path = contract_path(&ctx.cwd);
        if !contract_path.is_file() {
            return Err(AppError::User {
                message: "drifti.yaml is required for verify".to_owned(),
            });
        }
        let yaml = fs::read_to_string(&contract_path).map_err(|error| AppError::Internal {
            message: format!("read drifti.yaml: {error}"),
        })?;
        let document = parse_contract(&yaml).map_err(|error| AppError::InvalidContract {
            message: format!("drifti.yaml is not a valid capability contract: {error}"),
        })?;
        let contract = AcceptedContract::loaded(document);
        let contract_version = contract.document().version().get().to_string();
        let policy = contract
            .compile()
            .map_err(|error| AppError::InvalidContract {
                message: format!("drifti.yaml does not compile: {error}"),
            })?;

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, policy, contract_version);
            return Err(AppError::User {
                message: "observation requires Linux".to_owned(),
            });
        }

        #[cfg(target_os = "linux")]
        {
            verify_linux(ctx, command, policy, contract_version)
        }
    }

    fn diff(&self, ctx: &CommandContext) -> Result<CommandResult, AppError> {
        let contract_path = contract_path(&ctx.cwd);
        if !contract_path.is_file() {
            return Err(AppError::User {
                message: "drifti.yaml is required for diff".to_owned(),
            });
        }
        let yaml = fs::read_to_string(&contract_path).map_err(|error| AppError::Internal {
            message: format!("read drifti.yaml: {error}"),
        })?;
        let document = parse_contract(&yaml).map_err(|error| AppError::InvalidContract {
            message: format!("drifti.yaml is not a valid capability contract: {error}"),
        })?;
        let contract = AcceptedContract::loaded(document);
        let (reference, _) =
            resolve_comparable_capabilities(contract.document(), RuleEffect::Allow);
        let store = Store::open(&ctx.cwd).map_err(store_error)?;
        let roots = workspace_roots(&ctx.cwd)?;
        let input = learning_input_from_store(&store, &roots)?;
        let current = input.baseline_profile();
        let drift = diff(reference, current.capabilities());
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
        Ok(CommandResult::Diff(DiffResult {
            status: ResultStatus::Ok,
            contract_present: true,
            findings,
        }))
    }

    fn doctor(&self, ctx: &CommandContext) -> Result<CommandResult, AppError> {
        let report = DoctorReport::run();
        let findings: Vec<DoctorFindingView> = report
            .findings()
            .iter()
            .map(|finding| DoctorFindingView {
                check: format!("{:?}", finding.check),
                status: format!("{:?}", finding.status),
                explanation: finding.explanation.clone(),
            })
            .collect();
        let observer_ready = observer_launch_ready(&report);
        let store_open = Store::open(&ctx.cwd).is_ok();
        let contract_present = contract_path(&ctx.cwd).is_file();
        let contract_valid = if contract_present {
            let yaml = fs::read_to_string(contract_path(&ctx.cwd)).map_err(|error| {
                AppError::Internal {
                    message: format!("read drifti.yaml: {error}"),
                }
            })?;
            Some(parse_contract(&yaml).is_ok())
        } else {
            None
        };
        let ready = observer_ready && store_open && contract_valid.unwrap_or(true);
        Ok(CommandResult::Doctor(DoctorResult {
            status: if ready {
                ResultStatus::Ok
            } else {
                ResultStatus::NotReady
            },
            ready,
            store_open,
            contract_present,
            contract_valid,
            findings,
        }))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::num::NonZeroUsize;
    use std::thread;

    use drifti_core::adapters::exercised_capabilities_from_events;
    use drifti_core::observation::{
        ObservedResource as CoreResource, Operation as CoreOperation, Outcome as CoreOutcome,
    };
    use drifti_core::policy::CompiledPolicy;
    use drifti_observer::{
        CommandSpec, CursorError, ExecutionId as ObserverExecutionId,
        ObservedResource as ObserverResource, Observer, Operation as ObserverOperation,
    };
    use drifti_observer_linux::LinuxObserver;
    use drifti_store::{
        bounded_event_channel, CommandMetadata, CoverageStatus, EventBatchWriter, ExecutionId,
        FinishExecution, Store,
    };

    use super::*;
    use crate::app::verify::{apply_coverage_guard, evaluate_exercised};
    use crate::result::{CommandResult, ObserveResult, VerifyEvaluationView, VerifyResult};

    #[derive(Debug, Clone, Default)]
    pub(super) struct ObservationRunOptions {
        pub contract_version: Option<String>,
    }

    pub(super) fn observe_linux(
        ctx: &CommandContext,
        command: &[String],
        options: ObservationRunOptions,
    ) -> Result<ProcessOutcome, AppError> {
        ensure_observer_preflight()?;
        let mut store = Store::open(&ctx.cwd).map_err(store_error)?;
        let program = command.first().ok_or_else(|| AppError::User {
            message: "observe requires a command after `--`".to_owned(),
        })?;
        let args: Vec<String> = command.iter().skip(1).cloned().collect();
        let metadata = CommandMetadata::try_new(
            program,
            u16::try_from(args.len()).map_err(|_| AppError::User {
                message: "too many arguments for observe".to_owned(),
            })?,
        )
        .map_err(store_error)?;
        let record = store
            .create_execution(Some(metadata))
            .map_err(store_error)?;
        let store_id = record.id().clone();
        let observer_id = ObserverExecutionId::from_raw(store_id.to_raw());
        let command_spec = CommandSpec::try_new(program, args, Some(ctx.cwd.display().to_string()))
            .map_err(|error| AppError::Internal {
                message: format!("command spec: {error}"),
            })?;
        let (sink, cursor) = bounded_event_channel(NonZeroUsize::new(256).expect("capacity"));
        let collector = thread::spawn(move || {
            let mut events = Vec::new();
            loop {
                match cursor.recv() {
                    Ok(event) => events.push(event),
                    Err(CursorError::Disconnected) => break,
                    Err(CursorError::Empty | CursorError::TimedOut) => {}
                }
            }
            events
        });
        let observer = LinuxObserver::new(observer_id);
        let (sink, run_result) = observer.run(command_spec, sink);
        drop(sink);
        let events = collector.join().expect("event collector");
        let writer = EventBatchWriter::with_default_limit();
        let persisted = u64::try_from(writer.write_batch(&mut store, &store_id, events).map_err(
            |error| AppError::Internal {
                message: format!("event persistence failed: {}", error.store_error()),
            },
        )?)
        .unwrap_or(u64::MAX);
        let execution = run_result.map_err(|error| AppError::Internal {
            message: format!("observation failed: {error}"),
        })?;
        let (coverage, unsupported) = map_coverage(execution.coverage());
        let child_code = execution.exit_code().and_then(child_exit_to_u8);
        let finish = FinishExecution::try_new(
            coverage,
            unsupported,
            execution.exit_code(),
            options.contract_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION")),
        )
        .map_err(|error| AppError::Internal {
            message: format!("finish metadata: {error}"),
        })?;
        store
            .finish_execution(&store_id, finish)
            .map_err(store_error)?;
        let status = if matches!(
            coverage,
            CoverageStatus::Incomplete | CoverageStatus::Unsupported
        ) && child_code == Some(0)
        {
            ResultStatus::Incomplete
        } else {
            ResultStatus::Ok
        };
        let result = CommandResult::Observe(ObserveResult {
            status,
            execution_id: store_id.as_str().to_owned(),
            coverage: coverage.as_str().to_owned(),
            child_exit: child_code,
            events_persisted: persisted,
            unsupported_domains: None,
        });
        Ok(ProcessOutcome {
            result,
            process_exit: child_code.unwrap_or(0),
        })
    }

    pub(super) fn verify_linux(
        ctx: &CommandContext,
        command: &[String],
        policy: CompiledPolicy,
        contract_version: String,
    ) -> Result<ProcessOutcome, AppError> {
        let outcome = observe_linux(
            ctx,
            command,
            ObservationRunOptions {
                contract_version: Some(contract_version),
            },
        )?;
        let CommandResult::Observe(observe) = outcome.result else {
            return Err(AppError::Internal {
                message: "verify expected observe result".to_owned(),
            });
        };
        let store = Store::open(&ctx.cwd).map_err(store_error)?;
        let history = store
            .execution_history(&ExecutionId::parse(&observe.execution_id).map_err(store_error)?)
            .map_err(store_error)?;
        let roots = workspace_roots(&ctx.cwd)?;
        let capabilities = exercised_capabilities_from_events(
            history.events().iter().cloned().filter_map(map_store_event),
            &roots,
        );
        let coverage = map_policy_coverage(history.execution().coverage());
        let summary = apply_coverage_guard(
            evaluate_exercised(&policy, capabilities, coverage),
            coverage,
        );
        let evaluations = summary
            .evaluations
            .into_iter()
            .map(|(capability, evaluation)| VerifyEvaluationView {
                decision: evaluation.decision().as_str().to_owned(),
                capability: Some(capability),
            })
            .collect();
        let status = if summary.denied {
            ResultStatus::Violation
        } else if summary.indeterminate {
            ResultStatus::Incomplete
        } else {
            ResultStatus::Ok
        };
        let result = CommandResult::Verify(VerifyResult {
            status,
            coverage: observe.coverage,
            child_exit: observe.child_exit,
            evaluations,
        });
        Ok(ProcessOutcome {
            result,
            process_exit: outcome.process_exit,
        })
    }

    fn map_store_event(
        event: drifti_observer::ObservedEvent,
    ) -> Option<drifti_core::observation::ObservedEvent> {
        let operation = match event.operation() {
            ObserverOperation::FilesystemRead => CoreOperation::FilesystemRead,
            ObserverOperation::FilesystemWrite => CoreOperation::FilesystemWrite,
            ObserverOperation::FilesystemMetadata => CoreOperation::FilesystemMetadata,
            ObserverOperation::ProcessExecute => CoreOperation::ProcessExecute,
            ObserverOperation::NetworkConnect => CoreOperation::NetworkConnect,
            ObserverOperation::NetworkListen => CoreOperation::NetworkListen,
        };
        let resource = match event.resource() {
            ObserverResource::File { path } => CoreResource::file(path.clone()).ok()?,
            ObserverResource::Executable { identity } => {
                CoreResource::executable(identity.clone()).ok()?
            }
            ObserverResource::Network { host, port, .. } => {
                CoreResource::network(host.clone(), *port).ok()?
            }
        };
        let outcome = if event.was_exercised() {
            CoreOutcome::Success
        } else {
            CoreOutcome::Failure
        };
        Some(drifti_core::observation::ObservedEvent::new(
            operation, resource, outcome,
        ))
    }

    fn child_exit_to_u8(code: i32) -> Option<u8> {
        u8::try_from(code).ok().or_else(|| {
            if code > i32::from(u8::MAX) {
                Some(u8::MAX)
            } else {
                None
            }
        })
    }

    fn map_coverage(
        coverage: &drifti_observer::ExecutionCoverage,
    ) -> (
        CoverageStatus,
        std::collections::BTreeSet<drifti_store::CapabilityDomain>,
    ) {
        use drifti_observer::ObservationCoverage;
        let status = match coverage.status() {
            ObservationCoverage::Complete => CoverageStatus::Complete,
            ObservationCoverage::Incomplete => CoverageStatus::Incomplete,
            ObservationCoverage::Unsupported => CoverageStatus::Unsupported,
        };
        let unsupported = coverage
            .unsupported_domains()
            .iter()
            .map(|domain| match domain {
                drifti_observer::CapabilityDomain::Filesystem => {
                    drifti_store::CapabilityDomain::Filesystem
                }
                drifti_observer::CapabilityDomain::Network => {
                    drifti_store::CapabilityDomain::Network
                }
                drifti_observer::CapabilityDomain::Process => {
                    drifti_store::CapabilityDomain::Process
                }
            })
            .collect();
        (status, unsupported)
    }
}

#[cfg(target_os = "linux")]
use linux::{observe_linux, verify_linux};

fn contract_path(cwd: &Path) -> PathBuf {
    cwd.join(CONTRACT_FILE)
}

fn workspace_roots(cwd: &Path) -> Result<FilesystemRoots, AppError> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
    let temp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    FilesystemRoots::new(cwd.display().to_string(), home, temp).map_err(|error| {
        AppError::Internal {
            message: format!("workspace roots: {error}"),
        }
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn map_policy_coverage(coverage: Option<CoverageStatus>) -> Coverage {
    match coverage {
        Some(CoverageStatus::Complete) => Coverage::Complete,
        Some(CoverageStatus::Unsupported) => Coverage::Unsupported,
        Some(CoverageStatus::Incomplete) | None => Coverage::Incomplete,
    }
}

fn store_error(error: drifti_store::StoreError) -> AppError {
    AppError::Internal {
        message: format!("store error: {error}"),
    }
}
