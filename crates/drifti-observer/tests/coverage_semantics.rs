// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Coverage semantics for one execution. This test is the higher-layer consumer:
//! it matches [`drifti_observer::coverage::DomainObservation`] using only this crate.

use drifti_observer::coverage::DomainObservation;
use drifti_observer::{
    CapabilityDomain, CommandSpec, CoverageError, EventSink, ExecutionCoverage, ExecutionId,
    ExecutionResult, ObservationCoverage, Observer, ObserverCapabilities, ObserverError,
};

#[test]
fn observation_coverage_round_trips_screaming_snake_case() {
    for status in ObservationCoverage::ALL {
        let name = status.as_str();
        let encoded = serde_json::to_string(&status).expect("serialize");
        assert_eq!(encoded, format!("\"{name}\""));
        let decoded: ObservationCoverage = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, status);
    }

    for name in ["COMPLETE", "INCOMPLETE", "UNSUPPORTED"] {
        let decoded: ObservationCoverage =
            serde_json::from_str(&format!("\"{name}\"")).expect("known status");
        assert_eq!(decoded.as_str(), name);
    }

    assert!(serde_json::from_str::<ObservationCoverage>("\"ALLOWED\"").is_err());
    assert!(serde_json::from_str::<ObservationCoverage>("\"success\"").is_err());
}

#[test]
fn complete_declaration_rejects_an_unsupported_domain() {
    let complete =
        ExecutionCoverage::declared(ObservationCoverage::Complete, []).expect("explicit complete");
    assert!(complete.is_complete());
    assert_eq!(complete.status(), ObservationCoverage::Complete);
    assert!(complete.unsupported_domains().is_empty());

    let rejected = ExecutionCoverage::declared(
        ObservationCoverage::Complete,
        [CapabilityDomain::Filesystem],
    );
    assert_eq!(rejected, Err(CoverageError::CompleteWhileUnsupported));
    assert!(rejected.ok().is_none());
}

#[test]
fn no_events_seen_is_incomplete_and_not_unsupported() {
    let coverage = ExecutionCoverage::no_events_seen();
    assert_eq!(coverage.status(), ObservationCoverage::Incomplete);
    assert!(coverage.unsupported_domains().is_empty());
    assert!(!coverage.is_complete());
    assert_ne!(coverage.status(), ObservationCoverage::Unsupported);
    assert_ne!(coverage.status(), ObservationCoverage::Complete);

    let advertised = ObserverCapabilities::new(CapabilityDomain::ALL);
    for domain in CapabilityDomain::ALL {
        assert_eq!(
            coverage.domain(&advertised, domain),
            DomainObservation::NotObserved
        );
    }

    let encoded = serde_json::to_value(&coverage).expect("serialize absence");
    assert_eq!(encoded["status"], "INCOMPLETE");
    assert_ne!(encoded["status"], "COMPLETE");
    assert_ne!(encoded["status"], "UNSUPPORTED");
    assert_eq!(encoded["unsupported_domains"], serde_json::json!([]));
    let decoded: ExecutionCoverage = serde_json::from_value(encoded).expect("deserialize absence");
    assert_eq!(decoded, coverage);
    assert!(!decoded.is_complete());
}

#[test]
fn empty_event_list_does_not_become_complete() {
    let events: &[()] = &[];
    let coverage = absence_from_events(events);
    assert!(events.is_empty());
    assert_eq!(coverage, ExecutionCoverage::no_events_seen());
    assert!(!coverage.is_complete());
    assert_eq!(coverage.status(), ObservationCoverage::Incomplete);
}

fn absence_from_events<T>(events: &[T]) -> ExecutionCoverage {
    assert!(
        events.is_empty(),
        "only the absence constructor applies to an empty event list"
    );
    ExecutionCoverage::no_events_seen()
}

#[test]
fn unsupported_domain_stays_distinct_from_a_domain_that_was_not_seen() {
    let advertised = ObserverCapabilities::new(CapabilityDomain::ALL);
    let partial =
        ExecutionCoverage::declared(ObservationCoverage::Incomplete, [CapabilityDomain::Network])
            .expect("partial declaration");

    assert_eq!(
        partial.domain(&advertised, CapabilityDomain::Network),
        DomainObservation::Unsupported
    );
    assert_eq!(
        partial.domain(&advertised, CapabilityDomain::Filesystem),
        DomainObservation::NotObserved
    );
    assert_ne!(
        partial.domain(&advertised, CapabilityDomain::Network),
        partial.domain(&advertised, CapabilityDomain::Filesystem)
    );

    let execution_unsupported =
        ExecutionCoverage::declared(ObservationCoverage::Unsupported, []).expect("unsupported");
    assert_eq!(
        execution_unsupported.domain(&advertised, CapabilityDomain::Process),
        DomainObservation::Unsupported
    );
    assert_ne!(
        execution_unsupported.domain(&advertised, CapabilityDomain::Process),
        ExecutionCoverage::no_events_seen().domain(&advertised, CapabilityDomain::Process)
    );

    let complete =
        ExecutionCoverage::declared(ObservationCoverage::Complete, []).expect("complete");
    for domain in CapabilityDomain::ALL {
        assert_eq!(
            complete.domain(&advertised, domain),
            DomainObservation::Covered
        );
    }
}

#[test]
fn higher_layer_matches_domain_observation_without_a_platform_backend() {
    let cases = [
        (
            ExecutionCoverage::no_events_seen(),
            CapabilityDomain::Filesystem,
            "not_observed",
        ),
        (
            ExecutionCoverage::declared(
                ObservationCoverage::Incomplete,
                [CapabilityDomain::Network],
            )
            .expect("network unsupported"),
            CapabilityDomain::Network,
            "unsupported",
        ),
        (
            ExecutionCoverage::declared(
                ObservationCoverage::Incomplete,
                [CapabilityDomain::Network],
            )
            .expect("filesystem not seen"),
            CapabilityDomain::Filesystem,
            "not_observed",
        ),
        (
            ExecutionCoverage::declared(ObservationCoverage::Complete, []).expect("complete"),
            CapabilityDomain::Process,
            "covered",
        ),
    ];

    let advertised = ObserverCapabilities::new(CapabilityDomain::ALL);
    for (coverage, domain, expected) in cases {
        assert_eq!(classify_domain(&coverage, &advertised, domain), expected);
    }
}

fn classify_domain(
    coverage: &ExecutionCoverage,
    capabilities: &ObserverCapabilities,
    domain: CapabilityDomain,
) -> &'static str {
    match coverage.domain(capabilities, domain) {
        drifti_observer::coverage::DomainObservation::Covered => "covered",
        drifti_observer::coverage::DomainObservation::NotObserved => "not_observed",
        drifti_observer::coverage::DomainObservation::Unsupported => "unsupported",
    }
}

#[test]
fn status_degrade_keeps_unsupported_when_folded_with_incomplete() {
    for left in ObservationCoverage::ALL {
        for right in ObservationCoverage::ALL {
            let degraded = left.degrade(right);
            if left.is_complete() && right.is_complete() {
                assert!(degraded.is_complete());
            } else {
                assert!(!degraded.is_complete());
            }
        }
    }

    assert_eq!(
        ObservationCoverage::Incomplete.degrade(ObservationCoverage::Complete),
        ObservationCoverage::Incomplete
    );
    assert_eq!(
        ObservationCoverage::Unsupported.degrade(ObservationCoverage::Complete),
        ObservationCoverage::Unsupported
    );
    assert_eq!(
        ObservationCoverage::Complete.degrade(ObservationCoverage::Incomplete),
        ObservationCoverage::Incomplete
    );
    assert_eq!(
        ObservationCoverage::Complete.degrade(ObservationCoverage::Unsupported),
        ObservationCoverage::Unsupported
    );
    assert_eq!(
        ObservationCoverage::Incomplete.degrade(ObservationCoverage::Unsupported),
        ObservationCoverage::Unsupported
    );
    assert_eq!(
        ObservationCoverage::Unsupported.degrade(ObservationCoverage::Incomplete),
        ObservationCoverage::Unsupported
    );
    assert_eq!(
        ObservationCoverage::Incomplete.degrade(ObservationCoverage::Unsupported),
        ObservationCoverage::Unsupported.degrade(ObservationCoverage::Incomplete)
    );

    let advertised = ObserverCapabilities::new(CapabilityDomain::ALL);
    let from_incomplete =
        ExecutionCoverage::no_events_seen().degrade_status(ObservationCoverage::Unsupported);
    assert_eq!(from_incomplete.status(), ObservationCoverage::Unsupported);
    assert_eq!(
        from_incomplete.domain(&advertised, CapabilityDomain::Filesystem),
        DomainObservation::Unsupported
    );
    assert_ne!(
        from_incomplete.domain(&advertised, CapabilityDomain::Filesystem),
        DomainObservation::NotObserved
    );
    let from_unsupported =
        ExecutionCoverage::declared(ObservationCoverage::Unsupported, []).expect("unsupported");
    let folded = from_unsupported.degrade_status(ObservationCoverage::Incomplete);
    assert_eq!(folded.status(), from_incomplete.status());
    assert_eq!(
        folded.domain(&advertised, CapabilityDomain::Network),
        DomainObservation::Unsupported
    );
}

#[test]
fn degrade_status_does_not_invent_complete_coverage() {
    let domain_sets: [&[CapabilityDomain]; 2] = [&[], &[CapabilityDomain::Filesystem]];

    for status in ObservationCoverage::ALL {
        for domains in domain_sets {
            let Ok(coverage) = ExecutionCoverage::declared(status, domains.iter().copied()) else {
                assert!(status.is_complete());
                assert!(!domains.is_empty());
                continue;
            };
            for next in ObservationCoverage::ALL {
                let degraded = coverage.clone().degrade_status(next);
                let expected = status.degrade(next);
                assert_eq!(degraded.status(), expected);
                assert_eq!(
                    degraded.unsupported_domains(),
                    coverage.unsupported_domains()
                );
                if degraded.is_complete() {
                    assert!(expected.is_complete());
                    assert!(degraded.unsupported_domains().is_empty());
                }
            }
        }
    }

    let network_unseen =
        ExecutionCoverage::declared(ObservationCoverage::Incomplete, [CapabilityDomain::Network])
            .expect("network unsupported");
    let stayed = network_unseen
        .clone()
        .degrade_status(ObservationCoverage::Complete);
    assert_eq!(stayed.status(), ObservationCoverage::Incomplete);
    assert!(!stayed.is_complete());
    let advertised = ObserverCapabilities::new(CapabilityDomain::ALL);
    assert_eq!(
        stayed.domain(&advertised, CapabilityDomain::Network),
        DomainObservation::Unsupported
    );
    assert_eq!(
        stayed.domain(&advertised, CapabilityDomain::Filesystem),
        DomainObservation::NotObserved
    );

    let complete =
        ExecutionCoverage::declared(ObservationCoverage::Complete, []).expect("complete");
    assert!(complete
        .clone()
        .degrade_status(ObservationCoverage::Complete)
        .is_complete());
    assert_eq!(
        complete
            .clone()
            .degrade_status(ObservationCoverage::Incomplete)
            .status(),
        ObservationCoverage::Incomplete
    );
    assert_eq!(
        complete
            .degrade_status(ObservationCoverage::Unsupported)
            .status(),
        ObservationCoverage::Unsupported
    );
}

#[test]
fn complete_does_not_cover_a_domain_the_observer_did_not_advertise() {
    let capabilities = FilesystemOnly.capabilities();
    assert!(capabilities.observes(CapabilityDomain::Filesystem));
    assert!(!capabilities.observes(CapabilityDomain::Network));

    let complete =
        ExecutionCoverage::declared(ObservationCoverage::Complete, []).expect("complete");
    assert_eq!(
        complete.domain(&capabilities, CapabilityDomain::Filesystem),
        DomainObservation::Covered
    );
    assert_eq!(
        complete.domain(&capabilities, CapabilityDomain::Network),
        DomainObservation::Unsupported
    );
    assert_ne!(
        complete.domain(&capabilities, CapabilityDomain::Network),
        DomainObservation::Covered
    );
    assert_ne!(
        complete.domain(&capabilities, CapabilityDomain::Network),
        DomainObservation::NotObserved
    );

    let absent = ExecutionCoverage::no_events_seen();
    assert_eq!(
        absent.domain(&capabilities, CapabilityDomain::Filesystem),
        DomainObservation::NotObserved
    );
    assert_eq!(
        absent.domain(&capabilities, CapabilityDomain::Network),
        DomainObservation::Unsupported
    );
    assert_ne!(
        absent.domain(&capabilities, CapabilityDomain::Network),
        DomainObservation::NotObserved
    );
}

struct FilesystemOnly;

impl Observer for FilesystemOnly {
    fn capabilities(&self) -> ObserverCapabilities {
        ObserverCapabilities::new([CapabilityDomain::Filesystem])
    }

    fn run(
        &self,
        _command: CommandSpec,
        sink: EventSink,
    ) -> (EventSink, Result<ExecutionResult, ObserverError>) {
        let coverage =
            ExecutionCoverage::declared(ObservationCoverage::Complete, []).expect("complete");
        (
            sink,
            Ok(ExecutionResult::new(
                ExecutionId::from_raw(1),
                coverage,
                Some(0),
            )),
        )
    }
}
