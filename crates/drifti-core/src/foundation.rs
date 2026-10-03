// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serde boundary for domain values.
//!
//! Domain types in this crate serialize with these traits. This module is
//! not a capability, a contract, or a policy decision.

pub use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::{Deserialize, Serialize};
    use proptest::prelude::*;
    use proptest::test_runner::{TestRng, TestRunner};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Probe {
        n: u32,
    }

    fn deterministic_runner() -> TestRunner {
        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm))
    }

    #[test]
    fn round_trip_is_lossless() {
        let value = Probe { n: 7 };
        let encoded = serde_json::to_string(&value).expect("serialize probe");
        let decoded: Probe = serde_json::from_str(&encoded).expect("deserialize probe");
        assert_eq!(value, decoded);
    }

    #[test]
    fn invalid_json_is_rejected() {
        let error = serde_json::from_str::<Probe>("{\"n\":").expect_err("truncated json");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn round_trip_preserves_integers() {
        let mut runner = deterministic_runner();
        runner
            .run(&any::<u32>(), |n| {
                let value = Probe { n };
                let encoded = serde_json::to_vec(&value).expect("serialize probe");
                let decoded: Probe = serde_json::from_slice(&encoded).expect("deserialize probe");
                prop_assert_eq!(value, decoded);
                Ok(())
            })
            .expect("serde round trip");
    }
}
