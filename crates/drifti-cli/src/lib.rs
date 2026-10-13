// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI parsing and application-service boundary for Drifti.
//!
//! KAN-75 wires the command tree and dispatches to [`app::ApplicationServices`].
//! KAN-77 wires `observe` through store and Linux observation when available.
//! KAN-78 wires `learn`, `generate`, and `diff` through core learning and drift.
//! KAN-79 wires `verify` to observation, policy evaluation, and exit mapping.

#![forbid(unsafe_code)]

pub mod app;
pub mod cli;
pub mod dispatch;
pub mod exit;
pub mod output;
pub mod render;
pub mod result;

use std::env;
use std::path::PathBuf;

pub use app::{DefaultApplicationServices, StubApplicationServices};
pub use cli::DriftiCli;
pub use exit::{EXIT_COMMAND, EXIT_INTERNAL, EXIT_NOT_READY, EXIT_SUCCESS, EXIT_USER};

use app::ApplicationServices;
use dispatch::dispatch;

const CLAP_USAGE_EXIT: i32 = 2;

pub fn run_from_env() -> i32 {
    run_with_services(&DefaultApplicationServices, env::args())
}

pub fn run_with_services<S: ApplicationServices>(
    services: &S,
    args: impl IntoIterator<Item = impl AsRef<str>>,
) -> i32 {
    let args: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string())
        .collect();
    let cwd = env::current_dir().unwrap_or_else(|error| {
        eprintln!("error: cannot read current directory: {error}");
        PathBuf::from(".")
    });

    let cli = match DriftiCli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => {
            if error.use_stderr() {
                error.print().expect("print clap error");
            } else {
                error.print().expect("print clap help");
            }
            return CLAP_USAGE_EXIT;
        }
    };

    i32::from(dispatch(services, &args, cli, cwd))
}
