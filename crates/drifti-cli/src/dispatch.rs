// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Map parsed CLI commands to application services.

use std::path::PathBuf;

use crate::app::{AppError, ApplicationServices, CliError, CommandContext};
use crate::cli::{Commands, DriftiCli};
use crate::exit::{EXIT_INTERNAL, EXIT_NOT_READY, EXIT_SUCCESS, EXIT_USER};
use crate::output::OutputConfig;

pub fn validate_wrapped_command(
    raw_args: &[String],
    subcommand: &'static str,
) -> Result<Vec<String>, CliError> {
    let Some(index) = raw_args.iter().position(|arg| arg == subcommand) else {
        return Err(CliError::MissingCommandSeparator { subcommand });
    };
    let tail: Vec<&String> = raw_args.iter().skip(index + 1).collect();
    let Some(dash_index) = tail.iter().position(|arg| arg.as_str() == "--") else {
        return Err(CliError::MissingCommandSeparator { subcommand });
    };
    let command: Vec<String> = tail
        .iter()
        .skip(dash_index + 1)
        .map(|s| (*s).clone())
        .collect();
    if command.is_empty() {
        return Err(CliError::EmptyWrappedCommand { subcommand });
    }
    Ok(command)
}

fn command_context(cli: &DriftiCli, cwd: PathBuf) -> CommandContext {
    CommandContext {
        cwd,
        output: OutputConfig::new(cli.format, cli.quiet, cli.verbose, cli.color),
    }
}

pub fn dispatch<S: ApplicationServices>(
    services: &S,
    raw_args: &[String],
    cli: DriftiCli,
    cwd: PathBuf,
) -> u8 {
    let ctx = command_context(&cli, cwd);
    let result: Result<u8, AppError> = match cli.command {
        Commands::Init => services.init(&ctx).map(|_| EXIT_SUCCESS),
        Commands::Observe { .. } => {
            let command = match validate_wrapped_command(raw_args, "observe") {
                Ok(command) => command,
                Err(error) => {
                    eprintln!("error: {error}");
                    return EXIT_USER;
                }
            };
            services.observe(&ctx, &command).map(|exit| exit.code)
        }
        Commands::Learn => services.learn(&ctx).map(|_| EXIT_SUCCESS),
        Commands::Generate { write } => services.generate(&ctx, write).map(|_| EXIT_SUCCESS),
        Commands::Verify { .. } => {
            let command = match validate_wrapped_command(raw_args, "verify") {
                Ok(command) => command,
                Err(error) => {
                    eprintln!("error: {error}");
                    return EXIT_USER;
                }
            };
            services.verify(&ctx, &command).map(|exit| exit.code)
        }
        Commands::Diff => services.diff(&ctx).map(|_| EXIT_SUCCESS),
        Commands::Doctor => services.doctor(&ctx).map(|_| EXIT_SUCCESS),
    };

    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            map_app_error(error)
        }
    }
}

pub fn map_app_error(error: AppError) -> u8 {
    match error {
        AppError::Internal { .. } => EXIT_INTERNAL,
        AppError::User { .. } => EXIT_USER,
        AppError::NotImplemented { .. } => EXIT_NOT_READY,
    }
}
