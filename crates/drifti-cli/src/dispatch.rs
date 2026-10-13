// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Map parsed CLI commands to application services.

use std::io::{self, Write};
use std::path::PathBuf;

use crate::app::{AppError, ApplicationServices, CliError, CommandContext};
use crate::cli::{Commands, DriftiCli};
use crate::exit::{
    map_command_outcome, CommandExitInput, EXIT_INTERNAL, EXIT_INVALID_CONTRACT, EXIT_USAGE,
};
use crate::output::OutputConfig;
use crate::render::render_result;
use crate::result::CommandResult;

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
    let mut stdout = io::stdout();
    let outcome = match cli.command {
        Commands::Init => services.init(&ctx).map(|result| (result, None)),
        Commands::Observe { .. } => {
            let command = match validate_wrapped_command(raw_args, "observe") {
                Ok(command) => command,
                Err(error) => {
                    let _ = writeln!(io::stderr(), "error: {error}");
                    return EXIT_USAGE;
                }
            };
            services
                .observe(&ctx, &command)
                .map(|outcome| (outcome.result, Some(u16::from(outcome.process_exit))))
        }
        Commands::Learn => services.learn(&ctx).map(|result| (result, None)),
        Commands::Generate { write } => services.generate(&ctx, write).map(|result| (result, None)),
        Commands::Verify { .. } => {
            let command = match validate_wrapped_command(raw_args, "verify") {
                Ok(command) => command,
                Err(error) => {
                    let _ = writeln!(io::stderr(), "error: {error}");
                    return EXIT_USAGE;
                }
            };
            services
                .verify(&ctx, &command)
                .map(|outcome| (outcome.result, Some(u16::from(outcome.process_exit))))
        }
        Commands::Diff => services.diff(&ctx).map(|result| (result, None)),
        Commands::Doctor => services.doctor(&ctx).map(|result| (result, None)),
    };

    match outcome {
        Ok((result, process_override)) => {
            finish_command(&result, process_override, &ctx.output, &mut stdout)
        }
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {error}");
            map_app_error(error)
        }
    }
}

fn finish_command(
    result: &CommandResult,
    process_override: Option<u16>,
    output: &OutputConfig,
    stdout: &mut impl Write,
) -> u8 {
    if render_result(result, output, stdout).is_err() {
        return EXIT_INTERNAL;
    }
    let input = CommandExitInput {
        class: result.exit_class(),
        process_exit: process_override.or_else(|| result.process_exit().map(u16::from)),
    };
    map_command_outcome(input)
}

pub fn map_app_error(error: AppError) -> u8 {
    match error {
        AppError::Internal { .. } | AppError::NotImplemented { .. } => EXIT_INTERNAL,
        AppError::InvalidContract { .. } => EXIT_INVALID_CONTRACT,
        AppError::User { .. } => EXIT_USAGE,
    }
}
