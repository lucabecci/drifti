// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{self, Write};

use crate::output::OutputConfig;
use crate::result::{
    CommandResult, DiffResult, DoctorResult, GenerateResult, InitResult, LearnResult,
    ObserveResult, VerifyResult,
};

pub fn render(
    result: &CommandResult,
    output: &OutputConfig,
    use_color: bool,
    stdout: &mut impl Write,
) -> io::Result<()> {
    match result {
        CommandResult::Init(body) => render_init(body, stdout),
        CommandResult::Doctor(body) => render_doctor(body, output, stdout),
        CommandResult::Observe(body) => render_observe(body, stdout),
        CommandResult::Verify(body) => render_verify(body, stdout),
        CommandResult::Learn(body) => render_learn(body, output, stdout),
        CommandResult::Generate(body) => render_generate(body, output, stdout),
        CommandResult::Diff(body) => render_diff(body, stdout),
    }?;
    let _ = use_color;
    Ok(())
}

fn render_init(result: &InitResult, stdout: &mut impl Write) -> io::Result<()> {
    writeln!(
        stdout,
        "status: {}\nstate directory ready at {}\ncontract file present: {}",
        result.status.as_str(),
        result.state_dir,
        result.contract_present
    )
}

fn render_doctor(
    result: &DoctorResult,
    output: &OutputConfig,
    stdout: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        stdout,
        "status: {}\nready: {}\nstore: {}",
        result.status.as_str(),
        result.ready,
        if result.store_open {
            "open"
        } else {
            "unavailable"
        }
    )?;
    if let Some(valid) = result.contract_valid {
        writeln!(stdout, "contract valid: {valid}")?;
    }
    if output.mode.verbose {
        for finding in &result.findings {
            writeln!(
                stdout,
                "  {}: {} — {}",
                finding.check, finding.status, finding.explanation
            )?;
        }
    }
    Ok(())
}

fn render_observe(result: &ObserveResult, stdout: &mut impl Write) -> io::Result<()> {
    writeln!(
        stdout,
        "status: {}\nexecution: {}\ncoverage: {}",
        result.status.as_str(),
        result.execution_id,
        result.coverage
    )?;
    if let Some(code) = result.child_exit {
        writeln!(stdout, "child exit: {code}")?;
    }
    Ok(())
}

fn render_verify(result: &VerifyResult, stdout: &mut impl Write) -> io::Result<()> {
    writeln!(
        stdout,
        "status: {}\ncoverage: {}",
        result.status.as_str(),
        result.coverage
    )?;
    for evaluation in &result.evaluations {
        if evaluation.decision == "DENIED" || evaluation.decision == "INDETERMINATE" {
            writeln!(
                stdout,
                "  {} {:?}",
                evaluation.decision, evaluation.capability
            )?;
        }
    }
    if let Some(code) = result.child_exit {
        writeln!(stdout, "child exit: {code}")?;
    }
    Ok(())
}

fn render_learn(
    result: &LearnResult,
    output: &OutputConfig,
    stdout: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        stdout,
        "Capability Profile (observed)\nstatus: {}\ncapabilities: {}",
        result.status.as_str(),
        result.capability_count
    )?;
    if output.mode.verbose {
        for entry in &result.profile {
            writeln!(
                stdout,
                "  {} — {}",
                entry.label,
                entry.capability.action().as_str()
            )?;
        }
    }
    Ok(())
}

fn render_generate(
    result: &GenerateResult,
    output: &OutputConfig,
    stdout: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        stdout,
        "status: {}\nproposal only: {}\nwrote drifti.yaml: {}",
        result.status.as_str(),
        result.proposal,
        result.wrote_contract
    )?;
    if output.mode.verbose {
        if let Some(yaml) = &result.yaml_preview {
            writeln!(stdout, "{yaml}")?;
        }
    }
    Ok(())
}

fn render_diff(result: &DiffResult, stdout: &mut impl Write) -> io::Result<()> {
    writeln!(
        stdout,
        "status: {}\nfindings: {}",
        result.status.as_str(),
        result.findings.len()
    )?;
    for finding in &result.findings {
        writeln!(stdout, "  {}", finding.kind)?;
    }
    Ok(())
}
