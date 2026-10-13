// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{self, Write};

use crate::result::{DiffResult, GenerateResult, IntelligenceResult, LearnResult, ResultStatus};

pub fn render_text(result: &IntelligenceResult, stdout: &mut impl Write) -> io::Result<()> {
    match result {
        IntelligenceResult::Learn(learn) => render_learn_text(learn, stdout),
        IntelligenceResult::Generate(generate) => render_generate_text(generate, stdout),
        IntelligenceResult::Diff(diff) => render_diff_text(diff, stdout),
    }
}

pub fn render_json(result: &IntelligenceResult, stdout: &mut impl Write) -> io::Result<()> {
    let value = serde_json::to_string(result).map_err(io::Error::other)?;
    writeln!(stdout, "{value}")
}

fn render_learn_text(learn: &LearnResult, stdout: &mut impl Write) -> io::Result<()> {
    writeln!(
        stdout,
        "learned capability profile (not an accepted contract)"
    )?;
    writeln!(
        stdout,
        "executions: {}  capabilities: {}",
        learn.executions_considered, learn.capability_count
    )?;
    for entry in &learn.profile {
        writeln!(
            stdout,
            "{}  {}",
            entry.label,
            format_capability(&entry.capability)
        )?;
    }
    Ok(())
}

fn render_generate_text(generate: &GenerateResult, stdout: &mut impl Write) -> io::Result<()> {
    if generate.wrote_contract {
        writeln!(
            stdout,
            "wrote proposed contract to drifti.yaml (not accepted)"
        )?;
        return Ok(());
    }
    if let Some(yaml) = &generate.yaml_preview {
        writeln!(stdout, "proposed contract (not accepted):")?;
        write!(stdout, "{yaml}")?;
        if !yaml.ends_with('\n') {
            writeln!(stdout)?;
        }
    }
    Ok(())
}

fn render_diff_text(diff: &DiffResult, stdout: &mut impl Write) -> io::Result<()> {
    if diff.status != ResultStatus::Ok {
        return Ok(());
    }
    if diff.findings.is_empty() {
        writeln!(
            stdout,
            "no structural drift between learned profile and drifti.yaml allow rules"
        )?;
        return Ok(());
    }
    writeln!(stdout, "structural drift (allow rules vs learned profile):")?;
    for finding in &diff.findings {
        match (&finding.reference, &finding.current) {
            (Some(reference), Some(current)) => writeln!(
                stdout,
                "{}  {} -> {}",
                finding.kind,
                format_capability(reference),
                format_capability(current)
            )?,
            (None, Some(current)) => {
                writeln!(stdout, "{}  {}", finding.kind, format_capability(current))?
            }
            (Some(reference), None) => {
                writeln!(stdout, "{}  {}", finding.kind, format_capability(reference))?
            }
            (None, None) => writeln!(stdout, "{}", finding.kind)?,
        }
    }
    Ok(())
}

fn format_capability(capability: &drifti_core::capability::Capability) -> String {
    format!("{capability:?}")
}
