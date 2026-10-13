// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{self, Write};

use crate::result::CommandResult;

pub fn render(result: &CommandResult, stdout: &mut impl Write) -> io::Result<()> {
    let json =
        serde_json::to_string(result).map_err(|error| io::Error::other(error.to_string()))?;
    writeln!(stdout, "{json}")
}
