// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The contract compiler stays inside the domain crate.

#[test]
fn compiler_source_has_no_cli_rendering() {
    let source = include_str!("../src/contract/compile.rs");
    for token in [
        "println!",
        "eprintln!",
        "stdout",
        "stderr",
        "ansi_term",
        "clap",
        "colored",
        "dialoguer",
    ] {
        assert!(
            !source.contains(token),
            "compiler source contains CLI token {token}"
        );
    }
}
