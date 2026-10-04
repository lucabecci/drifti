// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Crate boundary: SQLite stays in `drifti-store`, and `drifti-core` does not
//! issue SQL.

use std::fs;
use std::path::{Path, PathBuf};

const LICENSE_HEADER: &str = "\
// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0
";

fn crate_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current).expect("read dir") {
            let path = entry.expect("read entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn rust_files_carry_the_license_header() {
    for dir in ["src", "tests"] {
        for path in rust_sources(&crate_dir().join(dir)) {
            let source = fs::read_to_string(&path).expect("read source");
            assert!(
                source.starts_with(LICENSE_HEADER),
                "{} is missing the license header",
                path.display()
            );
        }
    }
}

#[test]
fn store_depends_on_sqlite_and_not_on_core() {
    let manifest = fs::read_to_string(crate_dir().join("Cargo.toml")).expect("read manifest");
    let active: String = manifest
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(active.contains("rusqlite"));
    for forbidden in ["drifti-core", "nix", "libc", "clap", "sqlx"] {
        assert!(
            !active.contains(forbidden),
            "drifti-store manifest names {forbidden}"
        );
    }
}

#[test]
fn core_does_not_issue_sql() {
    let core = crate_dir().join("../drifti-core");
    let manifest = fs::read_to_string(core.join("Cargo.toml")).expect("read core manifest");
    for forbidden in ["rusqlite", "libsqlite3-sys", "sqlx", "drifti-store"] {
        assert!(
            !manifest.contains(forbidden),
            "drifti-core manifest names {forbidden}"
        );
    }
    for path in rust_sources(&core.join("src")) {
        let source = fs::read_to_string(&path).expect("read core source");
        for token in ["rusqlite", "libsqlite3", "PRAGMA ", "sqlite3_"] {
            assert!(
                !source.contains(token),
                "{} contains {token}",
                path.display()
            );
        }
    }
}
