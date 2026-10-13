// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Workspace paths and filesystem roots for CLI orchestration.

use std::path::{Path, PathBuf};

use drifti_core::resource::FilesystemRoots;

use super::AppError;

pub const CONTRACT_FILE: &str = "drifti.yaml";

pub fn contract_path(cwd: &Path) -> PathBuf {
    cwd.join(CONTRACT_FILE)
}

pub fn workspace_roots(cwd: &Path) -> Result<FilesystemRoots, AppError> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
    let temp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
    FilesystemRoots::new(cwd.display().to_string(), home, temp).map_err(|error| {
        AppError::Internal {
            message: format!("workspace roots: {error}"),
        }
    })
}

pub fn store_error(error: drifti_store::StoreError) -> AppError {
    AppError::Internal {
        message: error.to_string(),
    }
}

pub fn invalid_contract(message: impl Into<String>) -> AppError {
    AppError::InvalidContract {
        message: message.into(),
    }
}
