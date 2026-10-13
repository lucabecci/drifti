// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process exit codes for the `drifti` binary (SPEC-009).
//!
//! Mapping used by [`crate::dispatch`]:
//! - [`EXIT_SUCCESS`]: command completed without error.
//! - Clap usage / invalid flags: `2` (conventional; not a named constant here).
//! - [`EXIT_INTERNAL`]: unexpected failure in [`crate::app::AppError::Internal`].
//! - [`EXIT_USER`]: actionable user-facing errors ([`crate::app::AppError::User`]).
//! - [`EXIT_NOT_READY`]: command not wired yet ([`crate::app::AppError::NotImplemented`]).
//! - [`EXIT_COMMAND`]: wrapped command failed during observe/verify (future KAN-76+).

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_INTERNAL: u8 = 120;
pub const EXIT_USER: u8 = 121;
pub const EXIT_NOT_READY: u8 = 122;
pub const EXIT_COMMAND: u8 = 123;
