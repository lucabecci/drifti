// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded text checks shared by the observation types.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextError {
    Empty,
    TooLong,
    EmbeddedNul,
}

pub(crate) fn bounded(text: impl Into<String>, max: usize) -> Result<String, TextError> {
    let text = text.into();
    if text.is_empty() {
        return Err(TextError::Empty);
    }
    if text.len() > max {
        return Err(TextError::TooLong);
    }
    if text.contains('\0') {
        return Err(TextError::EmbeddedNul);
    }
    Ok(text)
}
