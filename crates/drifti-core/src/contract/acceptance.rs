// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Separate a generated proposal from an accepted contract.
//!
//! A proposal can be shown or prepared as text for an explicit write. Neither
//! of those steps accepts it. [`ContractProposal::accept`] and
//! [`ContractWriteRequest::accept_written`] are the only ways a proposal
//! becomes an [`AcceptedContract`]. [`AcceptedContract::loaded`] is the other
//! constructor: the caller already holds a document that was accepted before
//! this process saw it.
//!
//! Parsing and serialization still return a document or text. They do not
//! choose a standing. This module does not create files.

use super::compile::compile_contract;
use super::{serialize_contract, ContractCompileError, ContractDocument};
use crate::policy::CompiledPolicy;

/// Generated contract text that is not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a generated proposal is not accepted authority"]
pub struct ContractProposal {
    document: ContractDocument,
}

impl ContractProposal {
    /// Wraps a generated document. This does not accept it.
    pub fn generated(document: ContractDocument) -> Self {
        Self { document }
    }

    /// Document carried by the proposal.
    #[must_use]
    pub fn document(&self) -> &ContractDocument {
        &self.document
    }

    /// Stable YAML for review. Writing this text is a later explicit step.
    #[must_use]
    pub fn yaml(&self) -> String {
        serialize_contract(&self.document)
    }

    /// Accepts this proposal as authority. The document is unchanged.
    pub fn accept(self) -> AcceptedContract {
        AcceptedContract {
            document: self.document,
        }
    }

    /// Bytes a later explicit write can persist.
    ///
    /// The proposal stays a proposal. Confirming the write is
    /// [`ContractWriteRequest::accept_written`].
    pub fn write_request(&self) -> ContractWriteRequest {
        ContractWriteRequest {
            yaml: self.yaml(),
            document: self.document.clone(),
        }
    }
}

/// YAML prepared for an explicit write. Holding it does not accept the proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a write request is not accepted authority"]
pub struct ContractWriteRequest {
    yaml: String,
    document: ContractDocument,
}

impl ContractWriteRequest {
    /// Exact text the explicit write persists.
    #[must_use]
    pub fn yaml(&self) -> &str {
        &self.yaml
    }

    /// Records that the user accepted this write.
    ///
    /// The accepted document is the one that produced [`Self::yaml`]. This
    /// method does not create a file.
    pub fn accept_written(self) -> AcceptedContract {
        debug_assert_eq!(self.yaml, serialize_contract(&self.document));
        AcceptedContract {
            document: self.document,
        }
    }
}

/// Contract the caller has loaded or explicitly accepted.
///
/// This is the value that may be compiled into policy. A proposal does not
/// convert into this type on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an accepted contract is the authority boundary"]
pub struct AcceptedContract {
    document: ContractDocument,
}

impl AcceptedContract {
    /// A document that is already accepted authority.
    ///
    /// Use this for a contract the user has already accepted, such as one read
    /// back from an explicit write. Do not use it for a fresh proposal.
    pub fn loaded(document: ContractDocument) -> Self {
        Self { document }
    }

    /// Accepted document.
    #[must_use]
    pub fn document(&self) -> &ContractDocument {
        &self.document
    }

    /// Compiles the accepted document into typed policy rules.
    ///
    /// Acceptance does not skip resource validation.
    #[must_use = "compilation errors must be handled"]
    pub fn compile(&self) -> Result<CompiledPolicy, ContractCompileError> {
        compile_contract(&self.document)
    }
}
