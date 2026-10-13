// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build a version-1 contract proposal from a learned profile.

use std::collections::BTreeMap;

use drifti_core::capability::{Action, Capability};
use drifti_core::contract::{
    AllowDenyRules, AuthoringResource, ContractDocument, ContractVersion, FilesystemContract,
    NetworkContract, ProcessContract,
};
use drifti_core::learning_guard::guarded_learning_candidates;
use drifti_core::profile::CapabilityProfile;
use drifti_core::resource::{
    ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
    NetworkResource, Resource,
};

use super::AppError;

pub fn proposal_document(profile: &CapabilityProfile) -> Result<ContractDocument, AppError> {
    let candidates = guarded_learning_candidates(profile.capabilities());
    let mut read = Vec::new();
    let mut write = Vec::new();
    let mut execute = Vec::new();
    let mut connect = Vec::new();
    let mut listen = Vec::new();
    for capability in candidates {
        let text = capability_to_authoring(&capability)
            .map_err(|message| AppError::Internal { message })?;
        let resource = AuthoringResource::new(text).map_err(|error| AppError::Internal {
            message: format!("authoring resource: {error}"),
        })?;
        match capability.action() {
            Action::FilesystemRead | Action::FilesystemMetadata => read.push(resource),
            Action::FilesystemWrite => write.push(resource),
            Action::ProcessExecute => execute.push(resource),
            Action::NetworkConnect => connect.push(resource),
            Action::NetworkListen => listen.push(resource),
        }
    }
    dedupe(&mut read);
    dedupe(&mut write);
    dedupe(&mut execute);
    dedupe(&mut connect);
    dedupe(&mut listen);
    Ok(ContractDocument::new(
        ContractVersion::V1,
        FilesystemContract::new(
            AllowDenyRules::new(read, Vec::new()),
            AllowDenyRules::new(write, Vec::new()),
        ),
        ProcessContract::new(AllowDenyRules::new(execute, Vec::new())),
        NetworkContract::new(
            AllowDenyRules::new(connect, Vec::new()),
            AllowDenyRules::new(listen, Vec::new()),
        ),
    ))
}

fn dedupe(resources: &mut Vec<AuthoringResource>) {
    let mut seen = BTreeMap::new();
    for resource in resources.drain(..) {
        seen.insert(resource.as_str().to_owned(), resource);
    }
    resources.extend(seen.into_values());
}

fn capability_to_authoring(capability: &Capability) -> Result<String, String> {
    match capability.resource() {
        Resource::File(file) => file_authoring(file),
        Resource::Executable(executable) => executable_authoring(executable),
        Resource::Network(network) => network_authoring(network),
    }
}

fn file_authoring(file: &FileResource) -> Result<String, String> {
    let path = file.file_path();
    Ok(match file.anchor() {
        FilesystemAnchor::Repo => format!("./{path}"),
        FilesystemAnchor::Home => {
            if path == "." {
                "~/".to_owned()
            } else {
                format!("~/{path}")
            }
        }
        FilesystemAnchor::Temp => format!("temp://{path}"),
        FilesystemAnchor::Absolute => path.to_owned(),
    })
}

fn executable_authoring(executable: &ExecutableResource) -> Result<String, String> {
    Ok(executable.identity().to_owned())
}

fn network_authoring(network: &NetworkResource) -> Result<String, String> {
    let scheme = match network.protocol() {
        NetworkProtocol::Tcp => "tcp",
        NetworkProtocol::Udp => "udp",
    };
    let host = match network.address() {
        NetworkAddress::Ip(ip) => ip.to_string(),
        NetworkAddress::Cidr(cidr) => format!("{}/{}", cidr.address(), cidr.prefix_length()),
    };
    Ok(format!("{scheme}://{host}:{}", network.port()))
}

#[cfg(test)]
mod tests {
    use drifti_core::capability::Capability;
    use drifti_core::contract::ContractProposal;
    use drifti_core::profile::{CapabilityProfile, ProfileEntry};
    use drifti_core::resource::{FileResource, FilesystemAnchor};

    use super::proposal_document;

    #[test]
    fn proposal_stays_unaccepted_after_write_request() {
        let capability = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "src/main.rs").expect("file"),
        );
        let profile = CapabilityProfile::from_entries([ProfileEntry::new(capability, 1)]);
        let document = proposal_document(&profile).expect("document");
        let proposal = ContractProposal::generated(document);
        let request = proposal.write_request();
        assert!(!request.yaml().contains("accepted"));
        assert_eq!(proposal.document(), proposal.document());
    }
}
