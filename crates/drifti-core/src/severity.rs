// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic severity metadata for structural drift findings.
//!
//! [`classify`] maps a [`DriftFinding`] to a [`Severity`] from resource
//! sensitivity and authority shape. The result is risk metadata only: it is
//! not a policy decision, an LLM does not calculate it, and it does not mean
//! malicious, attack, theft, or breach.

use std::net::IpAddr;

use crate::capability::{Action, Capability};
use crate::drift::{DriftFinding, DriftKind, DriftResult};
use crate::resource::{
    ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkResource, Resource,
};

/// Design System severity level for a drift finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Ordinary change with limited sensitivity.
    Low,
    /// Notable sensitivity or modest authority expansion.
    Medium,
    /// Sensitive resource or configuration exposure.
    High,
    /// Highly sensitive resource or privilege-adjacent change.
    Critical,
}

impl Severity {
    /// Stable severity name from the Design System.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Resource-and-kind risk metadata. Not a policy decision and not intent.
#[must_use]
pub fn classify(finding: &DriftFinding) -> Severity {
    let Some(capability) = capability_for_band(finding) else {
        debug_assert!(false, "drift finding missing capability for severity band");
        return Severity::Low;
    };
    let mut band = capability_band(capability);
    if finding.kind() == DriftKind::Expanded && band == Severity::Low {
        band = Severity::Medium;
    }
    band
}

/// Attaches [`classify`] without changing kind or capabilities.
#[must_use]
pub fn attach(finding: DriftFinding) -> DriftFinding<Severity> {
    let severity = classify(&finding);
    finding.with_severity(severity)
}

/// Classifies every finding and re-sorts with the existing [`DriftResult::from_findings`] order.
#[must_use]
pub fn attach_result(result: &DriftResult) -> DriftResult<Severity> {
    DriftResult::from_findings(result.findings().iter().cloned().map(attach))
}

fn capability_for_band(finding: &DriftFinding) -> Option<&Capability> {
    match finding.kind() {
        DriftKind::Removed => finding.reference(),
        DriftKind::Added | DriftKind::Expanded | DriftKind::Reduced => finding.current(),
    }
}

fn capability_band(capability: &Capability) -> Severity {
    if is_critical(capability) {
        return Severity::Critical;
    }
    if is_high(capability) {
        return Severity::High;
    }
    default_band(capability)
}

fn is_critical(capability: &Capability) -> bool {
    match capability.resource() {
        Resource::File(file) => is_critical_file(capability.action(), file),
        Resource::Executable(executable) => is_critical_execute(executable),
        Resource::Network(_) => false,
    }
}

fn is_high(capability: &Capability) -> bool {
    match capability.resource() {
        Resource::File(file) => is_high_file(capability.action(), file),
        Resource::Executable(_) | Resource::Network(_) => false,
    }
}

fn default_band(capability: &Capability) -> Severity {
    match capability.resource() {
        Resource::Network(network) => {
            if network_is_loopback(network) {
                Severity::Low
            } else {
                Severity::Medium
            }
        }
        Resource::File(file) => default_file_band(capability.action(), file),
        Resource::Executable(_) => Severity::Low,
    }
}

fn is_critical_file(action: Action, file: &FileResource) -> bool {
    let base = path_base(file);
    match file.anchor() {
        FilesystemAnchor::Absolute if action == Action::FilesystemWrite => under(base, "/etc"),
        FilesystemAnchor::Home => home_is_critical(base),
        _ => false,
    }
}

fn is_high_file(action: Action, file: &FileResource) -> bool {
    let base = path_base(file);
    match file.anchor() {
        FilesystemAnchor::Home => home_is_high(base),
        FilesystemAnchor::Absolute if action == Action::FilesystemRead => under(base, "/etc"),
        _ => false,
    }
}

fn default_file_band(action: Action, file: &FileResource) -> Severity {
    if action == Action::FilesystemWrite {
        return Severity::Medium;
    }
    if file.anchor() == FilesystemAnchor::Home
        && matches!(
            action,
            Action::FilesystemRead | Action::FilesystemWrite | Action::FilesystemMetadata
        )
    {
        return Severity::Medium;
    }
    Severity::Low
}

fn home_is_critical(base: &str) -> bool {
    if under(base, ".ssh") && final_component(base).starts_with("id_") {
        return true;
    }
    if under(base, ".aws/credentials") {
        return true;
    }
    if under(base, ".kube/config") {
        return true;
    }
    under(base, ".config/gcloud") && base.contains("credential")
}

fn home_is_high(base: &str) -> bool {
    under(base, ".ssh") || under(base, ".aws") || under(base, ".gnupg") || under(base, ".kube")
}

fn is_critical_execute(executable: &ExecutableResource) -> bool {
    matches!(
        executable_basename(executable.identity()),
        "sudo" | "su" | "doas" | "pkexec"
    )
}

fn network_is_loopback(network: &NetworkResource) -> bool {
    match network.address() {
        NetworkAddress::Ip(address) => address.is_loopback(),
        NetworkAddress::Cidr(cidr) => {
            let address = cidr.address();
            if !address.is_loopback() {
                return false;
            }
            match address {
                IpAddr::V4(_) => cidr.prefix_length() >= 8,
                IpAddr::V6(_) => cidr.prefix_length() == 128,
            }
        }
    }
}

fn path_base(file: &FileResource) -> &str {
    let file_path = file.file_path();
    if file_path == "**" {
        return ".";
    }
    if file_path == "/**" {
        return "/";
    }
    if let Some((dir, tail)) = file_path.rsplit_once('/') {
        if tail == "**" && !dir.is_empty() {
            return dir;
        }
    }
    file_path
}

fn under(base: &str, prefix: &str) -> bool {
    base == prefix || base.starts_with(&format!("{prefix}/"))
}

fn final_component(base: &str) -> &str {
    base.rsplit('/').next().unwrap_or(base)
}

fn executable_basename(identity: &str) -> &str {
    identity.rsplit('/').next().unwrap_or(identity)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::capability::Capability;
    use crate::diff::diff;
    use crate::drift::{DriftFinding, DriftKind};
    use crate::resource::{
        ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource,
    };

    use super::{attach, classify, Severity};

    fn added(capability: Capability) -> DriftFinding {
        DriftFinding::added(capability)
    }

    fn removed(capability: Capability) -> DriftFinding {
        DriftFinding::removed(capability)
    }

    fn expanded(reference: Capability, current: Capability) -> DriftFinding {
        DriftFinding::expanded(reference, current)
    }

    fn reduced(reference: Capability, current: Capability) -> DriftFinding {
        DriftFinding::reduced(reference, current)
    }

    fn read(anchor: FilesystemAnchor, path: &str) -> Capability {
        Capability::filesystem_read(FileResource::new(anchor, path).expect("file"))
    }

    fn write(anchor: FilesystemAnchor, path: &str) -> Capability {
        Capability::filesystem_write(FileResource::new(anchor, path).expect("file"))
    }

    fn execute(identity: &str) -> Capability {
        Capability::process_execute(ExecutableResource::new(identity).expect("executable"))
    }

    fn connect(address: IpAddr, port: u16) -> Capability {
        Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(address),
            port,
        ))
    }

    fn assert_severity(finding: DriftFinding, expected: Severity) {
        assert_eq!(classify(&finding), expected);
    }

    #[test]
    fn severity_as_str_uses_design_system_words() {
        assert_eq!(Severity::Low.as_str(), "LOW");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        let debug = format!("{:?}", Severity::Critical);
        assert!(!debug.to_ascii_lowercase().contains("malicious"));
        assert!(!Severity::Critical
            .as_str()
            .to_ascii_lowercase()
            .contains("malicious"));
    }

    #[test]
    fn attach_preserves_kind_and_capabilities() {
        let reference = read(FilesystemAnchor::Repo, "src/**");
        let current = read(FilesystemAnchor::Repo, "./**");
        let finding = expanded(reference.clone(), current.clone());
        let marked = attach(finding);
        assert_eq!(marked.kind(), DriftKind::Expanded);
        assert_eq!(marked.reference(), Some(&reference));
        assert_eq!(marked.current(), Some(&current));
        assert_eq!(marked.severity(), Some(&Severity::Medium));
    }

    #[test]
    fn structural_diff_leaves_severity_unset() {
        let reference = read(FilesystemAnchor::Repo, "src/lib.rs");
        let current = read(FilesystemAnchor::Repo, "other.rs");
        let comparison = diff([reference], [current]);
        let findings = comparison.findings().expect("findings");
        assert!(findings
            .findings()
            .iter()
            .all(|finding| finding.severity().is_none()));
    }

    #[test]
    fn ordinary_process_execute_is_low() {
        assert_severity(added(execute("rustfmt")), Severity::Low);
        assert_severity(added(execute("/usr/bin/rustfmt")), Severity::Low);
    }

    #[test]
    fn privilege_adjacent_execute_is_critical() {
        for identity in ["sudo", "/usr/bin/sudo", "su", "doas", "pkexec"] {
            assert_severity(added(execute(identity)), Severity::Critical);
        }
    }

    #[test]
    fn network_connect_severity_follows_loopback() {
        assert_severity(
            added(connect(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443)),
            Severity::Medium,
        );
        assert_severity(
            added(connect(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)),
            Severity::Low,
        );
    }

    #[test]
    fn home_ssh_and_cloud_paths_follow_sensitivity_bands() {
        assert_severity(
            added(read(FilesystemAnchor::Home, ".ssh/config")),
            Severity::High,
        );
        assert_severity(
            added(read(FilesystemAnchor::Home, ".ssh/id_rsa")),
            Severity::Critical,
        );
        assert_severity(
            added(read(FilesystemAnchor::Home, ".aws/config")),
            Severity::High,
        );
        assert_severity(
            added(read(FilesystemAnchor::Home, ".aws/credentials")),
            Severity::Critical,
        );
        assert_severity(
            added(read(FilesystemAnchor::Home, ".kube/config")),
            Severity::Critical,
        );
    }

    #[test]
    fn absolute_etc_hosts_read_and_write() {
        assert_severity(
            added(write(FilesystemAnchor::Absolute, "/etc/hosts")),
            Severity::Critical,
        );
        assert_severity(
            added(read(FilesystemAnchor::Absolute, "/etc/hosts")),
            Severity::High,
        );
    }

    #[test]
    fn repo_expansion_and_reduction_adjust_severity() {
        let narrow = read(FilesystemAnchor::Repo, "src/**");
        let wide = read(FilesystemAnchor::Repo, "./**");
        assert_severity(expanded(narrow.clone(), wide.clone()), Severity::Medium);
        assert_severity(reduced(wide, narrow), Severity::Low);
    }

    #[test]
    fn removed_uses_reference_sensitivity() {
        assert_severity(
            removed(read(FilesystemAnchor::Home, ".ssh/id_rsa")),
            Severity::Critical,
        );
    }

    #[test]
    fn repo_paths_do_not_inherit_home_sensitivity() {
        assert_severity(
            added(read(FilesystemAnchor::Repo, "secrets/id_rsa")),
            Severity::Low,
        );
        assert_severity(
            added(read(FilesystemAnchor::Repo, "src/secret.rs")),
            Severity::Low,
        );
    }
}
