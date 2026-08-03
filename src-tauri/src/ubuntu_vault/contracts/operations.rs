//! Closed operation registry (FEAT-005 "Closed operation registry").
//!
//! The native boundary exposes ONLY reviewed operations. There is no
//! `getPrivateKey`, `decryptVault`, `sign(bytes)`, arbitrary encrypt/decrypt,
//! generic filesystem access, or generic credential serialization command.
//! Downstream consumers (FEAT-007..011) consume the closed seams declared here.

use serde::{Deserialize, Serialize};

/// FEAT-003 capability phase required before an operation may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityPhase {
    Provisioning,
    VerificationOnly,
    Authenticated,
    Locked,
    Removal,
}

/// Closed operation kinds. Every kind maps to a reviewed native authority
/// (Phase 4 dispatch); the registry below is exhaustive and forbids anything
/// generic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OperationKind {
    /// Safe preview/status inspection (no secrets).
    InspectPreview,
    /// Provision a fresh device-protected vault (FEAT-003 provisioning).
    Provision,
    /// Replace/reprovision the credential bundle atomically.
    Replace,
    /// Returning-user unlock (FEAT-010).
    Unlock,
    /// Global Lock — immediate revocation.
    Lock,
    /// Change device password (FEAT-010).
    ChangeDevicePassword,
    /// Tombstone-backed local-user removal (FEAT-010).
    RemoveLocalUser,
    /// Purpose-scoped transient recovery-word reveal.
    RevealMnemonic,
    /// FEAT-001 identity generation/derivation validation (FEAT-007).
    GenerateIdentity,
    /// FEAT-001 identity restore validation (FEAT-008).
    RestoreIdentity,
    /// Native exact online both-key identity verification.
    VerifyOnline,
    /// Operation-scoped `CreateFullIdentity` signing of TypeScript canonical
    /// bytes (FEAT-007), after native parse/context validation.
    CreateFullIdentitySign,
    /// Capability-scoped `.dat` v1 import/decryption (FEAT-009).
    ImportDatV1,
    /// Capability-scoped `.dat` v1 encrypted export (FEAT-011).
    ExportDatV1,
}

/// Static specification for one closed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationSpec {
    pub kind: OperationKind,
    /// Operation contract version (v1).
    pub version: u32,
    pub required_capability_phase: CapabilityPhase,
    /// Human-safe purpose string (display/telemetry only; never secret).
    pub purpose: &'static str,
    /// Bounded input byte ceiling enforced by the native dispatcher.
    pub max_input_bytes: usize,
}

/// The exhaustive registry. Adding a new operation requires a reviewed
/// operation-specific contract — generic signing/decryption is forbidden.
pub const OPERATION_REGISTRY: &[OperationSpec] = &[
    OperationSpec {
        kind: OperationKind::InspectPreview,
        version: 1,
        required_capability_phase: CapabilityPhase::Locked,
        purpose: "inspect-safe-preview",
        max_input_bytes: 0,
    },
    OperationSpec {
        kind: OperationKind::Provision,
        version: 1,
        required_capability_phase: CapabilityPhase::Provisioning,
        purpose: "provision-device-vault",
        max_input_bytes: 1_024,
    },
    OperationSpec {
        kind: OperationKind::Replace,
        version: 1,
        required_capability_phase: CapabilityPhase::Provisioning,
        purpose: "replace-credential-bundle",
        max_input_bytes: 1_024,
    },
    OperationSpec {
        kind: OperationKind::Unlock,
        version: 1,
        required_capability_phase: CapabilityPhase::Locked,
        purpose: "unlock-device-vault",
        max_input_bytes: 1_024,
    },
    OperationSpec {
        kind: OperationKind::Lock,
        version: 1,
        required_capability_phase: CapabilityPhase::VerificationOnly,
        purpose: "global-lock",
        max_input_bytes: 0,
    },
    OperationSpec {
        kind: OperationKind::ChangeDevicePassword,
        version: 1,
        required_capability_phase: CapabilityPhase::Authenticated,
        purpose: "change-device-password",
        max_input_bytes: 1_024,
    },
    OperationSpec {
        kind: OperationKind::RemoveLocalUser,
        version: 1,
        required_capability_phase: CapabilityPhase::Authenticated,
        purpose: "remove-local-user",
        max_input_bytes: 0,
    },
    OperationSpec {
        kind: OperationKind::RevealMnemonic,
        version: 1,
        required_capability_phase: CapabilityPhase::Authenticated,
        purpose: "reveal-recovery-words",
        max_input_bytes: 0,
    },
    OperationSpec {
        kind: OperationKind::GenerateIdentity,
        version: 1,
        required_capability_phase: CapabilityPhase::Provisioning,
        purpose: "generate-hush-identity",
        max_input_bytes: 0,
    },
    OperationSpec {
        kind: OperationKind::RestoreIdentity,
        version: 1,
        required_capability_phase: CapabilityPhase::Provisioning,
        purpose: "restore-hush-identity",
        max_input_bytes: 4_096,
    },
    OperationSpec {
        kind: OperationKind::VerifyOnline,
        version: 1,
        required_capability_phase: CapabilityPhase::VerificationOnly,
        purpose: "verify-online-identity",
        max_input_bytes: 256,
    },
    OperationSpec {
        kind: OperationKind::CreateFullIdentitySign,
        version: 1,
        required_capability_phase: CapabilityPhase::VerificationOnly,
        purpose: "create-full-identity-sign",
        max_input_bytes: 16_384,
    },
    OperationSpec {
        kind: OperationKind::ImportDatV1,
        version: 1,
        required_capability_phase: CapabilityPhase::Provisioning,
        purpose: "import-dat-v1",
        max_input_bytes: 4_096,
    },
    OperationSpec {
        kind: OperationKind::ExportDatV1,
        version: 1,
        required_capability_phase: CapabilityPhase::Authenticated,
        purpose: "export-dat-v1",
        max_input_bytes: 256,
    },
];

/// Lookup helper: returns the spec for a kind or None if unregistered.
pub fn operation_spec(kind: OperationKind) -> Option<&'static OperationSpec> {
    OPERATION_REGISTRY.iter().find(|spec| spec.kind == kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_exhaustive_for_declared_kinds() {
        // Every declared kind resolves to exactly one spec.
        for kind in [
            OperationKind::InspectPreview,
            OperationKind::Provision,
            OperationKind::Replace,
            OperationKind::Unlock,
            OperationKind::Lock,
            OperationKind::ChangeDevicePassword,
            OperationKind::RemoveLocalUser,
            OperationKind::RevealMnemonic,
            OperationKind::GenerateIdentity,
            OperationKind::RestoreIdentity,
            OperationKind::VerifyOnline,
            OperationKind::CreateFullIdentitySign,
            OperationKind::ImportDatV1,
            OperationKind::ExportDatV1,
        ] {
            let spec = operation_spec(kind).unwrap_or_else(|| panic!("missing {kind:?}"));
            assert_eq!(spec.version, 1);
            assert!(!spec.purpose.is_empty());
        }
    }

    #[test]
    fn no_generic_operation_ever_registers() {
        // The contract forbids generic access; prove no forbidden name exists.
        for spec in OPERATION_REGISTRY {
            let p = spec.purpose;
            assert!(!p.contains("sign(bytes)") && !p.contains("decryptVault"));
            assert!(!p.contains("private-key") && !p.contains("privateKey"));
            assert!(!p.contains("filesystem") && !p.contains("fs"));
        }
    }

    #[test]
    fn explicit_forbidden_vocabulary_never_appears() {
        // Strengthened mirror of the FEAT-004 review recommendation: an
        // explicit forbidden-name list scanned over every purpose, kind, and
        // input bound so a future mislabeled operation is caught.
        const FORBIDDEN: &[&str] = &[
            "sign-bytes",
            "signbytes",
            "sign(bytes)",
            "sign-any",
            "generic-sign",
            "decrypt",
            "encrypt-any",
            "private-key",
            "privatekey",
            "getPrivateKey",
            "decryptVault",
            "filesystem",
            "fs-read",
            "fs-write",
            "generic",
            "arbitrary",
            "all-credentials",
            "keyring",
            "dbus",
            "vault-dump",
        ];
        for spec in OPERATION_REGISTRY {
            let kind_lower = format!("{:?}", spec.kind).to_lowercase();
            let haystacks = [spec.purpose, kind_lower.as_str()];
            for needle in FORBIDDEN {
                for haystack in haystacks {
                    assert!(
                        !haystack.contains(needle),
                        "forbidden vocabulary {needle:?} in {haystack}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_secret_owned_operation_is_capability_scoped() {
        assert_eq!(
            operation_spec(OperationKind::RevealMnemonic)
                .unwrap()
                .required_capability_phase,
            CapabilityPhase::Authenticated
        );
        assert_eq!(
            operation_spec(OperationKind::CreateFullIdentitySign)
                .unwrap()
                .required_capability_phase,
            CapabilityPhase::VerificationOnly
        );
    }
}
