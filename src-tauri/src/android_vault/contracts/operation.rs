//! Closed Rust-internal mobile-bridge operation registry (FEAT-006 Phase 2).
//!
//! The Kotlin bridge exposes ONLY these typed operations, callable only through
//! the Rust-internal invocation path. No generic crypto, alias enumeration,
//! path/URI, intent, or private-key operation exists, and no Kotlin command is
//! registered as a WebView/Tauri capability. Unknown operations fail closed.

use serde::{Deserialize, Serialize};

/// Closed Android bridge operations (v1). Each maps to a bounded typed call
/// whose request/response schemas live in the shared contract vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BridgeOperation {
    /// Non-mutating capability/status probe (secure lock, hardware, class).
    QueryCapability,
    /// Create a staged wrapping key (non-exportable AES-256-GCM).
    CreateWrappingKey,
    /// Inspect key properties/security level without mutating.
    InspectWrappingKey,
    /// Wrap an inactive slot package with provider-generated nonce.
    WrapSlot,
    /// Unwrap and authenticate an active slot package.
    UnwrapSlot,
    /// Stage a rotation key and rewrap required generations transactionally.
    RotateWrappingKey,
    /// Delete the active (or abandoned staged) key after verified cleanup.
    DeleteWrappingKey,
    /// Query secure-lock and device-lock state.
    QuerySecureLock,
    /// Query boot-aware lifecycle/elapsed-time evidence.
    QueryLifecycleEvidence,
    /// Enable typed sensitive-window/recents shielding (FLAG_SECURE).
    ShieldSensitiveState,
    /// Disable typed sensitive-window shielding after the state ends.
    UnshieldSensitiveState,
    /// Bounded clipboard cleanup for copied mnemonic content.
    ClearClipboard,
    /// Start Android's system document picker for an approved import.
    OpenDocument,
    /// Start Android's system create-document picker for an approved export.
    CreateDocument,
}

impl BridgeOperation {
    /// Whether the operation mutates key/vault/platform state.
    pub fn is_mutating(self) -> bool {
        matches!(
            self,
            Self::CreateWrappingKey
                | Self::WrapSlot
                | Self::UnwrapSlot
                | Self::RotateWrappingKey
                | Self::DeleteWrappingKey
                | Self::ShieldSensitiveState
                | Self::UnshieldSensitiveState
                | Self::ClearClipboard
        )
    }

    /// Every declared operation for exhaustive matrix testing.
    pub const ALL: &'static [BridgeOperation] = &[
        BridgeOperation::QueryCapability,
        BridgeOperation::CreateWrappingKey,
        BridgeOperation::InspectWrappingKey,
        BridgeOperation::WrapSlot,
        BridgeOperation::UnwrapSlot,
        BridgeOperation::RotateWrappingKey,
        BridgeOperation::DeleteWrappingKey,
        BridgeOperation::QuerySecureLock,
        BridgeOperation::QueryLifecycleEvidence,
        BridgeOperation::ShieldSensitiveState,
        BridgeOperation::UnshieldSensitiveState,
        BridgeOperation::ClearClipboard,
        BridgeOperation::OpenDocument,
        BridgeOperation::CreateDocument,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_operations_round_trip_camel_case() {
        for op in BridgeOperation::ALL {
            let json = serde_json::to_string(op).unwrap();
            let back: BridgeOperation = serde_json::from_str(&json).unwrap();
            assert_eq!(*op, back);
        }
        assert_eq!(
            serde_json::to_string(&BridgeOperation::CreateWrappingKey).unwrap(),
            "\"createWrappingKey\""
        );
    }

    #[test]
    fn unknown_operation_is_rejected() {
        assert!(serde_json::from_str::<BridgeOperation>("\"decryptVault\"").is_err());
        assert!(serde_json::from_str::<BridgeOperation>("\"sign\"").is_err());
        assert!(serde_json::from_str::<BridgeOperation>("\"readFile\"").is_err());
    }

    #[test]
    fn mutating_classification_is_exact() {
        assert!(BridgeOperation::WrapSlot.is_mutating());
        assert!(BridgeOperation::DeleteWrappingKey.is_mutating());
        assert!(!BridgeOperation::QueryCapability.is_mutating());
        assert!(!BridgeOperation::InspectWrappingKey.is_mutating());
        assert!(!BridgeOperation::OpenDocument.is_mutating());
    }

    #[test]
    fn no_generic_operation_exists_in_registry() {
        let forbidden = [
            "sign",
            "decrypt",
            "encrypt",
            "getPrivateKey",
            "listAliases",
            "readFile",
            "writeFile",
            "openUri",
            "startActivity",
        ];
        for op in BridgeOperation::ALL {
            let name = format!("{op:?}").to_ascii_lowercase();
            for f in forbidden {
                assert!(
                    !name.contains(f),
                    "forbidden generic operation leaked: {name}"
                );
            }
        }
    }
}
