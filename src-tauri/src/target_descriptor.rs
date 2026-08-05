//! FEAT-010 trusted runtime-target descriptor.
//!
//! ONE narrow Rust-owned startup command returns a safe closed descriptor
//! that JavaScript validates against the deployment manifest before any
//! registration (FeatureDescription "Trusted runtime-target handshake",
//! AC-010-005/006). Platform derives from the compiled target; user agent,
//! environment text, page input, trial loading, or endpoint reachability
//! never selects the platform. A failed/incompatible descriptor fails closed
//! and never falls back to Browser storage or BFF transport.

use serde::{Deserialize, Serialize};

/// Closed native capability classes (must match the TS allowlist).
pub const CAPABILITY_SECRET_SERVICE: &str = "secret-service";
pub const CAPABILITY_ANDROID_KEYSTORE: &str = "android-keystore";
pub const CAPABILITY_NATIVE_TRANSPORT: &str = "native-transport";
pub const CAPABILITY_NATIVE_LIFECYCLE: &str = "native-lifecycle";

/// Adapter contract version exchanged with the deployment manifest
/// (must equal `contractVersions.adapter` in the approved manifests).
pub const ADAPTER_CONTRACT_VERSION: &str = "1.0.0";

/// Deployment configuration the build is compiled for.
pub const DEPLOYMENT_CONFIGURATION_ID: &str = "isolated-local-devnet-v1";

/// Safe closed descriptor (no secrets, no endpoints, no paths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeTargetDescriptor {
    /// `ubuntu` or `android` — derived from the compiled target.
    pub platform: &'static str,
    /// Application/build identity (digest-able, non-secret).
    pub build_identity: String,
    /// Exact adapter contract version.
    pub adapter_contract_version: &'static str,
    /// Available qualified capability classes.
    pub capability_classes: Vec<&'static str>,
    /// Deployment configuration identifier this build targets.
    pub deployment_configuration_id: &'static str,
}

/// Compiled-target platform truth.
#[cfg(target_os = "linux")]
const PLATFORM: &str = "ubuntu";
#[cfg(any(target_os = "android", target_os = "ios"))]
const PLATFORM: &str = "android";
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "ios")))]
const PLATFORM: &str = "unsupported";

/// Qualified capability classes for the compiled target.
fn capability_classes() -> Vec<&'static str> {
    #[cfg(target_os = "linux")]
    {
        vec![
            CAPABILITY_SECRET_SERVICE,
            CAPABILITY_NATIVE_TRANSPORT,
            CAPABILITY_NATIVE_LIFECYCLE,
        ]
    }
    #[cfg(target_os = "android")]
    {
        vec![
            CAPABILITY_ANDROID_KEYSTORE,
            CAPABILITY_NATIVE_TRANSPORT,
            CAPABILITY_NATIVE_LIFECYCLE,
        ]
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        vec![]
    }
}

/// Build identity: package version + revision tag (non-secret).
fn build_identity() -> String {
    format!(
        "hush-voting-app-{}-{}",
        env!("CARGO_PKG_VERSION"),
        option_env!("HUSH_BUILD_REVISION").unwrap_or("dev")
    )
}

/// The one trusted startup descriptor command.
#[tauri::command]
pub fn native_target_descriptor() -> Result<NativeTargetDescriptor, String> {
    if PLATFORM == "unsupported" {
        // Fail closed on unknown compiled targets.
        return Err("unsupported-native-target".into());
    }
    Ok(NativeTargetDescriptor {
        platform: PLATFORM,
        build_identity: build_identity(),
        adapter_contract_version: ADAPTER_CONTRACT_VERSION,
        capability_classes: capability_classes(),
        deployment_configuration_id: DEPLOYMENT_CONFIGURATION_ID,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_is_closed_and_serializable() {
        // Build the descriptor the way the command does (platform may be
        // ubuntu or unsupported depending on the test host).
        if PLATFORM == "unsupported" {
            return;
        }
        let descriptor = NativeTargetDescriptor {
            platform: PLATFORM,
            build_identity: build_identity(),
            adapter_contract_version: ADAPTER_CONTRACT_VERSION,
            capability_classes: capability_classes(),
            deployment_configuration_id: DEPLOYMENT_CONFIGURATION_ID,
        };
        let json = serde_json::to_string(&descriptor).expect("serializable");
        assert!(json.contains("\"platform\""));
        assert!(json.contains("\"capabilityClasses\""));
        // No credential/endpoint/path-shaped content (the allowlisted
        // "secret-service" class name is the only 'secret' occurrence).
        assert!(!json.contains("\"secret\""));
        assert!(!json.contains("password"));
        assert!(!json.contains("mnemonic"));
        assert!(!json.contains("http"));
        assert!(!json.contains('/'));
    }

    #[test]
    fn capability_classes_are_allowlisted() {
        for class in capability_classes() {
            assert!(
                matches!(
                    class,
                    CAPABILITY_SECRET_SERVICE
                        | CAPABILITY_ANDROID_KEYSTORE
                        | CAPABILITY_NATIVE_TRANSPORT
                        | CAPABILITY_NATIVE_LIFECYCLE
                ),
                "unknown class {class}"
            );
        }
    }
}
