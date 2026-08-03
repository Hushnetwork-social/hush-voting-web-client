//! Native online identity verification transport (FEAT-005 "Online Identity
//! Verification and Transport", "Pinned Rust gRPC client").
//!
//! After local decryption, Rust remains `VerificationOnly` and: uses safe
//! public signing/encryption addresses; resolves an approved endpoint
//! configuration identifier; performs public identity lookup through the
//! narrow native transport; validates profile existence and exact both-key
//! equality; and promotes the epoch to `Authenticated` only on current exact
//! match. The WebView cannot send `verified: true`, fabricate a profile
//! response, or trust locked preview metadata. Connectivity timeout/failure
//! remains distinct from password failure.
//!
//! Endpoints are a closed vocabulary — runtime URLs are impossible. Cleartext
//! endpoints exist only in explicit development composition; test fixtures
//! cannot enter release composition. Verification is bounded by
//! `ONLINE_VERIFY_BOUND_SECS` (FEAT-002 contract).

use std::time::Duration;

use crate::ubuntu_vault::session::SessionIdentity;

/// Bounded online verification timeout (FEAT-002 contract, seconds).
pub const ONLINE_VERIFY_BOUND_SECS: u64 = crate::ubuntu_vault::ONLINE_VERIFY_BOUND_SECS;

/// Build composition (which endpoint identifiers are allowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Composition {
    Production,
    Development,
    Test,
}

/// Closed endpoint identifiers — never arbitrary URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointId {
    ProductionHushNetwork,
    DevelopmentLocalhost,
    TestFixture,
}

/// Resolved endpoint (closed vocabulary; no caller-supplied URL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    url: String,
    /// True only for TLS endpoints (production).
    tls: bool,
}

impl Endpoint {
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn is_tls(&self) -> bool {
        self.tls
    }
}

/// Closed transport failure vocabulary (never raw gRPC/TLS detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    UnapprovedEndpoint,
    CleartextInProduction,
    Timeout,
    Unavailable,
    ProfileUnavailable,
}

impl TransportFailure {
    pub fn to_native_error(self) -> crate::ubuntu_vault::contracts::results::NativeErrorCode {
        use crate::ubuntu_vault::contracts::results::NativeErrorCode;
        match self {
            Self::UnapprovedEndpoint | Self::CleartextInProduction => {
                NativeErrorCode::OperationForbidden
            }
            Self::Timeout | Self::Unavailable => NativeErrorCode::NetworkTimeout,
            Self::ProfileUnavailable => NativeErrorCode::ProfileNotFound,
        }
    }
}

/// Resolve a closed endpoint identifier for the given composition.
/// Production resolves ONLY to the approved TLS endpoint; cleartext and test
/// endpoints cannot enter production composition.
pub fn resolve_endpoint(
    id: EndpointId,
    composition: Composition,
) -> Result<Endpoint, TransportFailure> {
    match (id, composition) {
        (EndpointId::ProductionHushNetwork, _) => Ok(Endpoint {
            url: "https://api.hushnetwork.social".to_string(),
            tls: true,
        }),
        (EndpointId::DevelopmentLocalhost, Composition::Development) => Ok(Endpoint {
            url: "http://localhost:4666".to_string(),
            tls: false,
        }),
        (EndpointId::DevelopmentLocalhost, Composition::Production) => {
            Err(TransportFailure::CleartextInProduction)
        }
        (EndpointId::TestFixture, Composition::Test) => Ok(Endpoint {
            url: "https://test-fixture.invalid".to_string(),
            tls: true,
        }),
        (EndpointId::TestFixture, Composition::Production | Composition::Development) => {
            Err(TransportFailure::UnapprovedEndpoint)
        }
        (EndpointId::DevelopmentLocalhost, Composition::Test) => {
            Err(TransportFailure::UnapprovedEndpoint)
        }
    }
}

/// A public identity profile returned by the identity service (safe public
/// fields only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicProfile {
    pub display_name: String,
    pub signing_address: String,
    pub encrypt_address: String,
    pub is_public: bool,
}

/// Narrow identity-lookup seam. Implemented by the tonic gRPC client; tests
/// use deterministic doubles (no session bus, no network).
///
/// `async fn` in a trait is used only with generic (monomorphized) bounds —
/// never through `dyn` — so the missing auto-trait specification is
/// irrelevant; concrete futures carry their own bounds.
#[allow(async_fn_in_trait)]
pub trait IdentityLookup {
    /// Look up a public profile by its signing address. `Ok(None)` when the
    /// profile does not exist.
    async fn get_identity(
        &mut self,
        signing_address: &str,
    ) -> Result<Option<PublicProfile>, TransportFailure>;
}

/// Exact both-key verification: the profile must exist, be public, and BOTH
/// keys must match exactly (case-insensitive hex). Never trusts `verified`
/// fields from the WebView.
pub fn verify_both_keys(local: &SessionIdentity, remote: Option<&PublicProfile>) -> bool {
    match remote {
        Some(profile) => {
            profile.is_public
                && profile
                    .signing_address
                    .eq_ignore_ascii_case(&local.signing_address)
                && profile
                    .encrypt_address
                    .eq_ignore_ascii_case(&local.encrypt_address)
        }
        None => false,
    }
}

/// Bounded online verifier: performs the lookup under the FEAT-002 timeout
/// and reports exact both-key match only.
pub struct OnlineVerifier {
    timeout: Duration,
}

impl Default for OnlineVerifier {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(ONLINE_VERIFY_BOUND_SECS),
        }
    }
}

impl OnlineVerifier {
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Verify under the bound. `Ok(true)` only on exact both-key match of an
    /// existing public profile; timeouts and transport loss return closed
    /// failures distinct from password failure.
    pub async fn verify(
        &self,
        lookup: &mut impl IdentityLookup,
        local: &SessionIdentity,
    ) -> Result<bool, TransportFailure> {
        let found = tokio::time::timeout(self.timeout, lookup.get_identity(&local.signing_address))
            .await
            .map_err(|_| TransportFailure::Timeout)??;
        Ok(verify_both_keys(local, found.as_ref()))
    }
}

/// Safe promotion decision for the session authority: promotion happens ONLY
/// after exact both-key match (never from WebView state).
pub fn promotion_allowed(local: &SessionIdentity, remote: Option<&PublicProfile>) -> bool {
    verify_both_keys(local, remote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::session::SessionIdentity;

    fn local_identity() -> SessionIdentity {
        SessionIdentity {
            signing_address: "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5"
                .to_string(),
            encrypt_address: "032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556"
                .to_string(),
        }
    }

    fn profile(public: bool) -> PublicProfile {
        PublicProfile {
            display_name: "Alice".to_string(),
            signing_address: "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5"
                .to_string(),
            encrypt_address: "032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556"
                .to_string(),
            is_public: public,
        }
    }

    #[test]
    fn endpoints_are_a_closed_vocabulary() {
        let prod =
            resolve_endpoint(EndpointId::ProductionHushNetwork, Composition::Production).unwrap();
        assert_eq!(prod.url(), "https://api.hushnetwork.social");
        assert!(prod.is_tls());
        // Cleartext cannot enter production.
        assert_eq!(
            resolve_endpoint(EndpointId::DevelopmentLocalhost, Composition::Production),
            Err(TransportFailure::CleartextInProduction)
        );
        // Test fixture only in test composition.
        assert_eq!(
            resolve_endpoint(EndpointId::TestFixture, Composition::Production),
            Err(TransportFailure::UnapprovedEndpoint)
        );
        assert!(
            resolve_endpoint(EndpointId::DevelopmentLocalhost, Composition::Development).is_ok()
        );
        assert!(resolve_endpoint(EndpointId::TestFixture, Composition::Test).is_ok());
    }

    #[test]
    fn only_exact_both_key_match_authenticates() {
        let local = local_identity();
        assert!(verify_both_keys(&local, Some(&profile(true))));
        assert!(
            !verify_both_keys(&local, Some(&profile(false))),
            "non-public"
        );
        assert!(!verify_both_keys(&local, None), "missing profile");
        let mut signing_mismatch = profile(true);
        signing_mismatch.signing_address = "03".repeat(33);
        assert!(!verify_both_keys(&local, Some(&signing_mismatch)));
        let mut encrypt_mismatch = profile(true);
        encrypt_mismatch.encrypt_address = "02".repeat(33);
        assert!(!verify_both_keys(&local, Some(&encrypt_mismatch)));
    }

    #[tokio::test]
    async fn verifier_bounds_the_lookup() {
        // Timeout-bound: a never-answering lookup returns Timeout.
        struct HangLookup;
        impl IdentityLookup for HangLookup {
            async fn get_identity(
                &mut self,
                _: &str,
            ) -> Result<Option<PublicProfile>, TransportFailure> {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                Ok(None)
            }
        }
        let verifier = OnlineVerifier::with_timeout(std::time::Duration::from_millis(20));
        let result = verifier.verify(&mut HangLookup, &local_identity()).await;
        assert_eq!(result, Err(TransportFailure::Timeout));
    }

    struct FakeLookup {
        reply: Result<Option<PublicProfile>, TransportFailure>,
    }
    impl IdentityLookup for FakeLookup {
        async fn get_identity(
            &mut self,
            _: &str,
        ) -> Result<Option<PublicProfile>, TransportFailure> {
            self.reply.clone()
        }
    }

    #[tokio::test]
    async fn both_key_matrix_runs() {
        let local = local_identity();
        let cases: Vec<(Result<Option<PublicProfile>, TransportFailure>, bool)> = vec![
            (Ok(Some(profile(true))), true),
            (Ok(Some(profile(false))), false),
            (Ok(None), false),
            (Err(TransportFailure::ProfileUnavailable), false),
            (Err(TransportFailure::Unavailable), false),
        ];
        for (reply, expected) in cases {
            let verifier = OnlineVerifier::default();
            let result = verifier
                .verify(&mut FakeLookup { reply }, &local)
                .await
                .unwrap_or(false);
            assert_eq!(result, expected);
        }
    }
}
