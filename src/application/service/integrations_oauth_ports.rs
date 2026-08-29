//! The OAuth credential port (hand-authored, user-owned) — the ADR-0024
//! amendment's placement rule, made concrete for the one OAuth generation.
//!
//! ADR-0024 as amended (2026-08-22) ships the fenced credential store in
//! backbone-sapiens and binds every consumer with two placement rules:
//! integration modules reach the store through a port, never a Cargo edge;
//! and the store's surface stays verb-shaped. The payment-gateway's
//! `CredentialReader` port took the amendment's "read port" phrase literally,
//! because webhook verification only ever reads. The OAuth dance is the one
//! consumer that must also MINT (issue the token bundle after the code
//! exchange) and ROTATE (refresh-before-expiry, and providers that hand back
//! a fresh refresh token on every exchange) — so this single port carries the
//! store's full verb set (issue / read_token / rotate / revoke) instead of a
//! read-only facet. The composing host binds those verbs 1:1 onto the store's
//! service; the store's placement stays swappable either way, and this module
//! imports nothing from backbone-sapiens.
//!
//! Secret discipline for the [`TokenBundle`] crossing the port:
//! - `Debug` is redacted — token material cannot drift into a log line;
//! - fields are zeroized on drop — a bundle exists only inside one verb call;
//! - no process-global cache — every read goes back through the port, so a
//!   rotation is observed immediately (ADR-0024 rule 3).
//!
//! `expires_at` is deliberately NOT optional on this port. ADR-0024 rule 2
//! (honest lifetimes) makes a "permanent" oauth_token unstoreable: the
//! provider's real `expires_in` is the only acceptable value, so the signature
//! refuses `None` by construction. The host adapter widens to the store's
//! optional `expires_at` column with `Some(..)` only.

use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::Zeroize;

/// The credential-store purpose for OAuth token material — the store's
/// `CredentialPurpose::oauth_token` variant as a plain string, so this module
/// carries no store types (the same discipline as the payment-gateway's
/// `webhook_verify` / `api_read` labels).
pub const PURPOSE_OAUTH_TOKEN: &str = "oauth_token";

/// An OAuth token bundle crossing the credential port: the access token, the
/// refresh token (absent when the provider does not return one), the honest
/// expiry derived from the provider's `expires_in`, and the granted scope.
///
/// This is the ONLY secret-bearing shape in the module. Material is private,
/// redacted in `Debug`, and zeroized on drop; accessors hand out `&str`
/// references for constructing provider requests (the token-exchange form,
/// the userinfo `Authorization` header) — never an owned copy.
pub struct TokenBundle {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: DateTime<Utc>,
    scope: Option<String>,
}

impl TokenBundle {
    /// Assemble a bundle from a verified provider token response. Callers pass
    /// `expires_at = now + expires_in`; a response without an expiry is
    /// rejected upstream as unstoreable and never reaches this constructor.
    pub fn new(
        access_token: String,
        refresh_token: Option<String>,
        expires_at: DateTime<Utc>,
        scope: Option<String>,
    ) -> Self {
        Self { access_token, refresh_token, expires_at, scope }
    }

    /// The access token — for the `Authorization` header of a provider call.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The refresh token, when the provider issued one — for the
    /// `grant_type=refresh_token` exchange form.
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The honest expiry (mirrored on the account row; drives the
    /// refresh-before-expiry window).
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// The granted scope, when the provider echoes it.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// Metadata safe for a response or log line — everything except the
    /// tokens. This is the shape HTTP surfaces may carry (the store's
    /// metadata-only rule applied at the port).
    pub fn metadata(&self) -> TokenMetadata {
        TokenMetadata { expires_at: self.expires_at, scope: self.scope.clone() }
    }
}

impl std::fmt::Debug for TokenBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted by construction — the token strings never appear.
        f.debug_struct("TokenBundle")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "[REDACTED]"))
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

impl Drop for TokenBundle {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(ref mut refresh) = self.refresh_token {
            refresh.zeroize();
        }
    }
}

/// The non-secret projection of a [`TokenBundle`] — the only token-adjacent
/// shape an HTTP response or log line may carry.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenMetadata {
    pub expires_at: DateTime<Utc>,
    pub scope: Option<String>,
}

/// Why a credential-store verb failed. A flat `{code, message}` record (the
/// payment-gateway `CredentialFetch` discipline): stable `code` strings
/// distinguish the cases, `message` carries context, and no store error type
/// crosses the port.
///
/// Failure posture of the codes:
/// - [`NotFound`](OAuthCredentialFailure::CODE_NOT_FOUND) / [`NotActive`](OAuthCredentialFailure::CODE_NOT_ACTIVE) /
///   [`Expired`](OAuthCredentialFailure::CODE_EXPIRED) — honest refusals: the scope has no
///   (readable) credential. Callers surface these, never retry them away.
/// - [`DuplicateActive`](OAuthCredentialFailure::CODE_DUPLICATE_ACTIVE) — an active credential
///   already exists for the scope; rotation is the only sanctioned replacement.
///   A second `issue` for the same scope is a caller bug.
/// - [`Transport`](OAuthCredentialFailure::CODE_TRANSPORT) — the store could not be reached;
///   the one retryable code.
#[derive(Debug, Clone, thiserror::Error)]
#[error("credential store call failed ({code}): {message}")]
pub struct OAuthCredentialFailure {
    pub code: String,
    pub message: String,
}

impl OAuthCredentialFailure {
    /// No credential was ever issued for this scope.
    pub const CODE_NOT_FOUND: &str = "not_found";
    /// The scope's credential exists but is in a terminal (non-active) status.
    pub const CODE_NOT_ACTIVE: &str = "not_active";
    /// The scope's credential passed its honest expiry (the store observes
    /// this lazily at read time).
    pub const CODE_EXPIRED: &str = "expired";
    /// An active credential already exists for the scope — rotate instead.
    pub const CODE_DUPLICATE_ACTIVE: &str = "duplicate_active";
    /// The store could not be reached — retryable.
    pub const CODE_TRANSPORT: &str = "transport";

    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.to_string(), message: message.into() }
    }

    pub fn not_found() -> Self {
        Self::new(Self::CODE_NOT_FOUND, "no credential issued for this scope")
    }

    pub fn not_active(status: &str) -> Self {
        Self::new(Self::CODE_NOT_ACTIVE, format!("credential is {status} (terminal)"))
    }

    pub fn expired() -> Self {
        Self::new(Self::CODE_EXPIRED, "credential passed its honest expiry; rotate it")
    }

    pub fn duplicate_active() -> Self {
        Self::new(Self::CODE_DUPLICATE_ACTIVE, "an active credential exists; rotate instead of issuing a second")
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self::new(Self::CODE_TRANSPORT, message)
    }

    /// The one retryable failure — the store itself was unreachable.
    pub fn is_transport(&self) -> bool {
        self.code == Self::CODE_TRANSPORT
    }
}

/// The credential-store port for the OAuth generation: the store's verb set
/// (issue / read / rotate / revoke) over edge-free types. The composing host
/// implements it as a thin adapter over the store's service verbs, scoped to
/// `purpose = oauth_token` for every read/rotate/revoke; `issue` takes the
/// purpose explicitly so the binding is visible at the call site.
///
/// All writes ride the store's rotate-lineage semantics — the module never
/// persists secret material itself, and replacement always goes through
/// [`rotate`](OAuthCredentialStore::rotate) so lineage is preserved.
#[async_trait::async_trait]
pub trait OAuthCredentialStore: Send + Sync {
    /// Store the FIRST credential for a scope (after the code exchange
    /// verifies). Rejects with
    /// [`DuplicateActive`](OAuthCredentialFailure::CODE_DUPLICATE_ACTIVE) when an active
    /// credential already exists — replacement is [`rotate`](OAuthCredentialStore::rotate),
    /// never a second issue. Returns the new credential id.
    async fn issue(
        &self,
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
        purpose: &str,
        bundle: TokenBundle,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, OAuthCredentialFailure>;

    /// Open the scope's active token bundle (the access-controlled read; the
    /// only path that ever sees token material). Refuses
    /// [`NotFound`](OAuthCredentialFailure::CODE_NOT_FOUND) / [`NotActive`](OAuthCredentialFailure::CODE_NOT_ACTIVE) /
    /// [`Expired`](OAuthCredentialFailure::CODE_EXPIRED) honestly — those are never retried away.
    async fn read_token(
        &self,
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
    ) -> Result<TokenBundle, OAuthCredentialFailure>;

    /// Replace the scope's active credential atomically: the successor is
    /// stored and the predecessor revoked with lineage preserved (the
    /// refresh-before-expiry path; also the mechanism for providers that
    /// rotate the refresh token itself). Returns the successor's id.
    async fn rotate(
        &self,
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
        bundle: TokenBundle,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, OAuthCredentialFailure>;

    /// Withdraw the scope's credential (account disconnect). Idempotent once
    /// the scope has had a credential; honest
    /// [`NotFound`](OAuthCredentialFailure::CODE_NOT_FOUND) when it never had one.
    async fn revoke(
        &self,
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
    ) -> Result<(), OAuthCredentialFailure>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> TokenBundle {
        TokenBundle::new(
            "SECRET-ACCESS-TOKEN-0123456789".into(),
            Some("SECRET-REFRESH-TOKEN-9876543210".into()),
            Utc::now() + chrono::Duration::hours(24),
            Some("https://mail.google.com/".into()),
        )
    }

    #[test]
    fn debug_never_contains_token_material() {
        let b = bundle();
        let debugged = format!("{b:?}");
        assert!(!debugged.contains("SECRET-ACCESS-TOKEN"), "access token leaked into Debug: {debugged}");
        assert!(!debugged.contains("SECRET-REFRESH-TOKEN"), "refresh token leaked into Debug: {debugged}");
        assert!(debugged.contains("[REDACTED]"), "redaction marker missing: {debugged}");
        // Non-secret fields stay visible — Debug remains diagnostic.
        assert!(debugged.contains("expires_at"), "expiry hidden, Debug no longer diagnostic: {debugged}");
    }

    #[test]
    fn accessors_hand_out_references_and_metadata_only_projection() {
        let b = bundle();
        assert_eq!(b.access_token(), "SECRET-ACCESS-TOKEN-0123456789");
        assert_eq!(b.refresh_token(), Some("SECRET-REFRESH-TOKEN-9876543210"));
        let meta = b.metadata();
        assert_eq!(meta.scope.as_deref(), Some("https://mail.google.com/"));
        let meta_debug = format!("{meta:?}");
        assert!(!meta_debug.contains("SECRET"), "metadata projection carries token material: {meta_debug}");
    }

    #[test]
    fn failure_codes_are_stable_and_distinct() {
        let codes = [
            OAuthCredentialFailure::CODE_NOT_FOUND,
            OAuthCredentialFailure::CODE_NOT_ACTIVE,
            OAuthCredentialFailure::CODE_EXPIRED,
            OAuthCredentialFailure::CODE_DUPLICATE_ACTIVE,
            OAuthCredentialFailure::CODE_TRANSPORT,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "failure codes must not collide");

        assert!(!OAuthCredentialFailure::not_found().is_transport());
        assert!(OAuthCredentialFailure::transport("store unreachable").is_transport());
        assert_eq!(OAuthCredentialFailure::duplicate_active().code, "duplicate_active");
    }

    #[test]
    fn purpose_label_matches_the_store_vocabulary() {
        // The store's CredentialPurpose variant name, as a plain string — the
        // host adapter binds this exact label.
        assert_eq!(PURPOSE_OAUTH_TOKEN, "oauth_token");
    }
}
