//! The one OAuth generation (hand-authored, user-owned) — the core flow.
//!
//! ONE HMAC-bound flow serves every provider (gmail / outlook mail, Google /
//! Microsoft calendar): an authenticated initiation mints a Tier-A state that
//! is signature-bound to the account row, the provider redirect target is a
//! SIDE-EFFECT-FREE page that auto-POSTs the code home (the RFC-8058 shape —
//! a safe method never writes), and the completion re-verifies the state,
//! exchanges the code at a VALIDATED endpoint, and runs the identity gauntlet
//! (audience, nonce, email match) before any token is stored. Providers
//! differ only in adapter data carried by the endpoint guard's registry —
//! there is no per-provider flow code, and no legacy public-callback route
//! exists anywhere on the surface.
//!
//! Secret placement (the credential-store ADR, as amended): token material
//! crosses only the [`OAuthCredentialStore`] port — the module never persists
//! a secret, and reaches the store with zero Cargo edge to its home crate.
//! Lifetimes are honest everywhere: a provider response without `expires_in`
//! is rejected as unstoreable, and a stored bundle's `expires_at` is
//! `now + expires_in`, mirrored on the account row.
//!
//! The account row is flow bookkeeping only (binding, lifecycle, the expiry
//! mirror, and the transient PKCE verifier, which lives solely while the
//! authorization is pending and is cleared the moment the exchange consumes
//! it). Its lifecycle is one hand_set enum: pending → active | revoked,
//! active → expired | revoked, with expired/revoked terminal — a
//! re-authorization replaces the row rather than un-terminal-ing it.

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use tracing::warn;
use uuid::Uuid;

use backbone_orm::company_scope;

use crate::application::service::integrations_oauth_ports::{
    OAuthCredentialFailure, OAuthCredentialStore, PURPOSE_OAUTH_TOKEN, TokenBundle,
};
use crate::infrastructure::http::{
    EndpointOverrides, OAuthClientConfigs, OAuthTransport, ProviderRegistry, TokenRequestForm,
    TransportFailure, ValidatedEndpoints,
};

/// How long a minted state stays verifiable (seconds). Tier-A capability
/// rule: mandatory expiry, short by construction.
pub const STATE_TTL_SECONDS: i64 = 600;

/// The environment variable the state-signing key is read from — the key is
/// never a file value and never a config-file value.
pub const DEFAULT_STATE_SECRET_ENV: &str = "INTEGRATIONS_OAUTH_STATE_SECRET";

/// The fixed callback path (appended to the deployment's public base to build
/// the OAuth `redirect_uri`; the browser lands here after consent).
pub const CALLBACK_PATH: &str = "/api/v1/integrations/oauth/callback";

/// Where the callback page auto-POSTs the code — the SAME mount as the
/// callback, one level up. Relative, so the flow works under whatever prefix
/// the composing host mounted the module's routes at.
pub const COMPLETE_ACTION: &str = "complete";

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// The `oauth:` configuration section (module-local, non-secret). Endpoint
/// overrides and client ids live here; the state-signing key comes from the
/// environment named by `state_secret_source`; a client secret, when a
/// deployment runs a confidential client, is supplied out-of-band and never
/// committed in this file.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct IntegrationsOauthConfig {
    /// Deployment base for the OAuth `redirect_uri` (e.g. `https://api.example.com`).
    pub public_base: Option<String>,
    /// Per-provider OAuth client registrations (the `oauth.clients` section).
    pub clients: OAuthClientConfigs,
    /// Per-provider endpoint overrides (the `oauth.endpoints` section) — empty
    /// by default (registry values); every value passes the endpoint guard at
    /// build time AND per request.
    pub endpoints: EndpointOverrides,
    /// Refresh before expiry by this many seconds.
    pub refresh_window_seconds: i64,
    /// Upper bound on accounts refreshed in one sweep.
    pub refresh_batch_size: i64,
    /// Declared admin bypass for the identity email match (shared mailboxes a
    /// system operator legitimately relays). Default OFF; every use is logged.
    pub shared_mailbox_bypass: bool,
    /// Where the state-signing key comes from — an environment variable
    /// (`env:NAME`); any other shape is refused.
    pub state_secret_source: String,
}

impl Default for IntegrationsOauthConfig {
    fn default() -> Self {
        Self {
            public_base: None,
            clients: OAuthClientConfigs::default(),
            endpoints: EndpointOverrides::default(),
            refresh_window_seconds: 600,
            refresh_batch_size: 100,
            shared_mailbox_bypass: false,
            state_secret_source: format!("env:{DEFAULT_STATE_SECRET_ENV}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Why an OAuth-flow call failed. Every rejection path leaves ZERO writes:
/// the account stays pending, the store is untouched.
#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("state rejected: {0}")]
    State(String),
    #[error("provider not configured: {0}")]
    ProviderUnconfigured(String),
    #[error("account not found")]
    NotFound,
    #[error("identity verification failed: {0}")]
    Identity(String),
    #[error("unstoreable token: {0}")]
    Unstoreable(String),
    #[error("provider transport: {0}")]
    Transport(String),
    #[error("credential store: {0}")]
    Store(String),
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// The Tier-A state (mint / verify)
// ─────────────────────────────────────────────────────────────────────────────

/// What the signed state binds: the account the authorization is FOR, the
/// provider it runs against, a fresh nonce, and a mandatory expiry. Payload
/// is visible-but-unforgeable (signed, not encrypted) — it carries no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthState {
    account_id: Uuid,
    provider: String,
    nonce: String,
    exp: i64,
}

/// HMAC-SHA256 over the payload bytes; comparison is constant-time and expiry
/// is mandatory. A tampered, flipped-byte, or expired state is refused before
/// ANY database read or write.
struct StateSigner {
    key: Vec<u8>,
}

impl StateSigner {
    fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    fn mint(&self, state: &OAuthState) -> Result<String, OauthError> {
        let payload = serde_json::to_vec(state)
            .map_err(|e| OauthError::State(format!("state serialization: {e}")))?;
        let mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("hmac accepts any key length")
            .chain_update(&payload)
            .finalize()
            .into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(mac)
        ))
    }

    fn verify(&self, token: &str) -> Result<OAuthState, OauthError> {
        let (payload_b64, mac_b64) = token
            .split_once('.')
            .ok_or_else(|| OauthError::State("malformed state".into()))?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| OauthError::State("malformed state payload".into()))?;
        let presented = URL_SAFE_NO_PAD
            .decode(mac_b64)
            .map_err(|_| OauthError::State("malformed state signature".into()))?;
        let expected = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("hmac accepts any key length")
            .chain_update(&payload)
            .finalize()
            .into_bytes();
        // Constant-time comparison — a flipped byte must not become an oracle.
        if presented.len() != expected.len() || bool::from(presented.ct_eq(&expected)) == false {
            return Err(OauthError::State("state signature mismatch".into()));
        }
        let state: OAuthState = serde_json::from_slice(&payload)
            .map_err(|_| OauthError::State("state payload is not a valid binding".into()))?;
        if state.exp <= Utc::now().timestamp() {
            return Err(OauthError::State("state expired".into()));
        }
        Ok(state)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PKCE + nonce material
// ─────────────────────────────────────────────────────────────────────────────

/// A fresh PKCE S256 code verifier (43–128 chars per the spec; 48 random
/// bytes → 64 url-safe chars). Single-use: stored on the pending account,
/// consumed by exactly one exchange, then cleared.
fn mint_pkce_verifier() -> String {
    let mut bytes = [0u8; 48];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The S256 challenge for a verifier (base64url(SHA-256(verifier))).
fn pkce_challenge(verifier: &str) -> String {
    use sha2::Digest;
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A fresh 128-bit nonce for the state binding.
fn mint_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Row shapes (plain strings; enum casts live in the SQL)
// ─────────────────────────────────────────────────────────────────────────────

/// One account row as the flow reads it — no enum types (the SQL casts
/// `$n::o_auth_provider` / selects `provider::text`), so runtime-bound
/// parameters resolve against the named Postgres types.
#[derive(Debug, sqlx::FromRow)]
pub struct AccountRow {
    pub id: Uuid,
    pub company_id: Uuid,
    pub provider: String,
    pub account_ref: String,
    pub status: String,
    pub scopes: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_refreshed_at: Option<DateTime<Utc>>,
}

/// Metadata-only account projection — the only account shape an HTTP
/// response carries.
#[derive(Debug, Clone, Serialize)]
pub struct AccountStatus {
    pub account_id: Uuid,
    pub provider: String,
    pub account_ref: String,
    pub status: String,
    pub scopes: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_refreshed_at: Option<DateTime<Utc>>,
}

impl From<AccountRow> for AccountStatus {
    fn from(r: AccountRow) -> Self {
        Self {
            account_id: r.id,
            provider: r.provider,
            account_ref: r.account_ref,
            status: r.status,
            scopes: r.scopes,
            expires_at: r.expires_at,
            last_refreshed_at: r.last_refreshed_at,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request / response shapes
// ─────────────────────────────────────────────────────────────────────────────

/// Start an authorization. `account_ref` is the provider-side identity this
/// connection claims (the mailbox address for mail providers).
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub provider: String,
    pub account_ref: String,
    pub scopes: Option<String>,
}

/// The authorize response — where to send the browser, and how long the
/// binding lives. No secrets.
#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub account_id: Uuid,
    pub authorize_url: String,
    pub state_expires_in: i64,
}

/// Complete an authorization with the code the provider handed back.
#[derive(Debug, Deserialize)]
pub struct CompleteRequest {
    pub code: String,
    pub state: String,
}

/// The completion outcome — metadata only; token material never crosses HTTP.
#[derive(Debug, Serialize)]
pub struct CompleteOutcome {
    pub account_id: Uuid,
    pub provider: String,
    pub account_ref: String,
    pub status: String,
    pub scopes: String,
    pub expires_at: DateTime<Utc>,
}

/// One sweep's counters (the request-path lazy refresh reports the same
/// shape for its single account).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RefreshSummary {
    pub refreshed: usize,
    /// Due by the mirror, but the store's bundle is still fresh (another
    /// runner rotated first) — the mirror was re-synced, nothing exchanged.
    pub resynced: usize,
    pub expired: usize,
    pub failures: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// The service
// ─────────────────────────────────────────────────────────────────────────────

/// The one OAuth generation service. Built once (config validated at build —
/// a bad endpoint override or a missing state secret refuses construction),
/// holding the resolved-and-validated endpoints per provider, the Tier-A
/// state signer, and the two ports (credential store + outbound transport)
/// the flow runs through.
pub struct IntegrationsOauthService {
    pool: PgPool,
    registry: ProviderRegistry,
    endpoints: HashMap<String, ValidatedEndpoints>,
    clients: OAuthClientConfigs,
    signer: StateSigner,
    public_base: String,
    refresh_window: Duration,
    refresh_batch_size: i64,
    shared_mailbox_bypass: bool,
    transport: Arc<dyn OAuthTransport>,
    store: Arc<dyn OAuthCredentialStore>,
}

impl IntegrationsOauthService {
    /// Validate configuration and construct the service. FAIL CLOSED: an
    /// unusable `state_secret_source`, a missing `public_base`, or ANY
    /// endpoint override the guard refuses is a build error — there is no
    /// degraded mode that skips the guard.
    pub fn build(
        pool: PgPool,
        config: IntegrationsOauthConfig,
        transport: Arc<dyn OAuthTransport>,
        store: Arc<dyn OAuthCredentialStore>,
    ) -> anyhow::Result<Self> {
        let state_secret_source = config.state_secret_source.trim().to_string();
        let var_name = state_secret_source
            .strip_prefix("env:")
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "oauth.state_secret_source must name an environment variable (env:NAME), got {state_secret_source:?} — a file value is never accepted"
                )
            })?
            .trim()
            .to_string();
        if var_name.is_empty() {
            return Err(anyhow::anyhow!("oauth.state_secret_source names no variable"));
        }
        let secret = std::env::var(&var_name).map_err(|_| {
            anyhow::anyhow!("environment variable {var_name} (the OAuth state-signing key) is not set")
        })?;
        if secret.len() < 32 {
            return Err(anyhow::anyhow!(
                "environment variable {var_name} must hold at least 32 bytes (an HMAC-SHA256 key)"
            ));
        }

        let public_base = config
            .public_base
            .as_deref()
            .map(str::trim)
            .map(trim_trailing_slash)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("oauth.public_base is required (the OAuth redirect_uri base)"))?;

        let registry = ProviderRegistry::with_builtin();
        // Every provider's endpoints resolve-and-validate NOW: registry value
        // or override, the same rule set. A bad override anywhere means no
        // module — deny by default, not per-request degradation.
        let mut endpoints = HashMap::new();
        for provider in registry.providers() {
            let resolved = ValidatedEndpoints::resolve(&registry, provider, &config.endpoints)
                .map_err(|e| anyhow::anyhow!("oauth endpoint configuration refused: {e}"))?;
            endpoints.insert(provider.to_string(), resolved);
        }

        Ok(Self {
            pool,
            registry,
            endpoints,
            clients: config.clients,
            signer: StateSigner::new(secret.into_bytes()),
            public_base,
            refresh_window: Duration::seconds(config.refresh_window_seconds.max(0)),
            refresh_batch_size: config.refresh_batch_size.max(1),
            shared_mailbox_bypass: config.shared_mailbox_bypass,
            transport,
            store,
        })
    }

    fn endpoints_for(&self, provider: &str) -> Result<(&ValidatedEndpoints, String), OauthError> {
        let resolved = self
            .endpoints
            .get(provider)
            .ok_or_else(|| OauthError::ProviderUnconfigured(format!("unknown provider {provider:?}")))?;
        let client_id = self
            .clients
            .get(provider)
            .map(|c| c.client_id.clone())
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| OauthError::ProviderUnconfigured(format!("no OAuth client configured for {provider}")))?;
        Ok((resolved, client_id))
    }

    fn redirect_uri(&self) -> String {
        format!("{}{}", self.public_base, CALLBACK_PATH)
    }

    // ── 1. authorize ────────────────────────────────────────────────────────

    /// Start ONE authorization through the ONE flow. Validates the claimed
    /// provider-side identity, replaces any existing row for the scope with a
    /// FRESH pending account (terminal statuses are never transitioned out
    /// of), mints the PKCE verifier + Tier-A state, and returns the provider
    /// authorize URL. Zero store contact on this path.
    pub async fn authorize(
        &self,
        company_id: Uuid,
        req: AuthorizeRequest,
    ) -> Result<AuthorizeResponse, OauthError> {
        let provider = req.provider.trim().to_string();
        let adapter = self
            .registry
            .lookup(&provider)
            .ok_or_else(|| OauthError::Invalid(format!("unknown provider {provider:?}")))?;
        let (endpoints, client_id) = self.endpoints_for(&provider)?;

        let account_ref = normalize_account_ref(&req.account_ref)
            .ok_or_else(|| OauthError::Invalid("account_ref must be 3..=120 chars without whitespace".into()))?;
        if is_mail_provider(&provider) && !looks_like_email(&account_ref) {
            return Err(OauthError::Invalid(format!(
                "account_ref for {provider} must be the mailbox address (a valid email)"
            )));
        }

        let scopes = req
            .scopes
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| adapter.default_scopes.to_string());
        if scopes.len() > 2048 || scopes.chars().any(|c| c.is_control()) {
            return Err(OauthError::Invalid("scopes must be <= 2048 chars, no control characters".into()));
        }

        // Fresh pending row: replace-on-reauthorize (a terminal row is deleted,
        // never resurrected). The PKCE verifier rides the pending row — the
        // state's account binding is what makes it recoverable.
        let verifier = if adapter.pkce_s256 { Some(mint_pkce_verifier()) } else { None };
        let account_id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;
        company_scope::bind_company_on(&mut tx, company_id).await?;
        sqlx::query(
            "DELETE FROM integrations.integration_accounts
              WHERE company_id = $1 AND provider = $2::o_auth_provider AND account_ref = $3",
        )
        .bind(company_id)
        .bind(&provider)
        .bind(&account_ref)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO integrations.integration_accounts
                 (id, company_id, provider, account_ref, status, scopes, pkce_verifier)
             VALUES ($1, $2, $3::o_auth_provider, $4, 'pending', $5, $6)",
        )
        .bind(account_id)
        .bind(company_id)
        .bind(&provider)
        .bind(&account_ref)
        .bind(&scopes)
        .bind(&verifier)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        // The nonce rides BOTH channels: into the signed state (compared at
        // completion) and into the authorize request (echoed by the provider
        // inside the id_token — the echo is the proof the token was minted
        // for THIS authorization, not replayed). Omitting the request pair
        // while requiring the echo would make completion unreachable against
        // every real provider.
        let nonce = mint_nonce();
        let state = self.signer.mint(&OAuthState {
            account_id,
            provider: provider.clone(),
            nonce: nonce.clone(),
            exp: Utc::now().timestamp() + STATE_TTL_SECONDS,
        })?;

        // The authorize URL — built ONLY from the validated endpoint (the
        // `Url` type is reqwest's re-export; no extra dependency).
        let mut url = reqwest::Url::parse(endpoints.authorize.as_str())
            .map_err(|e| OauthError::Invalid(format!("authorize endpoint: {e}")))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("response_type", "code");
            pairs.append_pair("client_id", &client_id);
            pairs.append_pair("redirect_uri", &self.redirect_uri());
            pairs.append_pair("scope", &scopes);
            // One flow, uniform parameters: offline access + forced consent so
            // the provider issues a refresh token; providers that don't use
            // them ignore them.
            pairs.append_pair("access_type", "offline");
            pairs.append_pair("prompt", "consent");
            if let Some(v) = verifier.as_deref() {
                pairs.append_pair("code_challenge", &pkce_challenge(v));
                pairs.append_pair("code_challenge_method", "S256");
            }
            pairs.append_pair("nonce", &nonce);
            pairs.append_pair("state", &state);
        }

        Ok(AuthorizeResponse { account_id, authorize_url: url.to_string(), state_expires_in: STATE_TTL_SECONDS })
    }

    // ── 2. callback (side-effect-free by construction) ─────────────────────

    /// Render the provider redirect target: verify the state (constant-time,
    /// mandatory expiry) and return a minimal HTML page that auto-submits an
    /// invisible POST form carrying `code` + `state` to the completion route.
    /// A SAFE METHOD: this writes nothing, mints nothing, transitions nothing
    /// — a GET here cannot change a single row. Garbage / tampered / expired
    /// state → rejection, still zero writes. The form target is RELATIVE, so
    /// no state-supplied (or any other) URL is ever redirected to.
    pub fn callback_page(&self, code: &str, state: &str) -> Result<String, OauthError> {
        if code.trim().is_empty() {
            return Err(OauthError::Invalid("callback is missing the authorization code".into()));
        }
        // Verify-only: no DB read, no DB write, no store call.
        self.signer.verify(state)?;
        Ok(auto_post_page(COMPLETE_ACTION, &[("code", code), ("state", state)]))
    }

    // ── 3. complete (the gauntlet) ──────────────────────────────────────────

    /// Complete an authorization: re-verify the state, exchange the code at
    /// the VALIDATED token endpoint (PKCE verifier from the pending account),
    /// then run the identity gauntlet — audience == configured client id,
    /// id_token nonce == the nonce minted into the signed state, and the
    /// provider-side identity must match the claimed `account_ref`. Only
    /// then is the bundle stored (honest expiry, never NULL) and the account
    /// transitioned pending → active. ANY rejection leaves zero writes.
    pub async fn complete(
        &self,
        company_id: Uuid,
        req: CompleteRequest,
    ) -> Result<CompleteOutcome, OauthError> {
        let state = self.signer.verify(&req.state)?;
        let account = self
            .fetch_account(company_id, state.account_id)
            .await?
            .ok_or(OauthError::NotFound)?;
        if account.provider != state.provider {
            return Err(OauthError::State("state provider does not match the account".into()));
        }
        if account.status != "pending" {
            return Err(OauthError::State(format!(
                "account is {} (only a pending authorization can complete)",
                account.status
            )));
        }

        let provider = account.provider.clone();
        let account_ref = account.account_ref.clone();
        let adapter = self
            .registry
            .lookup(&provider)
            .ok_or_else(|| OauthError::ProviderUnconfigured(provider.clone()))?;
        let (endpoints, client_id) = self.endpoints_for(&provider)?;

        // The exchange form. The PKCE verifier comes from the pending account
        // row (the state's binding makes it recoverable server-side only).
        // Scoped to the company — the forced RLS fence hides the row otherwise.
        let verifier = if adapter.pkce_s256 {
            let fetch = sqlx::query_scalar::<_, Option<String>>(
                "SELECT pkce_verifier FROM integrations.integration_accounts WHERE id = $1 AND company_id = $2",
            )
            .bind(state.account_id)
            .bind(company_id);
            let stored = company_scope::with_company_scope(Some(company_id), fetch.fetch_optional(&self.pool))
                .await
                .map_err(OauthError::Db)?
                .flatten()
                .filter(|v| !v.is_empty())
                .ok_or(OauthError::State("pending authorization has no PKCE verifier".into()))?;
            Some(stored)
        } else {
            None
        };

        let form = TokenRequestForm {
            grant_type: "authorization_code".into(),
            code: Some(req.code),
            refresh_token: None,
            redirect_uri: Some(self.redirect_uri()),
            code_verifier: verifier,
            client_id: client_id.clone(),
            client_secret: self.clients.get(&provider).and_then(|c| c.client_secret.clone()),
            scope: None,
        };
        let response = self
            .transport
            .exchange(&endpoints.token, &form)
            .await
            .map_err(|e| OauthError::Transport(e.to_string()))?;

        // Honest lifetimes: a response with no expires_in is unstoreable.
        let now = Utc::now();
        let expires_at = response
            .expires_at(now)
            .ok_or_else(|| OauthError::Unstoreable("provider returned no expires_in; a permanent token is not a storable value".into()))?;

        // The identity gauntlet.
        let identity = self
            .transport
            .fetch_identity(&endpoints.userinfo, &response.access_token)
            .await
            .map_err(|e| OauthError::Transport(e.to_string()))?;
        verify_audience_and_nonce(&identity, response.id_token.as_deref(), &client_id, &state.nonce)?;
        verify_email_match(
            &identity,
            &account_ref,
            self.shared_mailbox_bypass,
            &provider,
        )?;

        // Assemble the bundle inputs once. A compliant first consent hands back
        // a refresh token; a re-authorization may not — carry the prior one
        // forward (rotation lineage keeps the account reconnectable either way).
        let carried_refresh = match response.refresh_token.clone() {
            Some(r) => Some(r),
            None => self
                .store
                .read_token(company_id, &provider, &account_ref)
                .await
                .ok()
                .and_then(|prior| prior.refresh_token().map(str::to_string)),
        };
        let granted_scope = response.scope.clone().or_else(|| Some(adapter.default_scopes.to_string()));

        // Store first (the store's own fences apply), then transition the
        // account under the same honest expiry. A scope that already holds an
        // active credential (re-connect) rotates — lineage, never a second row.
        // The bundle is not Clone (it is secret-bearing by design), so the
        // rotate path re-assembles it from the same inputs.
        let issued = self
            .store
            .issue(
                company_id,
                &provider,
                &account_ref,
                PURPOSE_OAUTH_TOKEN,
                TokenBundle::new(
                    response.access_token.clone(),
                    carried_refresh.clone(),
                    expires_at,
                    granted_scope.clone(),
                ),
                expires_at,
            )
            .await;
        if let Err(f) = issued {
            if f.code == OAuthCredentialFailure::CODE_DUPLICATE_ACTIVE {
                self.store
                    .rotate(
                        company_id,
                        &provider,
                        &account_ref,
                        TokenBundle::new(
                            response.access_token.clone(),
                            carried_refresh,
                            expires_at,
                            granted_scope,
                        ),
                        expires_at,
                    )
                    .await
                    .map_err(|f| OauthError::Store(f.to_string()))?;
            } else {
                return Err(OauthError::Store(f.to_string()));
            }
        }

        let scopes = response.scope.clone().unwrap_or_default();
        let transition = sqlx::query(
            "UPDATE integrations.integration_accounts
                SET status = 'active', scopes = $3, expires_at = $4,
                    last_refreshed_at = $5, pkce_verifier = NULL
              WHERE id = $1 AND company_id = $2 AND status = 'pending'",
        )
        .bind(state.account_id)
        .bind(company_id)
        .bind(&scopes)
        .bind(expires_at)
        .bind(now);
        let updated =
            company_scope::with_company_scope(Some(company_id), transition.execute(&self.pool))
                .await
                .map_err(OauthError::Db)?;
        if updated.rows_affected() != 1 {
            return Err(OauthError::State("authorization was completed concurrently".into()));
        }

        Ok(CompleteOutcome {
            account_id: state.account_id,
            provider,
            account_ref,
            status: "active".into(),
            scopes,
            expires_at,
        })
    }

    // ── 4. disconnect ───────────────────────────────────────────────────────

    /// Disconnect: revoke the scope's credential through the port (a scope
    /// that never had one revokes cleanly), then transition the account to
    /// its terminal `revoked`. Idempotent for an already-revoked account.
    pub async fn disconnect(&self, company_id: Uuid, account_id: Uuid) -> Result<(), OauthError> {
        let account = self
            .fetch_account(company_id, account_id)
            .await?
            .ok_or(OauthError::NotFound)?;
        if account.status == "revoked" {
            return Ok(());
        }
        match self.store.revoke(company_id, &account.provider, &account.account_ref).await {
            Ok(()) => {}
            // Never issued (a pending authorization abandoned mid-flight) —
            // the account still revokes.
            Err(f) if f.code == OAuthCredentialFailure::CODE_NOT_FOUND => {}
            Err(f) => return Err(OauthError::Store(f.to_string())),
        }
        let transition = sqlx::query(
            "UPDATE integrations.integration_accounts
                SET status = 'revoked', pkce_verifier = NULL
              WHERE id = $1 AND company_id = $2 AND status IN ('pending', 'active')",
        )
        .bind(account_id)
        .bind(company_id);
        company_scope::with_company_scope(Some(company_id), transition.execute(&self.pool))
            .await
            .map_err(OauthError::Db)?;
        Ok(())
    }

    // ── 5. status ───────────────────────────────────────────────────────────

    /// The account's metadata (never secret material — none exists on the row).
    pub async fn status(&self, company_id: Uuid, account_id: Uuid) -> Result<AccountStatus, OauthError> {
        self.fetch_account(company_id, account_id)
            .await?
            .map(Into::into)
            .ok_or(OauthError::NotFound)
    }

    // ── 6. refresh (service-internal; the scheduler and the request path
    //        both land here) ────────────────────────────────────────────────

    /// Refresh every due account for ONE company (the host enumerates
    /// companies; under FORCE RLS a job cannot self-enumerate). Each account
    /// is claimed `FOR UPDATE SKIP LOCKED` in its OWN short transaction with
    /// the lock held through processing — concurrent runners take disjoint
    /// accounts — and commits independently (one provider outage rolls back
    /// exactly its own account). `invalid_grant` expires the account (the
    /// user must reconnect); the credential is left to the store's lazy
    /// expiry. Re-runs converge: a bundle the store already rotated is only
    /// re-mirrored, never re-exchanged.
    pub async fn refresh_due(&self, company_id: Uuid) -> Result<RefreshSummary, OauthError> {
        let mut summary = RefreshSummary::default();
        for _ in 0..self.refresh_batch_size {
            let mut tx = self.pool.begin().await?;
            company_scope::bind_company_on(&mut tx, company_id).await?;
            let claimed = sqlx::query_as::<_, (Uuid, String, String, Option<DateTime<Utc>>)>(
                "SELECT id, provider::text, account_ref, expires_at
                   FROM integrations.integration_accounts
                  WHERE company_id = $1 AND status = 'active'
                    AND expires_at IS NOT NULL
                    AND expires_at < now() + make_interval(secs => $2)
                  ORDER BY expires_at ASC
                  LIMIT 1
                  FOR UPDATE SKIP LOCKED",
            )
            .bind(company_id)
            .bind(self.refresh_window.num_seconds())
            .fetch_optional(&mut *tx)
            .await?;
            let Some((account_id, provider, account_ref, _mirror)) = claimed else {
                tx.commit().await?;
                break;
            };
            self.refresh_claimed(tx, company_id, account_id, provider, account_ref, &mut summary)
                .await?;
        }
        Ok(summary)
    }

    /// Request-path lazy refresh (refresh-on-use): if THIS account is inside
    /// the refresh window, run the same single-account refresh the sweep
    /// runs. Returns the account's metadata either way.
    pub async fn ensure_fresh(&self, company_id: Uuid, account_id: Uuid) -> Result<AccountStatus, OauthError> {
        let account = self
            .fetch_account(company_id, account_id)
            .await?
            .ok_or(OauthError::NotFound)?;
        if account.status != "active" {
            return Ok(account.into());
        }
        let due = account
            .expires_at
            .map(|e| e - self.refresh_window < Utc::now())
            .unwrap_or(false);
        if due {
            let mut tx = self.pool.begin().await?;
            company_scope::bind_company_on(&mut tx, company_id).await?;
            let claimed = sqlx::query_as::<_, (Uuid, String, String, Option<DateTime<Utc>>)>(
                "SELECT id, provider::text, account_ref, expires_at
                   FROM integrations.integration_accounts
                  WHERE id = $1 AND company_id = $2 AND status = 'active'
                  LIMIT 1
                  FOR UPDATE SKIP LOCKED",
            )
            .bind(account_id)
            .bind(company_id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((account_id, provider, account_ref, _)) = claimed {
                let mut summary = RefreshSummary::default();
                self.refresh_claimed(tx, company_id, account_id, provider, account_ref, &mut summary)
                    .await?;
            } else {
                tx.commit().await?;
            }
        }
        self.status(company_id, account_id).await
    }

    /// Refresh one claimed account inside its own transaction (lock held
    /// through processing; every exit path commits the outcome or rolls back
    /// to leave the account due for the next tick).
    async fn refresh_claimed(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        company_id: Uuid,
        account_id: Uuid,
        provider: String,
        account_ref: String,
        summary: &mut RefreshSummary,
    ) -> Result<(), OauthError> {
        // The store is the expiry authority: read the bundle, and if IT is
        // still fresh, only the account's mirror was stale (another runner
        // rotated first) — re-sync the mirror, never re-exchange.
        let prior = match self.store.read_token(company_id, &provider, &account_ref).await {
            Ok(b) => b,
            Err(f) if f.code == OAuthCredentialFailure::CODE_NOT_FOUND
                || f.code == OAuthCredentialFailure::CODE_NOT_ACTIVE
                || f.code == OAuthCredentialFailure::CODE_EXPIRED =>
            {
                // No usable credential: the connection is dead — expire the
                // account (terminal; the user must reconnect).
                sqlx::query(
                    "UPDATE integrations.integration_accounts
                        SET status = 'expired', pkce_verifier = NULL
                      WHERE id = $1 AND company_id = $2 AND status = 'active'",
                )
                .bind(account_id)
                .bind(company_id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                summary.expired += 1;
                return Ok(());
            }
            Err(f) => {
                warn!(target: "integrations.oauth.refresh", account_id = %account_id, "credential store unreadable: {f}");
                tx.rollback().await?;
                summary.failures += 1;
                return Ok(());
            }
        };
        if prior.expires_at() - self.refresh_window >= Utc::now() {
            sqlx::query(
                "UPDATE integrations.integration_accounts
                    SET expires_at = $3
                  WHERE id = $1 AND company_id = $2",
            )
            .bind(account_id)
            .bind(company_id)
            .bind(prior.expires_at())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            summary.resynced += 1;
            return Ok(());
        }
        let Some(refresh_token) = prior.refresh_token().map(str::to_string) else {
            // No refresh token ever stored: nothing to exchange — expire the
            // account (the access token dies at its honest expiry).
            sqlx::query(
                "UPDATE integrations.integration_accounts
                    SET status = 'expired', pkce_verifier = NULL
                  WHERE id = $1 AND company_id = $2 AND status = 'active'",
            )
            .bind(account_id)
            .bind(company_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            summary.expired += 1;
            return Ok(());
        };

        let Ok((endpoints, client_id)) = self.endpoints_for(&provider) else {
            warn!(target: "integrations.oauth.refresh", account_id = %account_id, provider = %provider, "provider unconfigured; left due");
            tx.rollback().await?;
            summary.failures += 1;
            return Ok(());
        };
        let form = TokenRequestForm {
            grant_type: "refresh_token".into(),
            code: None,
            refresh_token: Some(refresh_token),
            redirect_uri: None,
            code_verifier: None,
            client_id,
            client_secret: self.clients.get(&provider).and_then(|c| c.client_secret.clone()),
            // No scope: keep the originally granted scopes.
            scope: None,
        };
        let response = match self.transport.exchange(&endpoints.token, &form).await {
            Ok(r) => r,
            Err(f) if f.is_invalid_grant() => {
                // The refresh token is dead: expire the account, leave the
                // credential to the store's lazy expiry.
                sqlx::query(
                    "UPDATE integrations.integration_accounts
                        SET status = 'expired', pkce_verifier = NULL
                      WHERE id = $1 AND company_id = $2 AND status = 'active'",
                )
                .bind(account_id)
                .bind(company_id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                summary.expired += 1;
                return Ok(());
            }
            Err(f) => {
                warn!(target: "integrations.oauth.refresh", account_id = %account_id, "exchange failed; left due: {f}");
                tx.rollback().await?;
                summary.failures += 1;
                return Ok(());
            }
        };
        let now = Utc::now();
        let Some(expires_at) = response.expires_at(now) else {
            // Unstoreable response: refuse it, leave the account due (visible
            // in the run's failure count), never fake an expiry.
            warn!(target: "integrations.oauth.refresh", account_id = %account_id, "refresh response carried no expires_in; refused as unstoreable");
            tx.rollback().await?;
            summary.failures += 1;
            return Ok(());
        };
        // Microsoft rotates the refresh token itself; Google does not — carry
        // the prior one forward when the response omits it. Either way the
        // successor rides rotate-lineage semantics.
        let refresh = response.refresh_token.clone().or_else(|| prior.refresh_token().map(str::to_string));
        let scope = response.scope.clone().or_else(|| prior.scope().map(str::to_string));
        self.store
            .rotate(
                company_id,
                &provider,
                &account_ref,
                TokenBundle::new(response.access_token.clone(), refresh, expires_at, scope.clone()),
                expires_at,
            )
            .await
            .map_err(|f| OauthError::Store(f.to_string()))?;
        sqlx::query(
            "UPDATE integrations.integration_accounts
                SET expires_at = $3, scopes = COALESCE($4, scopes), last_refreshed_at = $5
              WHERE id = $1 AND company_id = $2",
        )
        .bind(account_id)
        .bind(company_id)
        .bind(expires_at)
        .bind(&scope)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        summary.refreshed += 1;
        Ok(())
    }

    // ── reads ───────────────────────────────────────────────────────────────

    async fn fetch_account(&self, company_id: Uuid, account_id: Uuid) -> Result<Option<AccountRow>, OauthError> {
        let row = sqlx::query_as::<_, AccountRow>(
            "SELECT id, company_id, provider::text AS provider, account_ref,
                    status::text AS status, scopes, expires_at, last_refreshed_at
               FROM integrations.integration_accounts
              WHERE id = $1 AND company_id = $2",
        )
        .bind(account_id)
        .bind(company_id);
        Ok(company_scope::with_company_scope(Some(company_id), row.fetch_optional(&self.pool))
            .await
            .map_err(OauthError::Db)?)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The identity gauntlet
// ─────────────────────────────────────────────────────────────────────────────

/// Enforce the audience + nonce binding: `aud == client_id` (token
/// substitution defense) and `nonce == the nonce minted into the signed
/// state` (replay binding). Sources, cross-checked when both exist: the
/// server-side identity read, and the id_token's own claims decoded here
/// (the token endpoint's response over TLS — never a browser-side claim).
/// Absent everywhere ⇒ unverified ⇒ rejected.
fn verify_audience_and_nonce(
    identity: &crate::infrastructure::http::IdentityClaims,
    id_token: Option<&str>,
    client_id: &str,
    state_nonce: &str,
) -> Result<(), OauthError> {
    let decoded = id_token.and_then(decode_id_token_claims);
    let audience = merge_claim(identity.audience.as_deref(), decoded.as_ref().and_then(|c| c.audience.clone()))?;
    let nonce = merge_claim(identity.nonce.as_deref(), decoded.as_ref().and_then(|c| c.nonce.clone()))?;

    let aud = audience.ok_or_else(|| OauthError::Identity("identity carries no audience to verify".into()))?;
    if aud != client_id {
        return Err(OauthError::Identity(format!(
            "token audience {aud:?} is not this deployment's client (token substitution rejected)"
        )));
    }
    let nonce = nonce.ok_or_else(|| OauthError::Identity("identity carries no nonce to verify".into()))?;
    if nonce != state_nonce {
        return Err(OauthError::Identity("nonce does not match the signed state (replay rejected)".into()));
    }
    Ok(())
}

/// The email match: the provider-side identity must be the identity the
/// account claims. An unverified email is refused; a mismatch rejects unless
/// the declared shared-mailbox bypass is ON (logged on every use).
fn verify_email_match(
    identity: &crate::infrastructure::http::IdentityClaims,
    account_ref: &str,
    shared_mailbox_bypass: bool,
    provider: &str,
) -> Result<(), OauthError> {
    let email = identity
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .ok_or_else(|| OauthError::Identity("provider-side identity carries no email".into()))?;
    if identity.email_verified == Some(false) {
        return Err(OauthError::Identity("provider reports the email as unverified".into()));
    }
    let matches = email.eq_ignore_ascii_case(account_ref);
    if !matches {
        if shared_mailbox_bypass {
            warn!(
                target: "integrations.oauth",
                provider,
                account_ref,
                claimed_identity = email,
                "SHARED-MAILBOX BYPASS: token identity does not match the configured account_ref (declared admin bypass)"
            );
            return Ok(());
        }
        return Err(OauthError::Identity(format!(
            "token identity {email:?} does not match the configured account_ref"
        )));
    }
    Ok(())
}

/// Merge two sources of one claim; disagreement is a rejection (two
/// server-side reads of the same fact must not conflict).
fn merge_claim(
    from_identity: Option<&str>,
    from_id_token: Option<String>,
) -> Result<Option<String>, OauthError> {
    match (from_identity, from_id_token) {
        (Some(a), Some(b)) if !a.eq_ignore_ascii_case(&b) => Err(OauthError::Identity(
            "identity reads disagree on a token claim (refused)".into(),
        )),
        (Some(a), _) => Ok(Some(a.to_string())),
        (None, Some(b)) => Ok(Some(b)),
        (None, None) => Ok(None),
    }
}

/// The id_token claims this flow enforces (decoded, not signature-verified —
/// the token arrived server-side over TLS from the validated token endpoint;
/// the audience + nonce checks below are the replay/substitution defense).
#[derive(Debug, Default)]
struct DecodedIdToken {
    audience: Option<String>,
    nonce: Option<String>,
}

fn decode_id_token_claims(id_token: &str) -> Option<DecodedIdToken> {
    let payload_b64 = id_token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload_b64.trim_end_matches('=')).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let audience = match value.get("aud")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(a) => a.first().and_then(|v| v.as_str()).map(String::from),
        _ => None,
    };
    Some(DecodedIdToken {
        audience,
        nonce: value.get("nonce").and_then(|v| v.as_str()).map(String::from),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn trim_trailing_slash(s: &str) -> String {
    s.trim_end_matches('/').to_string()
}

fn is_mail_provider(provider: &str) -> bool {
    matches!(provider, "gmail" | "outlook")
}

fn normalize_account_ref(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() < 3 || trimmed.len() > 120 || trimmed.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    Some(trimmed.to_string())
}

fn looks_like_email(value: &str) -> bool {
    match value.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        }
        None => false,
    }
}

/// Minimal HTML page that auto-submits an invisible POST form — the safe-method
/// split: the provider's redirect (GET) writes nothing; the mutation rides the
/// form POST. All inserted values are HTML-escaped (they are provider- and
/// attacker-influenceable strings).
fn auto_post_page(action: &str, fields: &[(&str, &str)]) -> String {
    let inputs = fields
        .iter()
        .map(|(name, value)| {
            format!(
                r#"    <input type="hidden" name="{}" value="{}">"#,
                html_escape(name),
                html_escape(value)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "<!doctype html>\n<html>\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"robots\" content=\"noindex\">\n  <title>Completing connection…</title>\n</head>\n<body onload=\"document.forms[0].submit()\">\n  <form method=\"POST\" action=\"{action}\">\n{inputs}\n    <noscript><button type=\"submit\">Continue</button></noscript>\n  </form>\n</body>\n</html>\n"
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> StateSigner {
        StateSigner::new(vec![7u8; 32])
    }

    fn state() -> OAuthState {
        OAuthState {
            account_id: Uuid::new_v4(),
            provider: "gmail".into(),
            nonce: mint_nonce(),
            exp: Utc::now().timestamp() + STATE_TTL_SECONDS,
        }
    }

    #[test]
    fn state_roundtrip_and_constant_time_rejection() {
        let s = signer();
        let token = s.mint(&state()).unwrap();
        assert!(s.verify(&token).is_ok());

        // Flip one byte of the signature → rejected.
        let (payload, mac) = token.split_at(token.len() - 1);
        let last = if mac.ends_with('A') { "B" } else { "A" };
        assert!(s.verify(&format!("{payload}{last}")).is_err(), "flipped signature byte must reject");

        // Tamper with the payload → rejected (replace the first char with one
        // guaranteed different, so the tamper is real whatever the UUID was).
        let (p, m) = token.split_once('.').unwrap();
        let first = p.chars().next().unwrap();
        let replacement = if first == 'e' { 'f' } else { 'e' };
        let tampered = format!("{replacement}{}", &p[1..]);
        assert_ne!(tampered, p, "tamper must actually change the payload");
        assert!(s.verify(&format!("{tampered}.{m}")).is_err());

        // Truncated / malformed shapes → rejected, never panicked.
        assert!(s.verify("").is_err());
        assert!(s.verify("only-one-part").is_err());
        assert!(s.verify("....").is_err());
    }

    #[test]
    fn expired_state_is_refused() {
        let s = signer();
        let mut st = state();
        st.exp = Utc::now().timestamp() - 1;
        let token = s.mint(&st).unwrap();
        assert!(matches!(s.verify(&token), Err(OauthError::State(_))));
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let v = mint_pkce_verifier();
        assert!((43..=128).contains(&v.len()), "verifier length {} out of spec", v.len());
        assert_eq!(pkce_challenge(&v).len(), 43);
        assert_ne!(pkce_challenge(&v), v);
    }

    #[test]
    fn id_token_claims_decode_string_and_array_audience() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = serde_json::json!({"aud": ["client-1", "extra"], "nonce": "n-1", "email": "u@example.com"});
        let encoded = URL_SAFE_NO_PAD.encode(payload.to_string());
        let claims = decode_id_token_claims(&format!("header.{encoded}.signature")).unwrap();
        assert_eq!(claims.audience.as_deref(), Some("client-1"));
        assert_eq!(claims.nonce.as_deref(), Some("n-1"));
        assert!(decode_id_token_claims("not-a-jwt").is_none());
    }

    #[test]
    fn gauntlet_enforces_audience_and_nonce() {
        use crate::infrastructure::http::IdentityClaims;
        let identity = IdentityClaims {
            sub: None,
            email: Some("u@example.com".into()),
            email_verified: Some(true),
            audience: Some("client-1".into()),
            nonce: Some("nonce-1".into()),
        };
        assert!(verify_audience_and_nonce(&identity, None, "client-1", "nonce-1").is_ok());
        assert!(verify_audience_and_nonce(&identity, None, "OTHER-CLIENT", "nonce-1").is_err());
        assert!(verify_audience_and_nonce(&identity, None, "client-1", "nonce-2").is_err());
        // Claims absent everywhere ⇒ unverified ⇒ rejected (fail closed).
        let empty = IdentityClaims::default();
        assert!(verify_audience_and_nonce(&empty, None, "client-1", "nonce-1").is_err());
    }

    #[test]
    fn email_match_rules() {
        use crate::infrastructure::http::IdentityClaims;
        let identity = |email: Option<&str>, verified: Option<bool>| IdentityClaims {
            sub: None,
            email: email.map(String::from),
            email_verified: verified,
            audience: None,
            nonce: None,
        };
        assert!(verify_email_match(&identity(Some("U@Example.com"), Some(true)), "u@example.com", false, "gmail").is_ok());
        assert!(verify_email_match(&identity(Some("other@example.com"), Some(true)), "u@example.com", false, "gmail").is_err());
        // Mismatch + declared bypass ⇒ allowed (the log line is the audit).
        assert!(verify_email_match(&identity(Some("shared@example.com"), Some(true)), "u@example.com", true, "gmail").is_ok());
        // Unverified email ⇒ refused even on a match.
        assert!(verify_email_match(&identity(Some("u@example.com"), Some(false)), "u@example.com", false, "gmail").is_err());
        assert!(verify_email_match(&identity(None, None), "u@example.com", false, "gmail").is_err());
    }

    #[test]
    fn callback_page_escapes_attacker_influenceable_values() {
        let s = signer();
        let state = s.mint(&state()).unwrap();
        let page = super::auto_post_page(COMPLETE_ACTION, &[("code", "a\"<script>"), ("state", &state)]);
        assert!(!page.contains("<script>"), "raw script tag leaked into the page");
        assert!(page.contains("&lt;script&gt;"));
        assert!(page.contains("action=\"complete\""), "the form target is the relative completion route");
    }

    #[test]
    fn account_ref_validation() {
        assert!(normalize_account_ref("  u@example.com ").is_some());
        assert!(normalize_account_ref("no").is_none());
        assert!(normalize_account_ref("has space@example.com").is_none());
        assert!(looks_like_email("u@example.com"));
        assert!(!looks_like_email("example.com"));
        assert!(!looks_like_email("@example.com"));
    }
}
