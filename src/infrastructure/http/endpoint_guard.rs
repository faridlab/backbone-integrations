//! The outbound endpoint guard for the one OAuth generation (hand-authored,
//! user-owned).
//!
//! Why this file exists: the upstream code this module replaces guarded its
//! outbound OAuth calls with a debug `assert` over a host allowlist — an
//! assertion the runtime strips under optimization, and whose Microsoft
//! endpoints were overridable at runtime with no validation at all. The guard
//! here is a real one, and it fails closed at every layer:
//!
//! 1. **Registry (compile time)** — [`ProviderRegistry`] carries the adapter
//!    data for every supported provider: endpoint URLs, default scopes, the
//!    PKCE capability, and the host allowlist for that provider family.
//!    There is no code path that constructs a provider URL from anything a
//!    request supplied.
//! 2. **Validation (config-load time)** — every endpoint override arriving
//!    from configuration passes [`validate_endpoint`] before the module using
//!    it may build: https-only, host suffix-matched against the provider's
//!    allowlist, no userinfo component, no IP-literal host, no port other
//!    than 443, a non-root path, no query, no fragment. ANY violation is an
//!    [`InvalidEndpoint`] and the module builder refuses to build — a bad
//!    override yields no module, not a degraded one.
//! 3. **Re-validation (request time)** — a [`ValidatedEndpoint`] can only be
//!    constructed through validation, and the transport re-runs the full rule
//!    set ([`ValidatedEndpoint::revalidate`]) before every call, so an
//!    endpoint that reached the transport by internal drift is refused there
//!    too. Fail closed at build time AND at request time.
//! 4. **Resolution guard (transport time)** — the reqwest client follows no
//!    redirects ([`reqwest::redirect::Policy::none`]) and resolves the host
//!    before connecting, refusing loopback/private/link-local/unique-local
//!    addresses ([`assert_public_resolution`]) — a basic DNS-rebinding
//!    closure on top of the allowlist.
//!
//! The type system carries the guarantee: the transport accepts ONLY
//! [`ValidatedEndpoint`] values — "URL that passed the guard" is the sole
//! currency — and the field inside is private, so no caller can smuggle an
//! unvalidated URL into an outbound call.
//!
//! [`OAuthTransport`] is the port the OAuth flow and the refresh scheduler
//! share; tests inject a fake that records every URL it was handed.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Url;

// ─────────────────────────────────────────────────────────────────────────────
// Provider registry — compile-time adapter data
// ─────────────────────────────────────────────────────────────────────────────

/// Provider key constants (the `OAuthProvider` enum's values as plain strings,
/// so infrastructure stays independent of the generated entity enum).
pub const PROVIDER_GMAIL: &str = "gmail";
pub const PROVIDER_OUTLOOK: &str = "outlook";
pub const PROVIDER_GOOGLE_CALENDAR: &str = "google_calendar";
pub const PROVIDER_MICROSOFT_CALENDAR: &str = "microsoft_calendar";

/// The host allowlist for the Google provider family. A configured endpoint
/// for `gmail` / `google_calendar` may live ONLY on these hosts (exact match
/// or a subdomain of a listed host).
pub const GOOGLE_HOSTS: &[&str] = &[
    "accounts.google.com",
    "oauth2.googleapis.com",
    "openidconnect.googleapis.com",
    "www.googleapis.com",
];

/// The host allowlist for the Microsoft provider family (`outlook` /
/// `microsoft_calendar`).
pub const MICROSOFT_HOSTS: &[&str] = &[
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "outlook.office365.com",
];

/// Which of a provider's three endpoints a URL is being validated as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKey {
    Authorize,
    Token,
    Userinfo,
}

impl EndpointKey {
    /// The key as it appears in configuration (`oauth.endpoints.<provider>.<key>`).
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointKey::Authorize => "authorize",
            EndpointKey::Token => "token",
            EndpointKey::Userinfo => "userinfo",
        }
    }
}

impl std::fmt::Display for EndpointKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One provider's adapter data: the endpoints, default scopes, PKCE
/// capability, and host allowlist. Purely compile-time — per-deployment
/// overrides arrive through [`EndpointOverrides`] and are validated against
/// the allowlist here before use.
#[derive(Debug, Clone)]
pub struct ProviderAdapter {
    /// Provider key (`"gmail"` …) — matches the account row's provider value.
    pub provider: &'static str,
    /// The authorization endpoint the browser is sent to.
    pub authorize_endpoint: &'static str,
    /// The token endpoint (code exchange AND refresh grant).
    pub token_endpoint: &'static str,
    /// The identity endpoint for post-exchange account verification.
    pub userinfo_endpoint: &'static str,
    /// Default scopes requested when the caller passes none.
    pub default_scopes: &'static str,
    /// Whether the provider supports PKCE S256 (verifier minted per
    /// authorization, challenge sent, verifier presented at exchange).
    pub pkce_s256: bool,
    /// Hosts this provider's endpoints may live on (the SSRF allowlist).
    pub host_allowlist: &'static [&'static str],
}

impl ProviderAdapter {
    /// Validate a candidate URL as one of this provider's endpoints — the
    /// single rule set every override and every registry value passes.
    pub fn validate(&self, key: EndpointKey, url: &str) -> Result<ValidatedEndpoint, InvalidEndpoint> {
        validate_endpoint(self.provider, key, self.host_allowlist, url)
    }
}

const GMAIL_ADAPTER: ProviderAdapter = ProviderAdapter {
    provider: PROVIDER_GMAIL,
    authorize_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    token_endpoint: "https://oauth2.googleapis.com/token",
    userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
    default_scopes: "https://mail.google.com/ openid https://www.googleapis.com/auth/userinfo.email",
    pkce_s256: true,
    host_allowlist: GOOGLE_HOSTS,
};

const GOOGLE_CALENDAR_ADAPTER: ProviderAdapter = ProviderAdapter {
    provider: PROVIDER_GOOGLE_CALENDAR,
    authorize_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    token_endpoint: "https://oauth2.googleapis.com/token",
    userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
    default_scopes: "https://www.googleapis.com/auth/calendar openid https://www.googleapis.com/auth/userinfo.email",
    pkce_s256: true,
    host_allowlist: GOOGLE_HOSTS,
};

const OUTLOOK_ADAPTER: ProviderAdapter = ProviderAdapter {
    provider: PROVIDER_OUTLOOK,
    authorize_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
    default_scopes: "https://outlook.office365.com/SMTP.Send https://outlook.office365.com/IMAP.AccessAsUser.All openid email profile",
    pkce_s256: true,
    host_allowlist: MICROSOFT_HOSTS,
};

const MICROSOFT_CALENDAR_ADAPTER: ProviderAdapter = ProviderAdapter {
    provider: PROVIDER_MICROSOFT_CALENDAR,
    authorize_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
    default_scopes: "https://graph.microsoft.com/Calendars.ReadWrite openid email profile",
    pkce_s256: true,
    host_allowlist: MICROSOFT_HOSTS,
};

/// The compile-time provider registry. [`ProviderRegistry::with_builtin`]
/// carries the four OAuth providers; composition may add adapters, never
/// remove the validation contract.
#[derive(Debug, Clone, Default)]
pub struct ProviderRegistry {
    adapters: BTreeMap<&'static str, ProviderAdapter>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self { adapters: BTreeMap::new() }
    }

    /// The four built-in providers (gmail / outlook / google_calendar /
    /// microsoft_calendar).
    pub fn with_builtin() -> Self {
        let mut r = Self::new();
        for adapter in [
            GMAIL_ADAPTER,
            OUTLOOK_ADAPTER,
            GOOGLE_CALENDAR_ADAPTER,
            MICROSOFT_CALENDAR_ADAPTER,
        ] {
            r.adapters.insert(adapter.provider, adapter);
        }
        r
    }

    /// Register an additional adapter (composition extension point).
    pub fn register(&mut self, adapter: ProviderAdapter) {
        self.adapters.insert(adapter.provider, adapter);
    }

    /// Look up one provider's adapter data.
    pub fn lookup(&self, provider: &str) -> Option<&ProviderAdapter> {
        self.adapters.get(provider)
    }

    /// All registered provider keys, sorted.
    pub fn providers(&self) -> Vec<&'static str> {
        self.adapters.keys().copied().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint validation — the guard
// ─────────────────────────────────────────────────────────────────────────────

/// A configuration-time endpoint rejection. Fail closed: the caller building
/// the module refuses to proceed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("invalid {key} endpoint for {provider} ({url}): {reason}")]
pub struct InvalidEndpoint {
    pub provider: String,
    pub key: EndpointKey,
    pub url: String,
    pub reason: &'static str,
}

/// Validate one endpoint URL against a provider's host allowlist. The full
/// rule set, in order:
///
/// - parses as an absolute URL;
/// - scheme is exactly `https`;
/// - host is present, carries no userinfo, and is NOT an IP literal;
/// - host suffix-matches an allowlist entry (exact host or subdomain of a
///   listed host — a listed apex covers its subdomains, nothing else);
/// - port is absent (default) or explicitly 443;
/// - the path is non-empty and not just `/`;
/// - no query string and no fragment.
///
/// Every rule is deny-by-default: anything the rule set does not recognize as
/// allowed is rejected.
pub fn validate_endpoint(
    provider: &str,
    key: EndpointKey,
    allowlist: &[&str],
    url_str: &str,
) -> Result<ValidatedEndpoint, InvalidEndpoint> {
    let reject = |reason: &'static str| InvalidEndpoint {
        provider: provider.to_string(),
        key,
        url: url_str.to_string(),
        reason,
    };
    let url: Url = url_str.parse().map_err(|_| reject("not a parseable URL"))?;
    if url.scheme() != "https" {
        return Err(reject("scheme must be https"));
    }
    let host = url.host_str().ok_or_else(|| reject("URL carries no host"))?;
    if host.is_empty() {
        return Err(reject("URL carries no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(reject("userinfo component forbidden"));
    }
    // IPv6 literals arrive bracketed ([::1]) — strip the brackets before the
    // IP parse so both families are caught.
    let host_core = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if host_core.parse::<IpAddr>().is_ok() {
        return Err(reject("IP-literal host forbidden"));
    }
    let host_lc = host.to_ascii_lowercase();
    let allowed = allowlist.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        host_lc == entry || host_lc.ends_with(&format!(".{entry}"))
    });
    if !allowed {
        return Err(reject("host is not on the provider allowlist"));
    }
    match url.port() {
        None | Some(443) => {}
        Some(_) => return Err(reject("only port 443 is permitted")),
    }
    let path = url.path();
    if path.is_empty() || path == "/" {
        return Err(reject("endpoint must carry a non-root path"));
    }
    if url.query().is_some() {
        return Err(reject("query string forbidden in a configured endpoint"));
    }
    if url.fragment().is_some() {
        return Err(reject("fragment forbidden in a configured endpoint"));
    }
    Ok(ValidatedEndpoint { provider_key: provider.to_string(), key, url })
}

/// A URL that passed the full rule set. Constructible only through
/// [`validate_endpoint`] (the inner URL is private); the transport accepts
/// nothing else, and re-runs the rules before every call.
#[derive(Debug, Clone)]
pub struct ValidatedEndpoint {
    provider_key: String,
    key: EndpointKey,
    url: Url,
}

impl ValidatedEndpoint {
    /// The validated URL (for building the outbound request).
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The URL as a string.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// The host this endpoint was validated against the allowlist for.
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }

    /// Re-run the full rule set against the stored URL (request-time
    /// fail-closed). The stored allowlist binding is re-derived from the
    /// provider key via the registry, so a tampered or drifted value is
    /// refused here exactly as it would be at config-load time.
    pub fn revalidate(&self, registry: &ProviderRegistry) -> Result<(), InvalidEndpoint> {
        let adapter = registry.lookup(&self.provider_key).ok_or_else(|| InvalidEndpoint {
            provider: self.provider_key.clone(),
            key: self.key,
            url: self.url.as_str().to_string(),
            reason: "provider is not registered",
        })?;
        validate_endpoint(
            adapter.provider,
            self.key,
            adapter.host_allowlist,
            self.url.as_str(),
        )
        .map(|_| ())
    }
}

/// Per-provider endpoint overrides from configuration. Empty by default — no
/// override means the registry value. An override is a candidate, never a
/// truth: it is validated before use, and a bad one fails the build.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub struct ProviderEndpointOverride {
    pub authorize: Option<String>,
    pub token: Option<String>,
    pub userinfo: Option<String>,
}

/// The `oauth.endpoints` configuration section: provider key → overrides.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub struct EndpointOverrides(pub BTreeMap<String, ProviderEndpointOverride>);

impl EndpointOverrides {
    pub fn get(&self, provider: &str) -> ProviderEndpointOverride {
        self.0.get(provider).cloned().unwrap_or_default()
    }
}

/// A provider's three endpoints, resolved and validated. Produced by
/// [`ValidatedEndpoints::resolve`] — registry values by default, validated
/// overrides where present. The sole endpoint currency the OAuth flow and the
/// refresh scheduler deal in.
#[derive(Debug, Clone)]
pub struct ValidatedEndpoints {
    pub authorize: ValidatedEndpoint,
    pub token: ValidatedEndpoint,
    pub userinfo: ValidatedEndpoint,
}

impl ValidatedEndpoints {
    /// Resolve one provider's endpoints: registry defaults unless a
    /// configuration override is present; EVERY value (registry or override)
    /// passes [`validate_endpoint`]. Any rejection propagates — the caller
    /// building the module refuses to build.
    pub fn resolve(
        registry: &ProviderRegistry,
        provider: &str,
        overrides: &EndpointOverrides,
    ) -> Result<Self, InvalidEndpoint> {
        let adapter = registry.lookup(provider).ok_or_else(|| InvalidEndpoint {
            provider: provider.to_string(),
            key: EndpointKey::Token,
            url: String::new(),
            reason: "provider is not registered",
        })?;
        let override_entry = overrides.get(provider);
        let pick = |key: EndpointKey,
                    registry_value: &'static str,
                    override_value: Option<&String>|
         -> Result<ValidatedEndpoint, InvalidEndpoint> {
            match override_value {
                Some(url) => adapter.validate(key, url),
                None => adapter.validate(key, registry_value),
            }
        };
        Ok(Self {
            authorize: pick(EndpointKey::Authorize, adapter.authorize_endpoint, override_entry.authorize.as_ref())?,
            token: pick(EndpointKey::Token, adapter.token_endpoint, override_entry.token.as_ref())?,
            userinfo: pick(EndpointKey::Userinfo, adapter.userinfo_endpoint, override_entry.userinfo.as_ref())?,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OAuth client configuration (non-secret id + secret handed by composition)
// ─────────────────────────────────────────────────────────────────────────────

/// One provider's OAuth client registration. The client id is not a secret
/// (it travels in the authorize URL); the client secret is — redacted in
/// Debug, zeroized on drop.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OAuthClientConfig {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// The `oauth.clients` configuration section: provider key → client config.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct OAuthClientConfigs(pub BTreeMap<String, OAuthClientConfig>);

impl OAuthClientConfigs {
    pub fn get(&self, provider: &str) -> Option<&OAuthClientConfig> {
        self.0.get(provider)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The transport port
// ─────────────────────────────────────────────────────────────────────────────

/// An OAuth token-endpoint request form (code exchange or refresh grant),
/// serialized as `application/x-www-form-urlencoded`. Debug is redacted — the
/// code, refresh token, and client secret must never drift into a log line.
#[derive(Clone, Default, serde::Serialize)]
pub struct TokenRequestForm {
    pub grant_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl std::fmt::Debug for TokenRequestForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequestForm")
            .field("grant_type", &self.grant_type)
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "[REDACTED]"))
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &self.code_verifier.as_ref().map(|_| "[REDACTED]"))
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "[REDACTED]"))
            .field("scope", &self.scope)
            .finish()
    }
}

/// A provider token response. `expires_in` missing means the provider claims
/// no expiry — per the honest-lifetime rule such a response is UNSTOREABLE
/// and callers refuse it (a "permanent" token is not a value the flow will
/// store). Debug is redacted.
#[derive(Clone, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "[REDACTED]"))
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("token_type", &self.token_type)
            .finish()
    }
}

impl TokenResponse {
    /// The honest expiry of this response: `now + expires_in`. `None` when
    /// the provider returned no `expires_in` — the unstoreable case.
    pub fn expires_at(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.expires_in
            .filter(|secs| *secs > 0)
            .map(|secs| now + chrono::Duration::seconds(secs))
    }
}

/// The verified identity of the token's subject, as read server-side (the
/// userinfo endpoint, or the id_token the token endpoint returned — never a
/// browser-side claim). `audience` and `nonce` carry the id_token's values so
/// the flow can enforce the audience check and the nonce binding.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct IdentityClaims {
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default, alias = "aud")]
    pub audience: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

/// Why an outbound OAuth call failed.
///
/// - [`InvalidGrant`](TransportFailureKind::InvalidGrant) — the provider
///   answered 400 `invalid_grant`: the refresh token is dead; the caller
///   expires the account (the user must reconnect), never retries.
/// - [`Provider`](TransportFailureKind::Provider) — the provider refused or
///   returned an unusable shape. Zero writes; the next tick retries.
/// - [`Network`](TransportFailureKind::Network) — transport-level failure.
///   Zero writes; the next tick retries.
/// - [`EndpointGuard`](TransportFailureKind::EndpointGuard) — the guard
///   refused (revalidation or resolution). Zero writes, zero HTTP calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportFailureKind {
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("provider refused")]
    Provider,
    #[error("network failure")]
    Network,
    #[error("endpoint guard refusal")]
    EndpointGuard,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("oauth transport failure ({kind}): {message}")]
pub struct TransportFailure {
    pub kind: TransportFailureKind,
    pub message: String,
}

impl TransportFailure {
    pub fn new(kind: TransportFailureKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }

    pub fn is_invalid_grant(&self) -> bool {
        self.kind == TransportFailureKind::InvalidGrant
    }
}

/// The outbound transport port: token exchange and server-side identity
/// fetch. Both methods take ONLY validated endpoints — an unvalidated URL
/// cannot reach the network through this trait.
#[async_trait::async_trait]
pub trait OAuthTransport: Send + Sync {
    /// POST the form to the token endpoint (code exchange or refresh grant).
    async fn exchange(
        &self,
        endpoint: &ValidatedEndpoint,
        form: &TokenRequestForm,
    ) -> Result<TokenResponse, TransportFailure>;

    /// GET the identity endpoint with the access token (server-side
    /// verification read).
    async fn fetch_identity(
        &self,
        endpoint: &ValidatedEndpoint,
        access_token: &str,
    ) -> Result<IdentityClaims, TransportFailure>;
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS resolution guard
// ─────────────────────────────────────────────────────────────────────────────

/// Whether an address is acceptable as an outbound OAuth target: not
/// loopback, not private (RFC1918 + carrier-grade NAT), not link-local, not
/// unique-local (fc00::/7), not unspecified, not multicast — for IPv4, IPv6,
/// and IPv4-mapped IPv6 alike.
pub fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_public(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ipv4_is_public(mapped);
            }
            ipv6_is_public(&v6)
        }
    }
}

fn ipv4_is_public(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        // Carrier-grade NAT 100.64.0.0/10 — not globally routable.
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000))
}

fn ipv6_is_public(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // Link-local fe80::/10.
        || (seg[0] & 0xffc0) == 0xfe80
        // Unique-local fc00::/7.
        || (seg[0] & 0xfe00) == 0xfc00)
}

/// Resolve `host` and refuse any answer in a forbidden range — the basic
/// DNS-rebinding closure. The allowlist remains the primary control (an
/// attacker cannot control DNS for an allowlisted provider host); this check
/// bounds the residual window where a name that passed the allowlist resolves
/// somewhere it should not. Returns the resolved addresses on success.
pub async fn assert_public_resolution(host: &str) -> Result<Vec<IpAddr>, TransportFailure> {
    let resolved: Vec<IpAddr> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|e| TransportFailure::new(
            TransportFailureKind::EndpointGuard,
            format!("resolving {host}: {e}"),
        ))?
        .map(|addr| addr.ip())
        .collect();
    if resolved.is_empty() {
        return Err(TransportFailure::new(
            TransportFailureKind::EndpointGuard,
            format!("resolving {host}: no addresses"),
        ));
    }
    for ip in &resolved {
        if !ip_is_public(*ip) {
            return Err(TransportFailure::new(
                TransportFailureKind::EndpointGuard,
                format!("{host} resolves to forbidden address {ip}"),
            ));
        }
    }
    Ok(resolved)
}

// ─────────────────────────────────────────────────────────────────────────────
// The reqwest implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Default connect budget for one outbound OAuth call.
pub const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default total budget for one outbound OAuth call.
pub const OAUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The production [`OAuthTransport`]: a reqwest client that follows no
/// redirects, carries explicit timeouts, re-validates the endpoint before
/// every call, and resolves the host through the private-range guard before
/// connecting.
///
/// The no-redirect policy is load-bearing: an allowlisted endpoint answering
/// `3xx Location: http://attacker.example/` must not be followed — the
/// response is surfaced as a provider error instead.
pub struct ReqwestOAuthTransport {
    client: reqwest::Client,
    registry: ProviderRegistry,
    redirect_policy_none: bool,
}

impl ReqwestOAuthTransport {
    /// Build with the guard postures (no redirects, timeouts) over the
    /// built-in provider registry. This is the production constructor.
    pub fn new() -> Result<Self, TransportFailure> {
        Self::with_registry(ProviderRegistry::with_builtin())
    }

    /// Build with the guard postures over a caller-supplied registry
    /// (composition that registered extra adapters).
    pub fn with_registry(registry: ProviderRegistry) -> Result<Self, TransportFailure> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(OAUTH_CONNECT_TIMEOUT)
            .timeout(OAUTH_REQUEST_TIMEOUT)
            .user_agent("backbone-integrations-oauth/1")
            .build()
            .map_err(|e| TransportFailure::new(TransportFailureKind::Network, e.to_string()))?;
        Ok(Self { client, registry, redirect_policy_none: true })
    }

    /// Wrap an externally built client (test injection). The no-redirect
    /// posture is reported as `false` unless the caller asserts it — the
    /// caller takes responsibility for the posture it injects.
    pub fn from_client(client: reqwest::Client, redirect_policy_none: bool) -> Self {
        Self { client, registry: ProviderRegistry::with_builtin(), redirect_policy_none }
    }

    /// Whether this transport refuses redirects (the guard posture). Asserted
    /// by the guard probes for the production constructor.
    pub fn redirect_policy_is_none(&self) -> bool {
        self.redirect_policy_none
    }

    /// The pre-call guard: re-run the full endpoint rule set against this
    /// transport's registry, then resolve the host through the private-range
    /// check. Fail closed — a refusal means zero bytes hit the network.
    async fn guard(&self, endpoint: &ValidatedEndpoint) -> Result<(), TransportFailure> {
        endpoint
            .revalidate(&self.registry)
            .map_err(|e| {
                TransportFailure::new(
                    TransportFailureKind::EndpointGuard,
                    format!("request-time revalidation refused {e}"),
                )
            })?;
        assert_public_resolution(endpoint.host()).await?;
        Ok(())
    }
}

impl Default for ReqwestOAuthTransport {
    fn default() -> Self {
        Self::new().expect("reqwest client construction")
    }
}

#[async_trait::async_trait]
impl OAuthTransport for ReqwestOAuthTransport {
    async fn exchange(
        &self,
        endpoint: &ValidatedEndpoint,
        form: &TokenRequestForm,
    ) -> Result<TokenResponse, TransportFailure> {
        self.guard(endpoint).await?;
        let response = self
            .client
            .post(endpoint.url().clone())
            .form(form)
            .send()
            .await
            .map_err(|e| TransportFailure::new(TransportFailureKind::Network, e.to_string()))?;
        let status = response.status();
        if status.is_success() {
            let token: TokenResponse = response
                .json()
                .await
                .map_err(|e| TransportFailure::new(
                    TransportFailureKind::Provider,
                    format!("token response was not valid provider JSON: {e}"),
                ))?;
            if token.access_token.trim().is_empty() {
                return Err(TransportFailure::new(
                    TransportFailureKind::Provider,
                    "token response carries no access_token",
                ));
            }
            return Ok(token);
        }
        // A provider refusal: 400 invalid_grant is the dead-refresh-token
        // signal the refresh path acts on; everything else is a plain
        // provider error. The body's error code is provider metadata (never
        // token material).
        let body = response.text().await.unwrap_or_default();
        let error_code = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from));
        if status.as_u16() == 400 && error_code.as_deref() == Some("invalid_grant") {
            return Err(TransportFailure::new(
                TransportFailureKind::InvalidGrant,
                "provider rejected the grant: invalid_grant",
            ));
        }
        Err(TransportFailure::new(
            TransportFailureKind::Provider,
            format!("provider answered {status}: {}", error_code.unwrap_or_else(|| body.chars().take(200).collect::<String>())),
        ))
    }

    async fn fetch_identity(
        &self,
        endpoint: &ValidatedEndpoint,
        access_token: &str,
    ) -> Result<IdentityClaims, TransportFailure> {
        self.guard(endpoint).await?;
        let response = self
            .client
            .get(endpoint.url().clone())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| TransportFailure::new(TransportFailureKind::Network, e.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return response.json().await.map_err(|e| {
                TransportFailure::new(
                    TransportFailureKind::Provider,
                    format!("identity response was not valid provider JSON: {e}"),
                )
            });
        }
        let body = response.text().await.unwrap_or_default();
        Err(TransportFailure::new(
            TransportFailureKind::Provider,
            format!("provider answered {status}: {}", body.chars().take(200).collect::<String>()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVIL: &str = "https://evil.example.com/token";

    #[test]
    fn registry_endpoints_pass_their_own_allowlist() {
        let registry = ProviderRegistry::with_builtin();
        for provider in registry.providers() {
            let adapter = registry.lookup(provider).expect("adapter");
            for (key, url) in [
                (EndpointKey::Authorize, adapter.authorize_endpoint),
                (EndpointKey::Token, adapter.token_endpoint),
                (EndpointKey::Userinfo, adapter.userinfo_endpoint),
            ] {
                assert!(
                    adapter.validate(key, url).is_ok(),
                    "{provider} {key:?} endpoint {url} must pass its own allowlist",
                );
            }
        }
    }

    #[test]
    fn guard_rejects_each_malicious_shape() {
        let registry = ProviderRegistry::with_builtin();
        let adapter = registry.lookup(PROVIDER_GMAIL).unwrap();
        let cases: &[(&str, &'static str)] = &[
            ("http://oauth2.googleapis.com/token", "scheme must be https"),
            (EVIL, "host is not on the provider allowlist"),
            ("https://user@oauth2.googleapis.com/token", "userinfo component forbidden"),
            ("https://user:pass@oauth2.googleapis.com/token", "userinfo component forbidden"),
            ("https://127.0.0.1/token", "IP-literal host forbidden"),
            ("https://[::1]/token", "IP-literal host forbidden"),
            ("https://oauth2.googleapis.com:8443/token", "only port 443 is permitted"),
            ("https://oauth2.googleapis.com/", "endpoint must carry a non-root path"),
            ("https://oauth2.googleapis.com", "endpoint must carry a non-root path"),
            ("https://oauth2.googleapis.com/token?x=1", "query string forbidden in a configured endpoint"),
            ("https://oauth2.googleapis.com/token#f", "fragment forbidden in a configured endpoint"),
            ("not a url", "not a parseable URL"),
        ];
        for (url, expected_reason) in cases {
            let err = adapter
                .validate(EndpointKey::Token, url)
                .expect_err(url);
            assert_eq!(err.reason, *expected_reason, "wrong reason for {url}: {err}");
        }
    }

    #[test]
    fn guard_accepts_subdomains_explicit_port_and_overrides() {
        let registry = ProviderRegistry::with_builtin();
        let adapter = registry.lookup(PROVIDER_GMAIL).unwrap();
        // A subdomain of a listed host is allowlisted; the suffix is
        // dot-anchored, so a host merely ENDING in the allowlist string
        // (eviloauth2.googleapis.com) does not match.
        assert!(adapter.validate(EndpointKey::Token, "https://oauth2.googleapis.com/token").is_ok());
        assert!(adapter
            .validate(EndpointKey::Token, "https://eviloauth2.googleapis.com/token")
            .is_err(), "suffix match must be dot-anchored");
        assert!(adapter
            .validate(EndpointKey::Token, "https://accounts.google.com.evil.example.com/token")
            .is_err(), "allowlisted host must be a suffix, not a substring");
        // Explicit 443 and a real path pass.
        assert!(adapter
            .validate(EndpointKey::Token, "https://oauth2.googleapis.com:443/token")
            .is_ok());
        // Microsoft hosts are NOT valid for a Google provider.
        assert!(adapter
            .validate(EndpointKey::Token, "https://login.microsoftonline.com/common/oauth2/v2.0/token")
            .is_err(), "cross-family host must be refused");
    }

    #[test]
    fn resolve_uses_registry_defaults_and_validated_overrides() {
        let registry = ProviderRegistry::with_builtin();
        let none = EndpointOverrides::default();
        let gmail = ValidatedEndpoints::resolve(&registry, PROVIDER_GMAIL, &none).expect("defaults resolve");
        assert_eq!(gmail.token.as_str(), "https://oauth2.googleapis.com/token");

        // A same-host path override passes and is used.
        let mut map = BTreeMap::new();
        map.insert(
            PROVIDER_GMAIL.to_string(),
            ProviderEndpointOverride {
                token: Some("https://oauth2.googleapis.com/token".into()),
                ..Default::default()
            },
        );
        let good = EndpointOverrides(map);
        assert!(ValidatedEndpoints::resolve(&registry, PROVIDER_GMAIL, &good).is_ok());

        // An evil override fails the resolve — the module cannot be built.
        let mut map = BTreeMap::new();
        map.insert(
            PROVIDER_GMAIL.to_string(),
            ProviderEndpointOverride { token: Some(EVIL.into()), ..Default::default() },
        );
        let evil = EndpointOverrides(map);
        let err = ValidatedEndpoints::resolve(&registry, PROVIDER_GMAIL, &evil).expect_err("evil override");
        assert_eq!(err.reason, "host is not on the provider allowlist");

        // An unknown provider fails closed.
        assert!(ValidatedEndpoints::resolve(&registry, "not_a_provider", &none).is_err());
    }

    #[test]
    fn revalidation_re_runs_the_full_rule_set() {
        let registry = ProviderRegistry::with_builtin();
        let mut endpoint = registry
            .lookup(PROVIDER_OUTLOOK)
            .unwrap()
            .validate(EndpointKey::Token, "https://login.microsoftonline.com/common/oauth2/v2.0/token")
            .expect("valid");
        assert!(endpoint.revalidate(&registry).is_ok(), "a clean endpoint revalidates");

        // Tamper with the stored URL (only reachable inside the module — the
        // field is private): revalidation must refuse it at request time.
        endpoint.url = "https://127.0.0.1/token".parse().unwrap();
        let err = endpoint.revalidate(&registry).expect_err("tampered endpoint");
        assert_eq!(err.reason, "IP-literal host forbidden");

        // A provider removed from the registry after validation also fails.
        let mut endpoint2 = registry
            .lookup(PROVIDER_GMAIL)
            .unwrap()
            .validate(EndpointKey::Token, "https://oauth2.googleapis.com/token")
            .unwrap();
        endpoint2.provider_key = "ghost_provider".into();
        assert!(endpoint2.revalidate(&registry).is_err());
    }

    #[test]
    fn public_transport_refuses_redirects_by_construction() {
        let transport = ReqwestOAuthTransport::new().expect("client builds");
        assert!(transport.redirect_policy_is_none(), "production client must refuse redirects");
    }

    #[test]
    fn private_ranges_are_not_public() {
        let forbidden = [
            "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.254", "169.254.1.1",
            "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
            "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1",
            "::ffff:127.0.0.1", "::ffff:10.0.0.1",
        ];
        for raw in forbidden {
            let ip: IpAddr = raw.parse().expect(raw);
            assert!(!ip_is_public(ip), "{raw} must be refused as an outbound target");
        }
        let public = ["8.8.8.8", "34.64.1.1", "2607:f8b0:4005:80a::200e", "2001:4860:4860::8888"];
        for raw in public {
            let ip: IpAddr = raw.parse().expect(raw);
            assert!(ip_is_public(ip), "{raw} is a legitimate outbound target");
        }
    }

    #[tokio::test]
    async fn resolution_guard_refuses_loopback_hosts() {
        // localhost resolves via the host table — no network needed.
        let err = assert_public_resolution("localhost").await.expect_err("loopback must be refused");
        assert_eq!(err.kind, TransportFailureKind::EndpointGuard);
        assert!(err.message.contains("forbidden address"), "unexpected message: {err}");
        let err = assert_public_resolution("127.0.0.1").await.expect_err("IP literal must be refused");
        assert_eq!(err.kind, TransportFailureKind::EndpointGuard);
    }

    #[test]
    fn form_and_response_debug_are_redacted() {
        let form = TokenRequestForm {
            grant_type: "authorization_code".into(),
            code: Some("SECRET-CODE".into()),
            refresh_token: Some("SECRET-REFRESH".into()),
            redirect_uri: Some("https://example.test/cb".into()),
            code_verifier: Some("SECRET-VERIFIER".into()),
            client_id: "client-1".into(),
            client_secret: Some("SECRET-CLIENT-SECRET".into()),
            scope: None,
        };
        let debugged = format!("{form:?}");
        for secret in ["SECRET-CODE", "SECRET-REFRESH", "SECRET-VERIFIER", "SECRET-CLIENT-SECRET"] {
            assert!(!debugged.contains(secret), "leak in form Debug: {debugged}");
        }
        assert!(debugged.contains("[REDACTED]"));

        let response = TokenResponse {
            access_token: "SECRET-ACCESS".into(),
            refresh_token: Some("SECRET-REFRESH2".into()),
            expires_in: Some(3600),
            scope: Some("openid".into()),
            id_token: Some("SECRET-ID-TOKEN".into()),
            token_type: Some("Bearer".into()),
        };
        let debugged = format!("{response:?}");
        for secret in ["SECRET-ACCESS", "SECRET-REFRESH2", "SECRET-ID-TOKEN"] {
            assert!(!debugged.contains(secret), "leak in response Debug: {debugged}");
        }
        // Non-secret fields remain diagnostic.
        assert!(debugged.contains("3600"));
    }

    #[test]
    fn honest_expiry_derivation() {
        let now = Utc::now();
        let with_expiry = TokenResponse {
            access_token: "a".into(),
            refresh_token: None,
            expires_in: Some(3600),
            scope: None,
            id_token: None,
            token_type: None,
        };
        assert_eq!(with_expiry.expires_at(now), Some(now + chrono::Duration::hours(1)));
        // A provider claiming no expiry — the unstoreable case.
        let permanent = TokenResponse { expires_in: None, ..with_expiry };
        assert_eq!(permanent.expires_at(now), None);
        // A non-positive expiry is not a lifetime either.
        let zero = TokenResponse { expires_in: Some(0), ..permanent };
        assert_eq!(zero.expires_at(now), None);
    }
}
