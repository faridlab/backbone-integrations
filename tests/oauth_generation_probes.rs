//! OAuth generation probes (IOA series) — the proof suite for the one OAuth
//! generation: one HMAC-bound flow for all providers, the old public-callback
//! calendar flow fenced by construction, audience + nonce enforced, honest
//! token lifetimes, the credential store reached only through the port, and
//! the SSRF guard a real guard.
//!
//! Fresh-DB required (DATABASE_URL): probes write integration_accounts /
//! integration_events rows and snapshot-compare them. The credential store is
//! the FakeStore from `common` (every verb call recorded); the outbound
//! transport is the FakeTransport (every URL recorded) — the probes assert on
//! those logs, never on real network or secret material.

mod common;
use common::*;

use backbone_integrations::application::service::integrations_oauth::{
    AuthorizeRequest, CompleteRequest, IntegrationsOauthConfig, IntegrationsOauthService,
};
use backbone_integrations::infrastructure::http::endpoint_guard::{
    EndpointOverrides, IdentityClaims, OAuthClientConfig, OAuthClientConfigs, ProviderRegistry,
    ProviderEndpointOverride, ReqwestOAuthTransport, TokenResponse, TransportFailure,
    TransportFailureKind, ValidatedEndpoints,
};
use backbone_integrations::infrastructure::jobs::refresh_oauth_credentials::{
    refresh_oauth_credentials, RefreshSchedule,
};
use backbone_integrations::presentation::http::{create_oauth_routes, OAuthPrincipal};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Shared OAuth probe fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// The builtin registry — every provider the one generation serves.
fn registry() -> ProviderRegistry {
    ProviderRegistry::with_builtin()
}

/// One client registration per provider (a non-secret id; no secret needed).
fn clients() -> OAuthClientConfigs {
    let mut map = BTreeMap::new();
    for provider in registry().providers() {
        map.insert(
            provider.to_string(),
            OAuthClientConfig { client_id: format!("client-{provider}"), client_secret: None },
        );
    }
    OAuthClientConfigs(map)
}

fn overrides_for(provider: &str, o: ProviderEndpointOverride) -> EndpointOverrides {
    let mut map = BTreeMap::new();
    map.insert(provider.to_string(), o);
    EndpointOverrides(map)
}

// ─────────────────────────────────────────────────────────────────────────────
// Service-level fixtures (the one OAuth generation)
// ─────────────────────────────────────────────────────────────────────────────

const STATE_SECRET: &str = "probe-state-secret-0123456789abcdef0123456789abcdef";

fn oauth_config() -> IntegrationsOauthConfig {
    IntegrationsOauthConfig {
        public_base: Some("https://api.example.test".into()),
        clients: clients(),
        ..Default::default()
    }
}

/// Build the service through its public constructor — config validation, the
/// state signer from the environment, and BOTH ports injected as fakes.
fn oauth_service(
    pool: &PgPool,
    transport: FakeTransport,
    store: FakeStore,
) -> IntegrationsOauthService {
    std::env::set_var("INTEGRATIONS_OAUTH_STATE_SECRET", STATE_SECRET);
    IntegrationsOauthService::build(
        pool.clone(),
        oauth_config(),
        Arc::new(transport),
        Arc::new(store),
    )
    .expect("oauth service build")
}

/// Decode a signed state's payload (visible-but-unforgeable — the binding is
/// the signature, and the probe needs the nonce it minted).
fn decode_state(state: &str) -> serde_json::Value {
    let (payload, _) = state.split_once('.').expect("state payload.mac shape");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("state payload is base64url");
    serde_json::from_slice(&bytes).expect("state payload is JSON")
}

/// Mint a state with the service's OWN key material (the probe knows the env
/// var it set) — the only way to produce a WELL-SIGNED state with hostile
/// claims (expired, wrong provider) for the fence probes.
fn mint_state(account_id: Uuid, provider: &str, nonce: &str, exp: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let payload = serde_json::json!({ "account_id": account_id, "provider": provider, "nonce": nonce, "exp": exp });
    let mut mac = Hmac::<Sha256>::new_from_slice(STATE_SECRET.as_bytes()).unwrap();
    mac.update(payload.to_string().as_bytes());
    format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// The company's account rows (id, status, account_ref) — the snapshot the
/// zero-write probes compare before/after a rejection.
async fn account_rows(pool: &PgPool, company: Uuid) -> Vec<(Uuid, String, String)> {
    sqlx::query_as(
        "SELECT id, status::text, account_ref FROM integrations.integration_accounts WHERE company_id=$1 ORDER BY account_ref",
    )
    .bind(company)
    .fetch_all(pool)
    .await
    .expect("snapshot account rows")
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-8 — GM-4: the SSRF guard is a real guard (deny-by-default, fail-closed)
// ─────────────────────────────────────────────────────────────────────────────

// Malicious endpoint overrides are refused at resolution — every class that
// Odoo's stripped-able `assert` never covered: plaintext scheme, off-allowlist
// host, userinfo credentials, IP-literal host, non-443 port.
#[tokio::test]
async fn ioa8_malicious_overrides_are_refused_at_resolution() {
    let reg = registry();
    let cases: &[(&str, &str)] = &[
        ("http scheme", "http://accounts.google.com/o/oauth2/v2/auth"),
        ("off-allowlist host", "https://evil.example.com/oauth2/auth"),
        ("allowlist-suffix trick", "https://accounts.google.com.evil.example.com/auth"),
        ("userinfo component", "https://user@accounts.google.com/o/oauth2/v2/auth"),
        ("IP literal", "https://127.0.0.1/oauth2/auth"),
        ("non-443 port", "https://accounts.google.com:8443/o/oauth2/v2/auth"),
        ("empty path", "https://accounts.google.com/"),
        ("query string", "https://accounts.google.com/auth?next=/steal"),
    ];
    for (label, url) in cases {
        let ov = overrides_for(
            "gmail",
            ProviderEndpointOverride { authorize: Some((*url).into()), token: None, userinfo: None },
        );
        let resolved = ValidatedEndpoints::resolve(&reg, "gmail", &ov);
        assert!(resolved.is_err(), "{label}: malicious override accepted ({url})");
    }
}

// The no-override default resolves: registry values pass the guard unchanged
// for every provider the one generation serves.
#[tokio::test]
async fn ioa8_registry_defaults_resolve_cleanly() {
    let reg = registry();
    let providers = reg.providers();
    assert_eq!(providers.len(), 4, "exactly the four providers of the one generation");
    for provider in providers {
        ValidatedEndpoints::resolve(&reg, provider, &EndpointOverrides::default())
            .unwrap_or_else(|e| panic!("{}: registry default rejected: {e:?}", provider));
    }
}

// A well-formed override on an allowlisted host IS accepted (the guard permits
// legitimate configuration; it is not a blanket deny).
#[tokio::test]
async fn ioa8_legitimate_override_accepted() {
    let reg = registry();
    let ov = overrides_for(
        "gmail",
        ProviderEndpointOverride {
            authorize: Some("https://accounts.google.com/custom/auth".into()),
            token: None,
            userinfo: None,
        },
    );
    let endpoints = ValidatedEndpoints::resolve(&reg, "gmail", &ov).expect("legitimate override refused");
    assert_eq!(endpoints.authorize.as_str(), "https://accounts.google.com/custom/auth");
}

// The real transport is constructed with redirect policy NONE — a redirect
// chain cannot walk the exchange off its guarded endpoint.
#[tokio::test]
async fn ioa8_real_transport_has_no_redirect_policy() {
    let transport = ReqwestOAuthTransport::new().expect("transport construction");
    assert!(
        transport.redirect_policy_is_none(),
        "the OAuth transport must never follow redirects"
    );
}

// An endpoint from ANOTHER provider's allowlist is refused for this provider
// (per-provider allowlists, not one global list).
#[tokio::test]
async fn ioa8_cross_provider_host_refused() {
    let reg = registry();
    let ov = overrides_for(
        "gmail",
        ProviderEndpointOverride {
            authorize: Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into()),
            token: None,
            userinfo: None,
        },
    );
    assert!(
        ValidatedEndpoints::resolve(&reg, "gmail", &ov).is_err(),
        "a Microsoft host must not serve as gmail's authorize endpoint"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-9 — refresh-before-expiry: rotate lineage, honest new expiry, SKIP LOCKED
// ─────────────────────────────────────────────────────────────────────────────

// The sweep probes drive the UNSCOPED scheduler entry point (the declared
// handler), which claims ANY due account. On the shared probe database that
// means sweep tests must not race each other's rows: serialize them on one
// lock, and make every test that leaves a due row behind (the retryable
// postures) retire it before releasing.
static SWEEP_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
async fn sweep_gate() -> tokio::sync::MutexGuard<'static, ()> {
    SWEEP_LOCK.get_or_init(|| tokio::sync::Mutex::new(())).lock().await
}

/// Seed one ACTIVE account row whose expiry mirror is `due_in` seconds away,
/// and (unless `bare`) issue it a live credential in the fake store.
async fn seed_active_account(
    pool: &PgPool,
    company: Uuid,
    account_ref: &str,
    due_in: i64,
    store: &FakeStore,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO integrations.integration_accounts
               (id, company_id, provider, account_ref, status, scopes, expires_at)
           VALUES ($1, $2, 'gmail', $3, 'active', '', now() + make_interval(secs => $4))"#,
    )
    .bind(id)
    .bind(company)
    .bind(account_ref)
    .bind(due_in)
    .execute(pool)
    .await
    .expect("seed account");
    store
        .issue(
            company,
            "gmail",
            account_ref,
            PURPOSE_OAUTH_TOKEN,
            TokenBundle::new(
                "SEED-ACCESS".into(),
                Some("SEED-REFRESH".into()),
                Utc::now() + Duration::hours(24),
                None,
            ),
            Utc::now() + Duration::hours(24),
        )
        .await
        .expect("seed credential");
    id
}

async fn account_state(pool: &PgPool, id: Uuid) -> (String, Option<chrono::DateTime<Utc>>, Option<chrono::DateTime<Utc>>) {
    sqlx::query_as(
        "SELECT status::text, expires_at, last_refreshed_at FROM integrations.integration_accounts WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("account row")
}

// A due account rotates through the port with a NEW honest expiry; the mirror
// and last_refreshed_at advance with it.
#[tokio::test]
async fn ioa9_due_account_rotates_with_new_honest_expiry() {
    let _gate = sweep_gate().await;
    let pool = pool().await;
    let company = Uuid::new_v4();
    let store = FakeStore::new();
    let transport = FakeTransport::happy("user@example.com", "client-gmail", "nonce-x");
    let account =
        seed_active_account(&pool, company, "due-user@example.com", 300, &store).await;
    let before_expires_at = Utc::now() + Duration::seconds(300);

    let report = refresh_oauth_credentials(
        &pool, &registry(), &EndpointOverrides::default(), &clients(), &store, &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("refresh run");

    assert_eq!(report.refreshed, 1, "one due account refreshed: {report:?}");
    assert_eq!(store.rotate_count(), 1, "the rotation rode the credential port");
    match store.calls().iter().find(|c| matches!(c, StoreCall::Rotated { .. })) {
        Some(StoreCall::Rotated { expires_at, .. }) => {
            let got = *expires_at;
            let expect = Utc::now() + Duration::seconds(86_400);
            assert!(
                got + Duration::seconds(5) > expect && expect + Duration::seconds(5) > got,
                "rotated expiry must be now + expires_in (got {got:?}, want ~{expect:?})"
            );
        }
        other => panic!("no rotate call recorded: {other:?}"),
    }
    let (status, expires_at, last_refreshed_at) = account_state(&pool, account).await;
    assert_eq!(status, "active");
    let mirror = expires_at.expect("active account keeps its expiry mirror");
    assert!(
        mirror > before_expires_at + Duration::hours(23),
        "the mirror advanced to the new honest expiry (got {mirror:?})"
    );
    assert!(last_refreshed_at.is_some(), "last_refreshed_at recorded");
    assert_eq!(store.revoke_count(), 0, "rotation is not a revoke");
}

// A not-yet-due account is untouched.
#[tokio::test]
async fn ioa9_not_due_account_untouched() {
    let _gate = sweep_gate().await;
    let pool = pool().await;
    let company = Uuid::new_v4();
    let store = FakeStore::new();
    let transport = FakeTransport::happy("user@example.com", "client-gmail", "nonce-x");
    let account = seed_active_account(&pool, company, "far-user@example.com", 86_400, &store).await;

    let report = refresh_oauth_credentials(
        &pool, &registry(), &EndpointOverrides::default(), &clients(), &store, &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("refresh run");

    assert_eq!(report.refreshed, 0, "nothing due: {report:?}");
    assert_eq!(store.rotate_count(), 0);
    let (_, expires_at, last_refreshed_at) = account_state(&pool, account).await;
    assert!(expires_at.is_some() && last_refreshed_at.is_none(), "row untouched");
}

// Two CONCURRENT runs claim disjoint account sets (FOR UPDATE SKIP LOCKED is
// the claim): N due accounts, N rotations total, each scope exactly once.
#[tokio::test]
async fn ioa9_concurrent_runs_claim_disjoint_sets() {
    let _gate = sweep_gate().await;
    let pool = pool().await;
    let company = Uuid::new_v4();
    let store = FakeStore::new();
    let transport = FakeTransport::happy("user@example.com", "client-gmail", "nonce-x");
    let n = 6;
    let mut refs = Vec::new();
    for i in 0..n {
        let r = format!("race-{i}@example.com");
        seed_active_account(&pool, company, &r, 300, &store).await;
        refs.push(r);
    }

    let schedule = RefreshSchedule::default();
    let reg = registry();
    let ov = EndpointOverrides::default();
    let cl = clients();
    let (a, b) = tokio::join!(
        refresh_oauth_credentials(&pool, &reg, &ov, &cl, &store, &transport, &schedule),
        refresh_oauth_credentials(&pool, &reg, &ov, &cl, &store, &transport, &schedule),
    );
    let (a, b) = (a.expect("run a"), b.expect("run b"));
    assert_eq!(a.refreshed + b.refreshed, n, "every due account refreshed exactly once: {a:?} + {b:?}");

    let rotations: Vec<(String, String)> = store
        .calls()
        .iter()
        .filter_map(|c| match c {
            StoreCall::Rotated { account_ref, provider, .. } => Some((provider.clone(), account_ref.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(rotations.len(), n, "N rotations, no more");
    let distinct: std::collections::HashSet<_> = rotations.iter().collect();
    assert_eq!(distinct.len(), n, "no account rotated twice — claims were disjoint");
    assert!(refs.iter().all(|r| distinct.contains(&("gmail".to_string(), r.clone()))));
}

// invalid_grant expires the account (terminal reconnect surface); the
// credential is left to the store's lazy expiry, never force-revoked.
#[tokio::test]
async fn ioa9_invalid_grant_expires_account() {
    let _gate = sweep_gate().await;
    let pool = pool().await;
    let company = Uuid::new_v4();
    let store = FakeStore::new();
    let transport = FakeTransport::happy("dead@example.com", "client-gmail", "nonce-x");
    transport.fail_with(TransportFailure::new(TransportFailureKind::InvalidGrant, "refresh token expired"));
    let account = seed_active_account(&pool, company, "dead@example.com", 300, &store).await;

    let report = refresh_oauth_credentials(
        &pool, &registry(), &EndpointOverrides::default(), &clients(), &store, &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("refresh run");

    assert_eq!(report.expired, 1, "the dead refresh grant expired its account: {report:?}");
    assert_eq!(store.rotate_count(), 0);
    assert_eq!(store.revoke_count(), 0, "expiry is not a store revoke — lazy store expiry owns it");
    let (status, _, _) = account_state(&pool, account).await;
    assert_eq!(status, "expired", "terminal expired; the user must reconnect");
}

// A store outage skips (retryable), never expires the account.
#[tokio::test]
async fn ioa9_store_outage_skips_not_expires() {
    let _gate = sweep_gate().await;
    let pool = pool().await;
    let company = Uuid::new_v4();
    let store = FakeStore::new();
    let transport = FakeTransport::happy("flaky@example.com", "client-gmail", "nonce-x");
    let account = seed_active_account(&pool, company, "flaky@example.com", 300, &store).await;
    store.fail_with(OAuthCredentialFailure::transport("store unreachable"));

    let report = refresh_oauth_credentials(
        &pool, &registry(), &EndpointOverrides::default(), &clients(), &store, &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("refresh run");

    assert_eq!(report.skipped, 1, "a transport-class store failure is retryable: {report:?}");
    assert_eq!(report.expired, 0);
    let (status, _, _) = account_state(&pool, account).await;
    assert_eq!(status, "active", "an outage must not expire a healthy account");
    // The skipped row stays due — retire it so later sweeps stay isolated.
    sqlx::query("UPDATE integrations.integration_accounts SET status='revoked' WHERE id=$1")
        .bind(account)
        .execute(&pool)
        .await
        .unwrap();
}

// The provider answering with NO expiry is refused as unstoreable — the sweep
// skips the account (retryable posture), never stores an eternal token.
#[tokio::test]
async fn ioa9_unstoreable_answer_skips() {
    let _gate = sweep_gate().await;
    let pool = pool().await;
    let company = Uuid::new_v4();
    let store = FakeStore::new();
    let transport = FakeTransport::default();
    transport.set_token_response(TokenResponse {
        access_token: "NO-EXPIRY-TOKEN".into(),
        refresh_token: Some("NO-EXPIRY-REFRESH".into()),
        expires_in: None,
        scope: None,
        id_token: None,
        token_type: Some("Bearer".into()),
    });
    let account = seed_active_account(&pool, company, "eternal@example.com", 300, &store).await;

    let report = refresh_oauth_credentials(
        &pool, &registry(), &EndpointOverrides::default(), &clients(), &store, &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("refresh run");

    assert_eq!(store.rotate_count(), 0, "a permanent token is not a storeable value");
    assert_eq!(report.refreshed, 0, "{report:?}");
    let (status, _, _) = account_state(&pool, account).await;
    assert_eq!(status, "active", "unstoreable is a provider-side refusal, not an account expiry");
    // The skipped row stays due — retire it so later sweeps stay isolated.
    sqlx::query("UPDATE integrations.integration_accounts SET status='revoked' WHERE id=$1")
        .bind(account)
        .execute(&pool)
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-1 — GM-1: ONE generation serves ALL four providers
// ─────────────────────────────────────────────────────────────────────────────

// All four providers authorize through the one code path: the SAME signed
// state envelope (identical field set), the SAME authorize-URL parameter set,
// providers differing only through registry data (endpoint hosts, scopes,
// PKCE flag). No per-provider flow code is observable — that is the point.
#[tokio::test]
async fn ioa1_one_flow_serves_all_four_providers() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let transport = FakeTransport::default();
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store);

    let reg = registry();
    let mut envelope_keys: Option<Vec<String>> = None;
    for provider in reg.providers() {
        let account_ref = if provider.contains("calendar") { "calendar-user-42".to_string() } else { format!("user-{provider}@example.com") };
        let resp = svc
            .authorize(company, AuthorizeRequest { provider: provider.into(), account_ref, scopes: None })
            .await
            .unwrap_or_else(|e| panic!("{provider}: authorize through the one flow failed: {e}"));

        // ONE state envelope for every provider: same field set, same shape.
        let claims = decode_state(&state_of(&resp.authorize_url));
        let mut keys: Vec<String> = claims.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        match &envelope_keys {
            None => envelope_keys = Some(keys),
            Some(expected) => assert_eq!(&keys, expected, "{provider}: state envelope diverged from the one generation"),
        }
        assert_eq!(claims["account_id"].as_str().unwrap(), resp.account_id.to_string(), "{provider}: state binds the account");
        assert_eq!(claims["provider"].as_str().unwrap(), provider, "{provider}: state names its provider");

        // ONE authorize-URL construction: same parameter set everywhere.
        let url = url::Url::parse(&resp.authorize_url).unwrap();
        let params: Vec<String> = {
            let mut v: Vec<String> = url.query_pairs().map(|(k, _)| k.to_string()).collect();
            v.sort();
            v
        };
        for must in ["access_type", "client_id", "prompt", "redirect_uri", "response_type", "scope", "state"] {
            assert!(params.contains(&must.to_string()), "{provider}: authorize URL misses {must}: {params:?}");
        }
        assert_eq!(url.query_pairs().find(|(k, _)| k == "response_type").unwrap().1, "code");
        assert_eq!(
            url.query_pairs().find(|(k, _)| k == "redirect_uri").unwrap().1,
            "https://api.example.test/api/v1/integrations/oauth/callback",
            "the redirect target is the fixed deployment constant"
        );
        // Registry data is the ONLY thing that differs: host family + PKCE.
        let host = url.host_str().unwrap();
        let google_family = host.ends_with("google.com");
        let microsoft_family = host.ends_with("microsoftonline.com");
        let in_family = if provider.starts_with("google") || provider == "gmail" {
            google_family
        } else {
            microsoft_family
        };
        assert!(in_family, "{provider}: authorize host {host} outside its registry family");
        let pkce_in_url = params.iter().any(|k| k == "code_challenge");
        assert_eq!(
            pkce_in_url, reg.lookup(provider).unwrap().pkce_s256,
            "{provider}: PKCE presence must come from registry data, not flow code"
        );
    }

    // Four pending accounts, one per provider, all through the same path.
    let rows = account_rows(&pool, company).await;
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|(_, s, _)| s == "pending"));
}

// The flow validates the claimed identity shape at initiation: mail
// providers require a mailbox address.
#[tokio::test]
async fn ioa1_mail_providers_require_email_account_ref() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = oauth_service(&pool, FakeTransport::default(), FakeStore::new());
    let r = svc
        .authorize(company, AuthorizeRequest { provider: "gmail".into(), account_ref: "not-an-email".into(), scopes: None })
        .await;
    assert!(r.is_err(), "a gmail account_ref that is not an address must be refused at initiation");
}

/// Pull the state parameter back out of an authorize URL (the browser would
/// carry it through the provider round-trip).
fn state_of(authorize_url: &str) -> String {
    url::Url::parse(authorize_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .expect("authorize URL carries the state")
        .1
        .to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-2 — GM-2: the old unsigned public-callback flow is fenced by construction
// ─────────────────────────────────────────────────────────────────────────────

// Garbage, tampered, expired, and provider-mismatched states are ALL refused
// with ZERO writes — the callback pair verifies an HMAC state (constant-time,
// mandatory expiry) before anything is read or written.
#[tokio::test]
async fn ioa2_state_fence_rejects_every_forgery_class() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let transport = FakeTransport::happy("fence@example.com", "client-gmail", "nonce-x");
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport.clone(), store.clone());

    let resp = svc
        .authorize(company, AuthorizeRequest { provider: "gmail".into(), account_ref: "fence@example.com".into(), scopes: None })
        .await
        .expect("authorize");
    let good_state = state_of(&resp.authorize_url);
    let snapshot = account_rows(&pool, company).await;

    // Garbage (the old flow's unsigned "state").
    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: "garbage".into() }).await;
    assert!(matches!(r, Err(backbone_integrations::application::service::integrations_oauth::OauthError::State(_))), "unsigned garbage state accepted: {r:?}");
    // Tampered payload (one byte flipped, signature now stale).
    let tampered = flip_a_byte(&good_state, 0);
    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: tampered }).await;
    assert!(matches!(r, Err(backbone_integrations::application::service::integrations_oauth::OauthError::State(_))), "tampered state accepted: {r:?}");
    // Expired (well-signed by the service's own key, exp in the past).
    let expired = mint_state(resp.account_id, "gmail", "nonce-x", Utc::now().timestamp() - 100);
    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: expired }).await;
    assert!(matches!(r, Err(backbone_integrations::application::service::integrations_oauth::OauthError::State(_))), "expired state accepted: {r:?}");
    // Provider mismatch (well-signed, but for a different provider than the account).
    let alien = mint_state(resp.account_id, "outlook", "nonce-x", Utc::now().timestamp() + 300);
    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: alien }).await;
    assert!(matches!(r, Err(backbone_integrations::application::service::integrations_oauth::OauthError::State(_))), "cross-provider state accepted: {r:?}");

    assert_eq!(account_rows(&pool, company).await, snapshot, "a forged state changed rows");
    assert!(store.calls().is_empty(), "a forged state touched the credential store");
    assert_eq!(transport.call_count(), 0, "a forged state reached the network");
}

/// Flip one base64url character in one half of the state (payload half for
/// `seg` 0, signature half for `seg` 1), keeping it well-formed.
fn flip_a_byte(state: &str, seg: usize) -> String {
    let parts: Vec<&str> = state.splitn(2, '.').collect();
    let mut half = parts[seg].to_string();
    let mut chars: Vec<char> = half.chars().collect();
    let i = chars.len() / 2;
    chars[i] = match chars[i] {
        'A' => 'B',
        c => char::from(c as u8 - 1),
    };
    half = chars.into_iter().collect();
    if seg == 0 { format!("{half}.{}", parts[1]) } else { format!("{}.{half}", parts[0]) }
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-3 — CSRF: constant-time compare, no oracle, no partial work
// ─────────────────────────────────────────────────────────────────────────────

// A flipped byte in the SIGNATURE half is refused; the account stays pending
// and nothing is issued — the compare leaks nothing and nothing runs first.
#[tokio::test]
async fn ioa3_flipped_signature_byte_rejected_no_side_effects() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let transport = FakeTransport::happy("csrf@example.com", "client-gmail", "nonce-x");
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport.clone(), store.clone());

    let resp = svc
        .authorize(company, AuthorizeRequest { provider: "gmail".into(), account_ref: "csrf@example.com".into(), scopes: None })
        .await
        .expect("authorize");
    let state = state_of(&resp.authorize_url);

    let flipped = flip_a_byte(&state, 1);
    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: flipped }).await;
    assert!(r.is_err(), "a flipped signature byte passed verification");
    let rows = account_rows(&pool, company).await;
    assert_eq!(rows.len(), 1, "the pending account is the only row");
    assert_eq!(rows[0].1, "pending", "the account stays pending");
    assert!(store.calls().is_empty(), "no credential was issued for a forged state");
    assert_eq!(transport.call_count(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-4 — O-2: audience check + nonce binding enforced
// ─────────────────────────────────────────────────────────────────────────────

// The well-behaved round trip first (the control): audience == client_id and
// nonce == the state's nonce complete the account.
#[tokio::test]
async fn ioa4_control_matching_audience_and_nonce_complete() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let resp_authorize = run_authorize(&pool, company, "match@example.com").await;
    let claims = decode_state(&resp_authorize.state);
    let nonce = claims["nonce"].as_str().unwrap().to_string();

    let transport = FakeTransport::happy("match@example.com", "client-gmail", &nonce);
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store.clone());
    let out = svc
        .complete(company, CompleteRequest { code: "AUTH-CODE".into(), state: resp_authorize.state })
        .await
        .expect("the control round trip must complete");
    assert_eq!(out.status, "active");
    assert_eq!(store.issue_count(), 1);
}

// The realistic echo: real Google/Microsoft put aud + nonce in the id_token
// and NOT in userinfo. Two things must hold for the round trip to survive a
// real provider: the authorize REQUEST carries the nonce (a provider can
// only echo what it received), and completion verifies it through the
// id_token decode path.
#[tokio::test]
async fn ioa4_realistic_echo_request_carries_nonce_idtoken_completes() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = oauth_service(&pool, FakeTransport::default(), FakeStore::new());
    let resp = svc
        .authorize(company, AuthorizeRequest { provider: "gmail".into(), account_ref: "echo@example.com".into(), scopes: None })
        .await
        .expect("authorize");
    let url = url::Url::parse(&resp.authorize_url).unwrap();
    let request_nonce = url
        .query_pairs()
        .find(|(k, _)| k == "nonce")
        .expect("the authorize request must carry the nonce pair (the provider echoes what it receives)")
        .1
        .to_string();
    assert!(!request_nonce.is_empty(), "the nonce pair must be non-empty");
    let state = state_of(&resp.authorize_url);
    assert_eq!(
        decode_state(&state)["nonce"].as_str().unwrap(),
        request_nonce,
        "the request nonce and the signed state's nonce are the same mint"
    );

    // Userinfo with NO audience/nonce; the id_token is the only echo source.
    let transport = FakeTransport::realistic_idtoken_echo("echo@example.com", "client-gmail", &request_nonce);
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store.clone());
    let out = svc
        .complete(company, CompleteRequest { code: "AUTH-CODE".into(), state })
        .await
        .expect("the realistic-echo round trip must complete via the id_token decode path");
    assert_eq!(out.status, "active");
    assert_eq!(store.issue_count(), 1);
}

// Audience ≠ configured client_id ⇒ token substitution rejected, account
// stays pending, zero writes. Nonce ≠ state nonce ⇒ replay rejected, same.
#[tokio::test]
async fn ioa4_audience_and_nonce_mismatches_rejected_zero_writes() {
    let pool = pool().await;
    let company = Uuid::new_v4();

    // Audience mismatch.
    let a = run_authorize(&pool, company, "aud@example.com").await;
    let nonce = decode_state(&a.state)["nonce"].as_str().unwrap().to_string();
    let transport = FakeTransport::happy("aud@example.com", "attacker-client-id", &nonce);
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store.clone());
    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: a.state }).await;
    assert!(r.is_err(), "token with the attacker's audience accepted");
    assert_eq!(account_rows(&pool, company).await.len(), 1);
    assert_eq!(account_rows(&pool, company).await[0].1, "pending", "audience mismatch must leave the account pending");
    assert!(store.calls().is_empty() && store.rotate_count() == 0, "audience mismatch wrote to the store");

    // Nonce mismatch (audience correct — exactly one gate at a time).
    let b = run_authorize(&pool, company, "nonce@example.com").await;
    let transport = FakeTransport::happy("nonce@example.com", "client-gmail", "a-different-nonce");
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store.clone());
    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: b.state }).await;
    assert!(r.is_err(), "replayed nonce accepted");
    assert_eq!(account_rows(&pool, company).await[1].1, "pending", "nonce mismatch must leave the account pending");
    assert!(store.calls().is_empty() && store.rotate_count() == 0, "nonce mismatch wrote to the store");
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-5 — post-exchange identity match (the gen-2 email verification)
// ─────────────────────────────────────────────────────────────────────────────

// The server-side identity read must match the claimed account_ref; a
// mismatch (or an unverified email) leaves the account pending with no issue.
#[tokio::test]
async fn ioa5_identity_email_mismatch_rejected() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let a = run_authorize(&pool, company, "victim@example.com").await;
    let nonce = decode_state(&a.state)["nonce"].as_str().unwrap().to_string();

    // The attacker's mailbox on a valid token for THIS client+nonce.
    let transport = FakeTransport::happy("attacker@example.com", "client-gmail", &nonce);
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store.clone());
    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: a.state }).await;
    assert!(r.is_err(), "identity email ≠ account_ref accepted (the token-substitution link attack)");
    assert_eq!(account_rows(&pool, company).await[0].1, "pending", "the victim's account stays pending");
    assert!(store.calls().is_empty(), "no credential issued for a substituted identity");

    // Unverified email is refused outright.
    let b = run_authorize(&pool, company, "unverified@example.com").await;
    let nonce_b = decode_state(&b.state)["nonce"].as_str().unwrap().to_string();
    let transport = FakeTransport::happy("unverified@example.com", "client-gmail", &nonce_b);
    transport.set_identity(backbone_integrations::infrastructure::http::IdentityClaims {
        email: Some("unverified@example.com".into()),
        email_verified: Some(false),
        audience: Some("client-gmail".into()),
        nonce: Some(nonce_b),
        sub: Some("sub-u".into()),
    });
    let store2 = FakeStore::new();
    let svc2 = oauth_service(&pool, transport, store2.clone());
    let r = svc2.complete(company, CompleteRequest { code: "c".into(), state: b.state }).await;
    assert!(r.is_err(), "an unverified email passed the gauntlet");
    assert!(store2.calls().is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-6 — MPG-2: honest lifetimes (expires_at = now + expires_in, never NULL)
// ─────────────────────────────────────────────────────────────────────────────

// The stored credential and the account mirror BOTH carry now + expires_in.
#[tokio::test]
async fn ioa6_stored_credential_and_mirror_carry_honest_expiry() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let a = run_authorize(&pool, company, "honest@example.com").await;
    let nonce = decode_state(&a.state)["nonce"].as_str().unwrap().to_string();
    let transport = FakeTransport::happy("honest@example.com", "client-gmail", &nonce);
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store.clone());

    let before = Utc::now();
    let out = svc.complete(company, CompleteRequest { code: "c".into(), state: a.state }).await.expect("complete");
    let after = Utc::now();

    let expect_low = before + Duration::seconds(86_400);
    let expect_high = after + Duration::seconds(86_400);
    assert!(out.expires_at > expect_low && out.expires_at < expect_high, "outcome expiry is now + expires_in");
    match store.calls().first() {
        Some(StoreCall::Issued { purpose, expires_at, .. }) => {
            assert_eq!(purpose, PURPOSE_OAUTH_TOKEN, "the bundle is stored as an oauth_token credential");
            assert!(*expires_at > expect_low && *expires_at < expect_high, "the STORED expiry is now + expires_in (got {expires_at:?})");
        }
        other => panic!("no issue call recorded: {other:?}"),
    }
    let (status, mirror, refreshed_at) = sqlx::query_as::<_, (String, Option<chrono::DateTime<Utc>>, Option<chrono::DateTime<Utc>>)>(
        "SELECT status::text, expires_at, last_refreshed_at FROM integrations.integration_accounts WHERE id=$1",
    )
    .bind(a.account_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "active");
    let mirror = mirror.expect("an active account mirrors its expiry — never NULL on this path");
    assert!(mirror > expect_low && mirror < expect_high, "the mirror carries the same honest expiry");
    assert!(refreshed_at.is_some());
}

// A provider response with NO expiry is refused as unstoreable — "permanent"
// is not a value this flow will store.
#[tokio::test]
async fn ioa6_permanent_token_refused_as_unstoreable() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let a = run_authorize(&pool, company, "eternal2@example.com").await;
    let nonce = decode_state(&a.state)["nonce"].as_str().unwrap().to_string();
    let transport = FakeTransport::happy("eternal2@example.com", "client-gmail", &nonce);
    transport.set_token_response(TokenResponse {
        access_token: "NO-EXPIRY".into(),
        refresh_token: Some("NO-EXPIRY-REFRESH".into()),
        expires_in: None,
        scope: None,
        id_token: None,
        token_type: Some("Bearer".into()),
    });
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store.clone());

    let r = svc.complete(company, CompleteRequest { code: "c".into(), state: a.state }).await;
    assert!(matches!(r, Err(backbone_integrations::application::service::integrations_oauth::OauthError::Unstoreable(_))), "a permanent token was stored: {r:?}");
    assert!(store.calls().is_empty(), "nothing reached the store");
    assert_eq!(account_rows(&pool, company).await[0].1, "pending", "the account stays pending");
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-7 — GM-3/ADR-0024: the store is reached ONLY through the port
// ─────────────────────────────────────────────────────────────────────────────

// A full connect + disconnect touches the credential surface ONLY through the
// port verbs (issue, then revoke), and the account table never grows
// token-shaped columns — the module persists no secret material itself.
#[tokio::test]
async fn ioa7_all_credential_contact_rides_the_port() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let a = run_authorize(&pool, company, "port@example.com").await;
    let nonce = decode_state(&a.state)["nonce"].as_str().unwrap().to_string();
    let transport = FakeTransport::happy("port@example.com", "client-gmail", &nonce);
    let store = FakeStore::new();
    let svc = oauth_service(&pool, transport, store.clone());

    svc.complete(company, CompleteRequest { code: "c".into(), state: a.state }).await.expect("complete");
    svc.disconnect(company, a.account_id).await.expect("disconnect");

    let verbs: Vec<&'static str> = store.calls().iter().map(call_verb).collect();
    assert_eq!(verbs, vec!["issue", "revoke"], "exactly an issue then a revoke — no other store contact: {verbs:?}");
    let row_status = account_rows(&pool, company).await[0].1.clone();
    assert_eq!(row_status, "revoked", "disconnect is terminal on the account");

    // The account relation has no token-shaped columns (schema-level: no
    // secret material has anywhere to live on the flow's own table).
    let secretish: Vec<String> = sqlx::query_scalar(
        r#"SELECT column_name FROM information_schema.columns
            WHERE table_schema='integrations' AND table_name='integration_accounts'
              AND (column_name ILIKE '%token%' OR column_name ILIKE '%secret%'
                   OR column_name ILIKE '%cipher%' OR column_name ILIKE '%password%')"#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(secretish.is_empty(), "token-shaped columns on integration_accounts: {secretish:?}");
}

fn call_verb(c: &StoreCall) -> &'static str {
    match c {
        StoreCall::Issued { .. } => "issue",
        StoreCall::Read { .. } => "read",
        StoreCall::Rotated { .. } => "rotate",
        StoreCall::Revoked { .. } => "revoke",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-10 — ADR-0019: the GET callback is side-effect-free (auto-POST split)
// ─────────────────────────────────────────────────────────────────────────────

// The provider redirect target renders an auto-submitting POST form and
// changes NOTHING: same rows before and after, garbage state rejected, and
// no redirect target anywhere in the page.
#[tokio::test]
async fn ioa10_callback_page_writes_nothing() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let a = run_authorize(&pool, company, "cb@example.com").await;
    let store = FakeStore::new();
    let svc = oauth_service(&pool, FakeTransport::default(), store.clone());

    let snapshot = account_rows(&pool, company).await;
    let page = svc.callback_page("AUTH-CODE", &a.state).expect("callback page");
    assert_eq!(account_rows(&pool, company).await, snapshot, "the GET callback changed rows");
    assert!(store.calls().is_empty());

    // The RFC-8058 shape: a form POSTing code+state to the RELATIVE
    // completion action — never a redirect to any URL.
    assert!(page.contains("form"), "the page carries the auto-POST form");
    assert!(page.contains("complete"), "the form targets the completion action");
    assert!(page.contains("AUTH-CODE") && page.contains(&a.state), "the form carries code + state");
    assert!(!page.to_lowercase().contains("http-equiv=\"refresh\""), "no meta-refresh redirect");
    assert!(!page.contains("Location:"), "no redirect header in the page");

    // Garbage state on the GET → rejection, still zero writes.
    let r = svc.callback_page("c", "garbage");
    assert!(r.is_err());
    assert_eq!(account_rows(&pool, company).await, snapshot);
}

/// authorize helper returning (account_id, state) for gauntlet probes.
struct Authorized {
    account_id: Uuid,
    state: String,
}

async fn run_authorize(pool: &PgPool, company: Uuid, account_ref: &str) -> Authorized {
    let svc = oauth_service(pool, FakeTransport::default(), FakeStore::new());
    let resp = svc
        .authorize(company, AuthorizeRequest { provider: "gmail".into(), account_ref: account_ref.into(), scopes: None })
        .await
        .expect("authorize");
    Authorized { account_id: resp.account_id, state: state_of(&resp.authorize_url) }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP-surface helpers (route-fence + fail-closed authorization probes)
// ─────────────────────────────────────────────────────────────────────────────

/// The composing host's auth layer inserts this; the probes do the same to
/// reach the authed verbs in-process.
fn principal(company: Uuid, permissions: &[&str]) -> OAuthPrincipal {
    OAuthPrincipal {
        company_id: company,
        user_id: Some(Uuid::new_v4()),
        permissions: permissions.iter().map(|p| p.to_string()).collect(),
    }
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    String::from_utf8_lossy(&bytes).into_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-2 (route leg) — GM-2 fence: no old-flow route exists on the surface
// ─────────────────────────────────────────────────────────────────────────────

// The old calendar flow was per-provider OAuth routes with a PUBLIC callback
// and unsigned state (GM-2). The one generation is provider-uniform: exactly
// five paths, none of them per-provider. Every old-flow candidate must miss
// the route table entirely (404 with a principal attached — auth cannot
// resurrect a route that does not exist), and the five real verbs must be
// reachable (a wrong-method probe lands 405, proving the path is routed).
#[tokio::test]
async fn ioa2_old_flow_routes_are_absent_from_the_surface() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let router = create_oauth_routes(Arc::new(oauth_service(&pool, FakeTransport::default(), FakeStore::new())));

    let old_flow_candidates = [
        "/oauth/google/authorize",
        "/oauth/google/callback",
        "/oauth/google/complete",
        "/oauth/microsoft/authorize",
        "/oauth/microsoft/callback",
        "/oauth/gmail/authorize",
        "/oauth/gmail/callback",
        "/oauth/gmail/complete",
        "/oauth/outlook/authorize",
        "/oauth/outlook/callback",
        "/oauth/google_calendar/authorize",
        "/oauth/google_calendar/callback",
        "/oauth/microsoft_calendar/authorize",
        "/oauth/microsoft_calendar/callback",
        "/oauth/connect",
        "/oauth/token",
    ];
    for path in old_flow_candidates {
        for method in [Method::GET, Method::POST] {
            let req = Request::builder()
                .method(method.clone())
                .uri(path)
                .extension(principal(company, &["write:integrations", "delete:integrations"]))
                .body(Body::empty())
                .expect("request");
            let status = router.clone().oneshot(req).await.expect("oneshot").status();
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{method} {path}: an old-flow route must not exist on the one-generation surface"
            );
        }
    }

    // The five new-flow verbs ARE routed: same path, wrong method → 405 with
    // the principal attached (the layer passed; the method router answered).
    let id = Uuid::new_v4();
    let wrong_method_probes: Vec<(Method, String)> = vec![
        (Method::GET, "/oauth/authorize".into()),
        (Method::GET, "/oauth/complete".into()),
        (Method::GET, format!("/oauth/{id}/disconnect")),
        (Method::POST, "/oauth/callback".into()),
        (Method::POST, format!("/oauth/{id}/status")),
    ];
    for (method, path) in wrong_method_probes {
        let req = Request::builder()
            .method(method.clone())
            .uri(&path)
            .extension(principal(company, &["write:integrations", "delete:integrations"]))
            .body(Body::empty())
            .expect("request");
        let status = router.clone().oneshot(req).await.expect("oneshot").status();
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}: the new-flow verb must exist (wrong-method probe expected 405)"
        );
    }
}

// The fence at the HTTP layer: a forged state POSTed to the completion verb
// answers 400 OAUTH_STATE_REJECTED and writes nothing (the old flow's
// token-substitution class dies at the door).
#[tokio::test]
async fn ioa2_forged_state_on_the_http_verb_is_a_400_with_zero_writes() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let transport = FakeTransport::default();
    let store = FakeStore::new();
    let router = create_oauth_routes(Arc::new(oauth_service(&pool, transport.clone(), store.clone())));

    let before = account_rows(&pool, company).await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/complete")
        .header("content-type", "application/x-www-form-urlencoded")
        .extension(principal(company, &["write:integrations"]))
        .body(Body::from("code=attacker-code&state=Zm9yZ2Vk.dmFjZQ"))
        .expect("request");
    let response = router.oneshot(req).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "forged state must be a 400");
    let body = body_text(response).await;
    assert!(body.contains("OAUTH_STATE_REJECTED"), "the rejection names the state fence: {body}");

    assert_eq!(account_rows(&pool, company).await, before, "zero rows written");
    assert!(store.calls().is_empty(), "zero credential verbs");
    assert_eq!(transport.call_count(), 0, "zero outbound calls");
}

// ─────────────────────────────────────────────────────────────────────────────
// IOA-11 — authorization fails closed on the HTTP surface
// ─────────────────────────────────────────────────────────────────────────────

// Every authed verb answers 401 (with the unauthenticated code) when no
// validated principal rides the request — absence of auth information is
// never access. The callback alone is public: the provider's redirect cannot
// carry the caller's credentials.
#[tokio::test]
async fn ioa11_every_authed_verb_fails_closed_without_a_principal() {
    let pool = pool().await;
    let router = create_oauth_routes(Arc::new(oauth_service(&pool, FakeTransport::default(), FakeStore::new())));
    let id = Uuid::new_v4();

    let probes: Vec<(Method, String, Body)> = vec![
        (
            Method::POST,
            "/oauth/authorize".into(),
            Body::from(r#"{"provider":"gmail","account_ref":"nobody@example.com"}"#),
        ),
        (
            Method::POST,
            "/oauth/complete".into(),
            Body::from("code=x&state=y"),
        ),
        (Method::POST, format!("/oauth/{id}/disconnect"), Body::empty()),
        (Method::GET, format!("/oauth/{id}/status"), Body::empty()),
    ];
    for (method, path, body) in probes {
        let req = Request::builder()
            .method(method.clone())
            .uri(&path)
            .header("content-type", "application/json")
            .body(body)
            .expect("request");
        let response = router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method} {path} without a principal");
        let body = body_text(response).await;
        assert!(body.contains("OAUTH_UNAUTHENTICATED"), "{method} {path}: {body}");
    }

    // The callback stays PUBLIC — it must never demand a principal (the
    // provider's redirect carries none). A garbage state is rejected with a
    // 400 error page, not a 401 and not a redirect.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/oauth/callback?code=c&state=garbage")
        .body(Body::empty())
        .expect("request");
    let response = router.oneshot(req).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "public callback rejects garbage with 400");
    assert!(response.headers().get("location").is_none(), "no redirect on the callback");
}

// With a principal, each verb still enforces its own permission — no god
// grant: authorize/complete need write:integrations, disconnect needs
// delete:integrations, and status is metadata-only for any authenticated
// principal of the company.
#[tokio::test]
async fn ioa11_verbs_enforce_their_own_permissions() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let transport = FakeTransport::default();
    let store = FakeStore::new();
    let router = create_oauth_routes(Arc::new(oauth_service(&pool, transport.clone(), store.clone())));
    let id = Uuid::new_v4();

    // A principal with NO integration grants: authenticated, unauthorized.
    let bare = principal(company, &[]);

    let authorize = Request::builder()
        .method(Method::POST)
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
        .extension(bare.clone())
        .body(Body::from(r#"{"provider":"gmail","account_ref":"nobody@example.com"}"#))
        .expect("request");
    let response = router.clone().oneshot(authorize).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "authorize without write:integrations");

    let disconnect = Request::builder()
        .method(Method::POST)
        .uri(format!("/oauth/{id}/disconnect"))
        .extension(bare.clone())
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(disconnect).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "disconnect without delete:integrations");

    // A write-granted principal still cannot disconnect (separation holds).
    let writer = principal(company, &["write:integrations"]);
    let disconnect = Request::builder()
        .method(Method::POST)
        .uri(format!("/oauth/{id}/disconnect"))
        .extension(writer.clone())
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(disconnect).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "write grant does not confer delete");

    // The full-grant round trip: authorize through the HTTP layer writes the
    // pending row (the surface reaches the real service), and disconnect on
    // the resulting account passes its gate (a 204 revocation — proving the
    // gate, not the absence of the route).
    let full = principal(company, &["write:integrations", "delete:integrations"]);
    let authorize = Request::builder()
        .method(Method::POST)
        .uri("/oauth/authorize")
        .header("content-type", "application/json")
        .extension(full.clone())
        .body(Body::from(r#"{"provider":"gmail","account_ref":"route-probe@example.com"}"#))
        .expect("request");
    let response = router.clone().oneshot(authorize).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK, "authorize with the write grant");
    let outcome: serde_json::Value =
        serde_json::from_str(&body_text(response).await).expect("authorize response JSON");
    let account_id: Uuid = outcome["data"]["account_id"]
        .as_str()
        .expect("account_id in the authorize response")
        .parse()
        .expect("account_id is a uuid");

    let rows = account_rows(&pool, company).await;
    assert_eq!(rows.len(), 1, "the HTTP authorize wrote exactly one pending row");
    assert_eq!(rows[0].0, account_id);
    assert_eq!(rows[0].1, "pending");

    // Complete through the HTTP surface too: script the well-behaved provider
    // (audience = this flow's client id, nonce = the one the state carries,
    // email = the account_ref authorize bound), then submit the callback form.
    let authorize_url = outcome["data"]["authorize_url"]
        .as_str()
        .expect("authorize_url in the authorize response")
        .to_string();
    let state = state_of(&authorize_url);
    let nonce = decode_state(&state)["nonce"].as_str().expect("nonce in the state").to_string();
    transport.set_token_response(TokenResponse {
        access_token: "FAKE-ACCESS-TOKEN".into(),
        refresh_token: Some("FAKE-REFRESH-TOKEN".into()),
        expires_in: Some(86_400),
        scope: Some("https://mail.google.com/".into()),
        id_token: Some("FAKE-ID-TOKEN".into()),
        token_type: Some("Bearer".into()),
    });
    transport.set_identity(IdentityClaims {
        sub: Some("sub-route-probe@example.com".into()),
        email: Some("route-probe@example.com".into()),
        email_verified: Some(true),
        audience: Some("client-gmail".into()),
        nonce: Some(nonce.clone()),
    });
    let complete = Request::builder()
        .method(Method::POST)
        .uri("/oauth/complete")
        .header("content-type", "application/x-www-form-urlencoded")
        .extension(full.clone())
        .body(Body::from(format!("code=provider-code&state={state}")))
        .expect("request");
    let response = router.clone().oneshot(complete).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK, "complete with the write grant");
    let rows = account_rows(&pool, company).await;
    assert_eq!(rows[0].1, "active", "the HTTP complete activated the account");
    assert_eq!(call_verb(&store.calls()[0]), "issue", "the credential was issued through the port");

    let disconnect = Request::builder()
        .method(Method::POST)
        .uri(format!("/oauth/{account_id}/disconnect"))
        .extension(full.clone())
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(disconnect).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "disconnect with the delete grant");
    assert_eq!(store.calls().len(), 2, "the disconnect revoked through the port");
    assert_eq!(call_verb(&store.calls()[1]), "revoke");

    // status is metadata-only: any authenticated principal of the company
    // reads it without an integration grant.
    let status = Request::builder()
        .method(Method::GET)
        .uri(format!("/oauth/{account_id}/status"))
        .extension(bare)
        .body(Body::empty())
        .expect("request");
    let response = router.oneshot(status).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK, "status needs no integration grant");
}
