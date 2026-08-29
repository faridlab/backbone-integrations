//! Guard + scheduler probes for the OAuth outbound lane (hand-authored,
//! user-owned): the fail-closed endpoint guard and the refresh-before-expiry
//! job.
//!
//! Two probe families:
//!
//! - **Guard (outbound safety)** — the endpoint rule set rejects every
//!   malicious override shape; a bad override yields no endpoints at
//!   config-load time AND zero outbound calls at request time (the refresh
//!   path runs the guard before any bytes leave the process); the production
//!   client refuses redirects by construction; the resolution guard refuses
//!   private-range answers.
//! - **Scheduler (refresh-before-expiry)** — a due account rotates through
//!   the credential port with a NEW honest expiry and a fresh
//!   `last_refreshed_at`; a not-due account is untouched; `invalid_grant`
//!   and unreadable credentials move the account to `expired` with no store
//!   write; a provider answer without an expiry is refused as unstoreable;
//!   two concurrent runs claim disjoint accounts (`FOR UPDATE SKIP LOCKED`)
//!   with no double rotation.
//!
//! The DB-bound probes need the account table. Each probe runs against a
//! throwaway per-test database created on the scratch server and shaped by
//! the module's own migration files applied verbatim (the real enum names,
//! `pkce_verifier`, audit triggers, RLS policy) — nothing shared is dropped
//! or reshaped, and no hand-rolled approximation can drift from the
//! migration.

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use backbone_integrations::application::service::integrations_oauth_ports::{
    OAuthCredentialStore, TokenBundle, PURPOSE_OAUTH_TOKEN,
};
use backbone_integrations::infrastructure::http::endpoint_guard::{
    assert_public_resolution, EndpointOverrides, IdentityClaims, OAuthClientConfig,
    OAuthClientConfigs, OAuthTransport, ProviderEndpointOverride, ProviderRegistry,
    ReqwestOAuthTransport, TokenRequestForm, TokenResponse, TransportFailure,
    TransportFailureKind, ValidatedEndpoint, ValidatedEndpoints, PROVIDER_GMAIL,
};
use backbone_integrations::infrastructure::jobs::refresh_oauth_credentials::{
    refresh_oauth_credentials, refresh_oauth_credentials_for_companies, RefreshReport,
    RefreshSchedule,
};
use chrono::{Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Fakes
// ─────────────────────────────────────────────────────────────────────────────

/// A scripted [`OAuthTransport`]: records every URL it is handed (the guard
/// probes assert this stays EMPTY on rejection paths), optionally delays each
/// exchange (the concurrency probe needs the claim window held open), and
/// answers from a script — an empty script answers a normal 3600s response.
#[derive(Clone, Default)]
struct FakeTransport {
    urls: Arc<Mutex<Vec<String>>>,
    script: Arc<Mutex<VecDeque<Result<TokenResponse, TransportFailure>>>>,
    delay_ms: u64,
}

impl FakeTransport {
    fn new() -> Self {
        Self::default()
    }

    fn with_delay(ms: u64) -> Self {
        Self { delay_ms: ms, ..Self::default() }
    }

    fn script(&self, responses: Vec<Result<TokenResponse, TransportFailure>>) {
        *self.script.lock().unwrap() = responses.into();
    }

    fn recorded_urls(&self) -> Vec<String> {
        self.urls.lock().unwrap().clone()
    }

    fn call_count(&self) -> usize {
        self.urls.lock().unwrap().len()
    }

    fn normal_response() -> TokenResponse {
        TokenResponse {
            access_token: "NEXT-ACCESS-TOKEN".into(),
            refresh_token: Some("NEXT-REFRESH-TOKEN".into()),
            expires_in: Some(3600),
            scope: Some("https://mail.google.com/".into()),
            id_token: None,
            token_type: Some("Bearer".into()),
        }
    }
}

#[async_trait::async_trait]
impl OAuthTransport for FakeTransport {
    async fn exchange(
        &self,
        endpoint: &ValidatedEndpoint,
        _form: &TokenRequestForm,
    ) -> Result<TokenResponse, TransportFailure> {
        self.urls.lock().unwrap().push(endpoint.as_str().to_string());
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
        let next = self.script.lock().unwrap().pop_front();
        match next {
            Some(result) => result,
            None => Ok(Self::normal_response()),
        }
    }

    async fn fetch_identity(
        &self,
        endpoint: &ValidatedEndpoint,
        _access_token: &str,
    ) -> Result<IdentityClaims, TransportFailure> {
        self.urls.lock().unwrap().push(endpoint.as_str().to_string());
        Ok(Default::default())
    }
}

fn clients_for(providers: &[&str]) -> OAuthClientConfigs {
    let mut map = std::collections::BTreeMap::new();
    for provider in providers {
        map.insert(
            provider.to_string(),
            OAuthClientConfig { client_id: format!("{provider}-client"), client_secret: None },
        );
    }
    OAuthClientConfigs(map)
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard probes (no DB)
// ─────────────────────────────────────────────────────────────────────────────

/// The DB probes share one probe database whose harness drops and recreates
/// the account table per test — so they run serialized, DB test by DB test.
static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn db_guard() -> tokio::sync::MutexGuard<'static, ()> {
    DB_LOCK.lock().await
}

/// GM-4: malicious overrides are refused at config-load time for EVERY
/// provider — the builder cannot produce endpoints from them.
#[test]
fn malicious_overrides_fail_closed_for_every_provider() {
    let registry = ProviderRegistry::with_builtin();
    let malicious: &[&str] = &[
        "http://oauth2.googleapis.com/token",             // plain-text scheme
        "https://evil.example.com/token",                 // off-allowlist host
        "https://user@oauth2.googleapis.com/token",       // userinfo component
        "https://127.0.0.1/token",                        // IP literal
        "https://oauth2.googleapis.com:8443/token",       // non-443 port
        "https://oauth2.googleapis.com/",                 // no real path
        "https://oauth2.googleapis.com/token?x=1",        // query string
        "https://accounts.google.com.evil.example/x",     // allowlist substring
    ];
    for provider in registry.providers() {
        for url in malicious {
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                provider.to_string(),
                ProviderEndpointOverride { token: Some((*url).to_string()), ..Default::default() },
            );
            let overrides = EndpointOverrides(map);
            assert!(
                ValidatedEndpoints::resolve(&registry, provider, &overrides).is_err(),
                "{provider} accepted malicious override {url}"
            );
        }
    }
}

/// GM-4: the request-time leg — inside the refresh path, a malicious override
/// yields ZERO outbound calls (the fake records nothing) and zero store
/// writes; the account is left due for a corrected config.
#[tokio::test]
async fn malicious_override_yields_zero_outbound_calls_in_the_refresh_path() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    let account_id = seed_account(&pool, company, "gmail", "due@example.com", "active", Some(300))
        .await;

    let mut map = std::collections::BTreeMap::new();
    map.insert(
        PROVIDER_GMAIL.to_string(),
        ProviderEndpointOverride {
            token: Some("https://evil.example.com/token".into()),
            ..Default::default()
        },
    );
    let evil = EndpointOverrides(map);
    let store = common::FakeStore::new();
    let transport = FakeTransport::new();

    let report = refresh_oauth_credentials(
        &pool,
        &ProviderRegistry::with_builtin(),
        &evil,
        &clients_for(&[PROVIDER_GMAIL]),
        &store,
        &transport,
        &RefreshSchedule { refresh_batch_size: 10, ..Default::default() },
    )
    .await
    .expect("run completes");

    assert_eq!(report, RefreshReport { refreshed: 0, expired: 0, skipped: 1 });
    assert!(transport.recorded_urls().is_empty(), "guard refusal must make zero outbound calls");
    assert!(store.calls().is_empty(), "guard refusal must make zero store calls");
    // The account is untouched and still due.
    let (status, window): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status::text, expires_at FROM integrations.integration_accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(status, "active");
    assert!(window.unwrap() < Utc::now() + ChronoDuration::seconds(400));
}

/// The production client refuses redirects by construction, and the
/// resolution guard refuses private-range answers (basic DNS-rebinding
/// closure) — both asserted through the public surface.
#[tokio::test]
async fn no_redirect_posture_and_private_range_refusal() {
    let transport = ReqwestOAuthTransport::new().expect("client builds");
    assert!(transport.redirect_policy_is_none(), "production transport must refuse redirects");

    for host in ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.254"] {
        let err = assert_public_resolution(host).await.expect_err("private range must be refused");
        assert_eq!(err.kind, TransportFailureKind::EndpointGuard);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduler probes (fresh DB)
// ─────────────────────────────────────────────────────────────────────────────

/// A due account rotates through the port with a NEW honest expiry, mirrors
/// it on the account row, and stamps `last_refreshed_at`.
#[tokio::test]
async fn due_account_rotates_with_new_honest_expiry() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    let account_id = seed_account(&pool, company, "gmail", "due@example.com", "active", Some(300))
        .await;

    let store = common::FakeStore::new();
    store
        .issue(
            company,
            "gmail",
            "due@example.com",
            PURPOSE_OAUTH_TOKEN,
            TokenBundle::new(
                "OLD-ACCESS".into(),
                Some("OLD-REFRESH".into()),
                Utc::now() + ChronoDuration::seconds(300),
                None,
            ),
            Utc::now() + ChronoDuration::seconds(300),
        )
        .await
        .expect("seed credential");

    let transport = FakeTransport::new();
    let before = Utc::now();
    let report = refresh_oauth_credentials(
        &pool,
        &ProviderRegistry::with_builtin(),
        &EndpointOverrides::default(),
        &clients_for(&[PROVIDER_GMAIL]),
        &store,
        &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("run");

    assert_eq!(report.refreshed, 1, "one due account refreshed");
    // The outbound call went to the VALIDATED registry endpoint.
    assert_eq!(transport.recorded_urls(), vec!["https://oauth2.googleapis.com/token".to_string()]);

    // The store saw read + rotate; the rotate carries the honest expiry
    // (now + 3600s, not the old 300s).
    let calls = store.calls();
    assert_eq!(store.rotate_count(), 1, "exactly one rotate");
    let rotated = calls
        .iter()
        .find_map(|c| match c {
            common::StoreCall::Rotated { expires_at, .. } => Some(*expires_at),
            _ => None,
        })
        .expect("rotate recorded");
    assert!(
        rotated > before + ChronoDuration::seconds(3500),
        "rotated expiry must be the honest new lifetime (got {rotated:?})"
    );

    // The account mirror follows the store.
    let (status, mirror, last_refreshed): (
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT status::text, expires_at, last_refreshed_at FROM integrations.integration_accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(status, "active");
    assert!(mirror > before + ChronoDuration::seconds(3500), "mirror carries the new expiry");
    assert!(last_refreshed.is_some(), "last_refreshed_at must be stamped");
}

/// A not-due account is untouched: no read, no rotate, no row change.
#[tokio::test]
async fn not_due_account_untouched() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    let account_id = seed_account(&pool, company, "gmail", "fine@example.com", "active", Some(7200))
        .await;

    let store = common::FakeStore::new();
    let transport = FakeTransport::new();
    let report = refresh_oauth_credentials(
        &pool,
        &ProviderRegistry::with_builtin(),
        &EndpointOverrides::default(),
        &clients_for(&[PROVIDER_GMAIL]),
        &store,
        &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("run");

    assert_eq!(report, RefreshReport::default());
    assert_eq!(transport.call_count(), 0);
    assert!(store.calls().is_empty());
    let (status, last_refreshed): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status::text, last_refreshed_at FROM integrations.integration_accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(status, "active");
    assert!(last_refreshed.is_none());
}

/// `invalid_grant` moves the account to `expired` (the reconnect surface)
/// with NO store write — the credential is left to the store's lazy expiry.
#[tokio::test]
async fn invalid_grant_expires_the_account_without_store_writes() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    let account_id = seed_account(&pool, company, "gmail", "dead@example.com", "active", Some(300))
        .await;

    let store = common::FakeStore::new();
    store
        .issue(
            company,
            "gmail",
            "dead@example.com",
            PURPOSE_OAUTH_TOKEN,
            TokenBundle::new(
                "OLD-ACCESS".into(),
                Some("POISONED-REFRESH".into()),
                Utc::now() + ChronoDuration::seconds(300),
                None,
            ),
            Utc::now() + ChronoDuration::seconds(300),
        )
        .await
        .expect("seed credential");

    let transport = FakeTransport::new();
    transport.script(vec![Err(TransportFailure::new(
        TransportFailureKind::InvalidGrant,
        "provider rejected the grant: invalid_grant",
    ))]);

    let report = refresh_oauth_credentials(
        &pool,
        &ProviderRegistry::with_builtin(),
        &EndpointOverrides::default(),
        &clients_for(&[PROVIDER_GMAIL]),
        &store,
        &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("run");

    assert_eq!(report.expired, 1);
    assert_eq!(report.refreshed, 0);
    assert_eq!(store.rotate_count(), 0, "no rotate on invalid_grant");
    assert_eq!(store.revoke_count(), 0, "no revoke from the job — lazy expiry is the store's");
    let status: String =
        sqlx::query_scalar("SELECT status::text FROM integrations.integration_accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(status, "expired");
}

/// An active account whose credential the store cannot read is drift: the
/// account moves to `expired`, zero rotations.
#[tokio::test]
async fn unreadable_credential_expires_the_account() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    let account_id =
        seed_account(&pool, company, "outlook", "drift@example.com", "active", Some(300)).await;

    let store = common::FakeStore::new(); // never issued → read refuses NotFound
    let transport = FakeTransport::new();
    let report = refresh_oauth_credentials(
        &pool,
        &ProviderRegistry::with_builtin(),
        &EndpointOverrides::default(),
        &clients_for(&["outlook"]),
        &store,
        &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("run");

    assert_eq!(report.expired, 1);
    assert_eq!(transport.call_count(), 0, "no outbound call without a readable credential");
    let status: String =
        sqlx::query_scalar("SELECT status::text FROM integrations.integration_accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(status, "expired");
}

/// A provider answer with no expiry is refused as unstoreable: the account
/// stays active and due, no rotation, the next tick retries.
#[tokio::test]
async fn response_without_expiry_is_unstoreable() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    let account_id = seed_account(&pool, company, "gmail", "lying@example.com", "active", Some(300))
        .await;

    let store = common::FakeStore::new();
    store
        .issue(
            company,
            "gmail",
            "lying@example.com",
            PURPOSE_OAUTH_TOKEN,
            TokenBundle::new(
                "OLD-ACCESS".into(),
                Some("OLD-REFRESH".into()),
                Utc::now() + ChronoDuration::seconds(300),
                None,
            ),
            Utc::now() + ChronoDuration::seconds(300),
        )
        .await
        .expect("seed credential");

    let transport = FakeTransport::new();
    transport.script(vec![Ok(TokenResponse {
        access_token: "NO-EXPIRY-TOKEN".into(),
        refresh_token: Some("R".into()),
        expires_in: None, // the provider claims no lifetime — unstoreable
        scope: None,
        id_token: None,
        token_type: Some("Bearer".into()),
    })]);

    let report = refresh_oauth_credentials(
        &pool,
        &ProviderRegistry::with_builtin(),
        &EndpointOverrides::default(),
        &clients_for(&[PROVIDER_GMAIL]),
        &store,
        &transport,
        &RefreshSchedule::default(),
    )
    .await
    .expect("run");

    assert_eq!(report.skipped, 1);
    assert_eq!(store.rotate_count(), 0, "an expiry-less response must never be stored");
    let (status, still_due): (String, bool) = sqlx::query_as(
        "SELECT status::text, expires_at < now() + interval '600 seconds' FROM integrations.integration_accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(status, "active");
    assert!(still_due, "the account stays due for the next tick");
}

/// Two concurrent runs claim disjoint accounts and nothing rotates twice —
/// the `FOR UPDATE SKIP LOCKED` pickup lock, exercised end to end with the
/// exchange held open long enough for the race window to be real.
#[tokio::test]
async fn concurrent_runs_claim_disjoint_accounts_without_double_rotation() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    let mut ids = Vec::new();
    for i in 0..4 {
        ids.push(seed_account(
            &pool,
            company,
            "gmail",
            &format!("racer{i}@example.com"),
            "active",
            Some(60 + i),
        )
        .await);
    }
    let store = common::FakeStore::new();
    for i in 0..4 {
        store
            .issue(
                company,
                "gmail",
                &format!("racer{i}@example.com"),
                PURPOSE_OAUTH_TOKEN,
                TokenBundle::new(
                    "OLD".into(),
                    Some("OLD-REFRESH".into()),
                    Utc::now() + ChronoDuration::seconds(60),
                    None,
                ),
                Utc::now() + ChronoDuration::seconds(60),
            )
            .await
            .expect("seed");
    }

    let transport = FakeTransport::with_delay(150);
    let pool_a = pool.clone();
    let pool_b = pool.clone();
    let run = |pool: PgPool, transport: FakeTransport, store: common::FakeStore| async move {
        refresh_oauth_credentials(
            &pool,
            &ProviderRegistry::with_builtin(),
            &EndpointOverrides::default(),
            &clients_for(&[PROVIDER_GMAIL]),
            &store,
            &transport,
            &RefreshSchedule::default(),
        )
        .await
        .expect("run")
    };
    let (report_a, report_b) = tokio::join!(
        run(pool_a, transport.clone(), store.clone()),
        run(pool_b, transport, store.clone())
    );

    let total = report_a.refreshed + report_b.refreshed;
    assert_eq!(total, 4, "every due account refreshed exactly once across both runs");
    assert_eq!(store.rotate_count(), 4, "four accounts, four rotations — no double rotation");
    for id in &ids {
        let (status, last): (String, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as("SELECT status::text, last_refreshed_at FROM integrations.integration_accounts WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_eq!(status, "active");
        assert!(last.is_some(), "every racer was mirrored");
    }
}

/// The claim mechanism itself: a row locked by one transaction is INVISIBLE
/// to a concurrent `FOR UPDATE SKIP LOCKED` claim, and reappears once the
/// lock releases.
#[tokio::test]
async fn skip_locked_hides_locked_rows_from_concurrent_claims() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    let id = seed_account(&pool, company, "gmail", "locked@example.com", "active", Some(300)).await;

    let mut tx_a = pool.begin().await.expect("tx a");
    let claim_a: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM integrations.integration_accounts
            WHERE status = 'active' AND expires_at IS NOT NULL
              AND expires_at < now() + make_interval(secs => $1)
            LIMIT 1 FOR UPDATE SKIP LOCKED"#,
    )
    .bind(600)
    .fetch_optional(&mut *tx_a)
    .await
    .expect("claim a");
    assert_eq!(claim_a, Some(id), "run A claims the due row");

    let mut tx_b = pool.begin().await.expect("tx b");
    let claim_b: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM integrations.integration_accounts
            WHERE status = 'active' AND expires_at IS NOT NULL
              AND expires_at < now() + make_interval(secs => $1)
            LIMIT 1 FOR UPDATE SKIP LOCKED"#,
    )
    .bind(600)
    .fetch_optional(&mut *tx_b)
    .await
    .expect("claim b");
    assert_eq!(claim_b, None, "run B must SKIP the row run A holds");

    tx_a.rollback().await.expect("release");
    let claim_b2: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM integrations.integration_accounts
            WHERE status = 'active' AND expires_at IS NOT NULL
              AND expires_at < now() + make_interval(secs => $1)
            LIMIT 1 FOR UPDATE SKIP LOCKED"#,
    )
    .bind(600)
    .fetch_optional(&mut *tx_b)
    .await
    .expect("claim b2");
    assert_eq!(claim_b2, Some(id), "the row reappears once the lock releases");
    tx_b.rollback().await.expect("release");
}

/// The per-company fan-out wraps the same sweep with the company scope bound
/// (the FORCE-RLS host surface).
#[tokio::test]
async fn per_company_fan_out_refreshes_scoped_accounts() {
    let _guard = db_guard().await;
    let pool = probe_db().await;
    let company = Uuid::new_v4();
    seed_account(&pool, company, "gmail", "scoped@example.com", "active", Some(300)).await;

    let store = common::FakeStore::new();
    store
        .issue(
            company,
            "gmail",
            "scoped@example.com",
            PURPOSE_OAUTH_TOKEN,
            TokenBundle::new(
                "OLD".into(),
                Some("OLD-REFRESH".into()),
                Utc::now() + ChronoDuration::seconds(300),
                None,
            ),
            Utc::now() + ChronoDuration::seconds(300),
        )
        .await
        .expect("seed");

    let transport = FakeTransport::new();
    let results = refresh_oauth_credentials_for_companies(
        &pool,
        &ProviderRegistry::with_builtin(),
        &EndpointOverrides::default(),
        &clients_for(&[PROVIDER_GMAIL]),
        &store,
        &transport,
        &RefreshSchedule::default(),
        &[company],
    )
    .await;
    assert_eq!(results.len(), 1);
    let (reported_company, report) = &results[0];
    assert_eq!(*reported_company, company);
    assert_eq!(report.as_ref().expect("run").refreshed, 1);
    assert_eq!(store.rotate_count(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Fresh-DB harness
// ─────────────────────────────────────────────────────────────────────────────

/// Connect to a THROWAWAY per-test database carrying the module's REAL
/// migration shape, applied verbatim from the migration files — never a
/// hand-rolled approximation. The scratch server is located via
/// `DATABASE_URL`; a uniquely-named database is created per call (left
/// behind — the scratch container is disposable), so the harness never
/// drops or reshapes anything a migration (or another test binary) owns,
/// and tests cannot interfere through shared rows. The RLS policy is part
/// of the applied shape; as everywhere in the fresh-DB recipe, the scratch
/// superuser bypasses it, so these probes exercise the claim/refresh logic
/// — the fence is proven by the migration probes against the real role.
async fn probe_db() -> PgPool {
    let mut server_url = url::Url::parse(&common::dburl()).expect("DATABASE_URL parses");
    server_url.set_path("postgres");
    let admin = PgPool::connect(server_url.as_str()).await.expect("connect the scratch server's maintenance database");
    let db_name = format!("oauth_guard_probe_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .expect("create a throwaway probe database (the recipe's scratch role must be allowed to CREATE DATABASE)");
    admin.close().await;

    let mut probe_url = url::Url::parse(&common::dburl()).expect("DATABASE_URL parses");
    probe_url.set_path(&db_name);
    let pool = PgPool::connect(probe_url.as_str()).await.expect("connect the throwaway probe database");
    sqlx::raw_sql(include_str!("../migrations/20260821130001_create_integration_account_table.up.sql"))
        .execute(&pool)
        .await
        .expect("apply the account-table migration verbatim");
    sqlx::raw_sql(include_str!("../migrations/20260821130002_enable_integration_account_rls.up.sql"))
        .execute(&pool)
        .await
        .expect("apply the RLS migration verbatim");
    pool
}

/// Seed one account row; `expires_in_seconds` is relative to now (`None`
/// leaves the mirror empty — the pending shape).
async fn seed_account(
    pool: &PgPool,
    company_id: Uuid,
    provider: &str,
    account_ref: &str,
    status: &str,
    expires_in_seconds: Option<i64>,
) -> Uuid {
    let id = Uuid::new_v4();
    let expires_at = expires_in_seconds.map(|s| Utc::now() + ChronoDuration::seconds(s));
    sqlx::query(
        r#"INSERT INTO integrations.integration_accounts
               (id, company_id, provider, account_ref, status, expires_at)
           VALUES ($1, $2, $3::o_auth_provider, $4, $5::integration_account_status, $6)"#,
    )
    .bind(id)
    .bind(company_id)
    .bind(provider)
    .bind(account_ref)
    .bind(status)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("seed account");
    id
}
