//! `refresh_oauth_credentials` — the refresh-before-expiry scheduled job
//! (hand-authored, user-owned).
//!
//! The declaration of record is the `scheduled_jobs.refresh_oauth_credentials`
//! block in `schema/hooks/index.hook.yaml`; this file is the handler it names.
//! Its declared posture (ADR-0020 vocabulary):
//!
//! - **`posture: pull`** — an interval-driven scan (`*/15 * * * *`). The
//!   interval is the FLOOR, never the contract: the account row's honest
//!   `expires_at` decides when a refresh is due, so a schedule gap degrades
//!   latency, never correctness. Request-path lazy refresh (refresh-on-use
//!   inside the expiry window) rides the same due-window computation and is
//!   available to future consumers without a second code path.
//! - **`pickup_lock: true`** — the claim is `SELECT ... FOR UPDATE SKIP
//!   LOCKED`, one account per short transaction. Two concurrent replicas
//!   (or a manual overlap with the interval) take disjoint accounts instead
//!   of double-refreshing.
//! - **`commit_policy: commit_per_batch`** — each account's refresh commits
//!   independently: claim, exchange, rotate, mirror, commit. One provider
//!   outage rolls back exactly its own account; the rest of the batch is not
//!   held hostage to it. The at-least-once window this opens (ADR-0017) is
//!   bounded by rotate-lineage semantics — a retried refresh rotates again,
//!   it never forks.
//!
//! Per-account flow:
//!
//! 1. **Claim** — the oldest account `status = 'active'` whose mirrored
//!    `expires_at` lands inside the refresh window
//!    (`expires_at < now + refresh_window_seconds`), locked `FOR UPDATE
//!    SKIP LOCKED` in its own transaction. The lock IS the claim: it is held
//!    for the account's full processing, then committed.
//! 2. **Read** — the current token bundle crosses the credential port
//!    ([`OAuthCredentialStore::read_token`]). A scope with no readable
//!    credential (never issued / revoked / expired past honesty) is account
//!    drift: the account moves to `expired` — the reconnect surface — and
//!    the store is left to its own lazy expiry, exactly as an
//!    `invalid_grant` below.
//! 3. **Exchange** — `grant_type=refresh_token` at the provider's VALIDATED
//!    token endpoint through [`OAuthTransport`]. A provider answer with no
//!    `expires_in` is refused as unstoreable (an honest lifetime is the only
//!    kind the flow stores); the account stays due and the next tick
//!    retries. `invalid_grant` (400) is the dead-refresh-token signal: the
//!    account moves to `expired` and the user must reconnect — the
//!    self-heal-to-reconnect behavior, minus the mid-transaction commit of
//!    the code this port replaces.
//! 4. **Rotate** — the successor bundle goes to the store through
//!    [`OAuthCredentialStore::rotate`] (lineage preserved; providers that
//!    hand back a fresh refresh token on every exchange — Microsoft — and
//!    providers that do not — Google — are handled by the same call: the
//!    successor keeps the previous refresh token only when the provider
//!    returned none).
//! 5. **Mirror** — the account row's advisory `expires_at` mirror moves to
//!    the successor's honest expiry and `last_refreshed_at` to now; commit.
//!    A crash between rotate and mirror leaves the mirror stale — the next
//!    tick re-claims the account and rotates again (lineage tolerates it);
//!    expiry TRUTH lives in the store, the mirror only drives scheduling.
//!
//! **Per-company handler**: under FORCE RLS a job cannot enumerate companies,
//! so the host enumerates its companies and calls
//! [`refresh_oauth_credentials_for_companies`] (ADR-0008). The company is
//! applied inside the sweep's claim step — an explicit predicate on the claim
//! SQL plus a transaction-local `app.company_id` bind on the claim connection
//! — so the RLS fence stays meaningful for the claim, the mirror, and the
//! expire writes alike. [`refresh_oauth_credentials`] is the unscoped variant
//! for compositions that do not enable RLS on
//! `integrations.integration_accounts`; under FORCE RLS no company is bound
//! and it sees zero rows (fail-closed, inert).

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tracing::{debug, warn};
use uuid::Uuid;

use backbone_orm::company_scope;

use crate::application::service::integrations_oauth_ports::{
    OAuthCredentialFailure, OAuthCredentialStore, TokenBundle, PURPOSE_OAUTH_TOKEN,
};
use crate::infrastructure::http::endpoint_guard::{
    EndpointOverrides, OAuthClientConfigs, OAuthTransport, ProviderRegistry, TokenRequestForm,
    TransportFailureKind, ValidatedEndpoints,
};

/// The due-window and batch knobs (the `oauth.refresh_window_seconds` /
/// `oauth.refresh_batch_size` configuration values). Defaults: refresh when
/// ten minutes remain; at most one hundred accounts per run.
#[derive(Debug, Clone, PartialEq)]
pub struct RefreshSchedule {
    /// Refresh when `expires_at` is less than this many seconds away.
    pub refresh_window_seconds: i64,
    /// Upper bound on accounts refreshed in one run. Not a loss: unclaimed
    /// accounts are still due, so the next tick (manual or interval) picks
    /// them up while their window still matches.
    pub refresh_batch_size: i64,
}

impl Default for RefreshSchedule {
    fn default() -> Self {
        Self { refresh_window_seconds: 600, refresh_batch_size: 100 }
    }
}

/// One run's counters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RefreshReport {
    /// Accounts claimed, refreshed, rotated, and mirrored this run.
    pub refreshed: usize,
    /// Accounts moved to `expired` (invalid_grant, or no readable
    /// credential — the reconnect surface).
    pub expired: usize,
    /// Accounts skipped on a retryable failure (store or transport
    /// unreachable, unstoreable provider answer). Left due; next tick
    /// retries.
    pub skipped: usize,
}

/// One due account, as claimed.
struct DueAccount {
    id: Uuid,
    company_id: Uuid,
    provider: String,
    account_ref: String,
}

/// Build the refresh grant form for one account: the provider's client
/// credentials plus the current refresh token. Omitting `scope` keeps the
/// originally granted scopes (the provider's refresh semantics).
fn refresh_form(
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> TokenRequestForm {
    TokenRequestForm {
        grant_type: "refresh_token".into(),
        code: None,
        refresh_token: Some(refresh_token.to_string()),
        redirect_uri: None,
        code_verifier: None,
        client_id: client_id.to_string(),
        client_secret: client_secret.map(str::to_string),
        scope: None,
    }
}

/// Run the refresh sweep (unscoped variant — for compositions without RLS on
/// `integrations.integration_accounts`; under FORCE RLS this sees zero rows).
pub async fn refresh_oauth_credentials(
    pool: &PgPool,
    registry: &ProviderRegistry,
    overrides: &EndpointOverrides,
    clients: &OAuthClientConfigs,
    store: &dyn OAuthCredentialStore,
    transport: &dyn OAuthTransport,
    schedule: &RefreshSchedule,
) -> Result<RefreshReport, sqlx::Error> {
    let mut report = RefreshReport::default();
    // The sweep's company scope, if the caller set one (the per-company
    // fan-out does). It is applied to the claim TWO ways, because ambient
    // task-locals never reach a raw sqlx statement: an explicit predicate on
    // the claim SQL (correct even where the table carries no RLS policy)
    // and a transaction-local `app.company_id` bind (makes the RLS fence
    // meaningful where it exists).
    let scope = company_scope::current_company();
    // Accounts this run already attempted (refreshed, expired, or skipped).
    // A skipped account is rolled back and stays due — excluding it here
    // means one run attempts each account at most once instead of spinning
    // its whole batch on the same stuck row; the NEXT tick retries it.
    let mut attempted: Vec<Uuid> = Vec::new();
    for _ in 0..schedule.refresh_batch_size.max(0) {
        let mut tx = pool.begin().await?;
        if let Some(company_id) = scope {
            company_scope::bind_company_on(&mut tx, company_id).await?;
        }
        let claimed = sqlx::query(
            r#"SELECT id, company_id, provider::text AS provider, account_ref
                 FROM integrations.integration_accounts
                WHERE status = 'active'
                  AND expires_at IS NOT NULL
                  AND expires_at < now() + make_interval(secs => $1)
                  AND id <> ALL($2::uuid[])
                  AND ($3::uuid IS NULL OR company_id = $3::uuid)
                ORDER BY expires_at
                LIMIT 1
                FOR UPDATE SKIP LOCKED"#,
        )
        .bind(schedule.refresh_window_seconds)
        .bind(&attempted)
        .bind(scope)
        .fetch_optional(&mut *tx)
        .await?;
        let row = match claimed {
            Some(row) => row,
            None => {
                // Nothing due (or everything claimable is locked by a
                // concurrent run) — the run is complete.
                tx.rollback().await?;
                break;
            }
        };
        let account = DueAccount {
            id: row.get("id"),
            company_id: row.get("company_id"),
            provider: row.get("provider"),
            account_ref: row.get("account_ref"),
        };
        attempted.push(account.id);
        refresh_one(tx, registry, overrides, clients, store, transport, &account, &mut report)
            .await?;
    }
    Ok(report)
}

/// The host-driven fan-out: run the sweep once per named company. Companies
/// are named by the HOST (the job cannot self-enumerate under FORCE RLS); a
/// failure for one company is reported, not fatal to the rest.
pub async fn refresh_oauth_credentials_for_companies(
    pool: &PgPool,
    registry: &ProviderRegistry,
    overrides: &EndpointOverrides,
    clients: &OAuthClientConfigs,
    store: &dyn OAuthCredentialStore,
    transport: &dyn OAuthTransport,
    schedule: &RefreshSchedule,
    companies: &[Uuid],
) -> Vec<(Uuid, Result<RefreshReport, sqlx::Error>)> {
    let mut out = Vec::with_capacity(companies.len());
    for company_id in companies {
        let r = company_scope::with_company_scope(
            Some(*company_id),
            refresh_oauth_credentials(pool, registry, overrides, clients, store, transport, schedule),
        )
        .await;
        out.push((*company_id, r));
    }
    out
}

/// Refresh ONE claimed account inside its own transaction. The row lock is
/// held for the whole call; every exit path either commits the account's
/// outcome (refreshed / expired) or rolls back (skipped — the account stays
/// due and the next tick retries). This is the `commit_per_batch` grain: one
/// account, one commit.
async fn refresh_one(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    registry: &ProviderRegistry,
    overrides: &EndpointOverrides,
    clients: &OAuthClientConfigs,
    store: &dyn OAuthCredentialStore,
    transport: &dyn OAuthTransport,
    account: &DueAccount,
    report: &mut RefreshReport,
) -> Result<(), sqlx::Error> {
    // The validated endpoints for this provider — the guard runs here too:
    // a drifted or malicious override refuses the account (skipped, still
    // due) before any bytes leave the process.
    let endpoints: ValidatedEndpoints = match ValidatedEndpoints::resolve(
        registry,
        &account.provider,
        overrides,
    ) {
        Ok(endpoints) => endpoints,
        Err(e) => {
            warn!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                provider = %account.provider,
                "endpoint guard refused the provider config; account left due: {e}"
            );
            report.skipped += 1;
            tx.rollback().await?;
            return Ok(());
        }
    };
    let client = match clients.get(&account.provider) {
        Some(client) => client,
        None => {
            warn!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                provider = %account.provider,
                "no OAuth client configured for provider; account left due"
            );
            report.skipped += 1;
            tx.rollback().await?;
            return Ok(());
        }
    };

    // The current bundle through the port. A scope the store cannot read is
    // account drift (or an honestly-expired credential): move the account to
    // `expired` and leave the store to its lazy expiry.
    let bundle: TokenBundle = match store
        .read_token(account.company_id, &account.provider, &account.account_ref)
        .await
    {
        Ok(bundle) => bundle,
        Err(e) if e.is_transport() => {
            // The store itself was unreachable — retryable, zero writes.
            debug!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                "credential store unreachable; account left due ({e})"
            );
            report.skipped += 1;
            tx.rollback().await?;
            return Ok(());
        }
        Err(OAuthCredentialFailure { code, message }) => {
            warn!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                provider = %account.provider,
                "credential unreadable ({code}: {message}); account moves to expired (reconnect required)"
            );
            expire_account(tx, account.id).await?;
            report.expired += 1;
            return Ok(());
        }
    };

    let refresh_token = match bundle.refresh_token() {
        Some(token) => token.to_string(),
        None => {
            // An access token with no refresh token cannot be renewed — the
            // connection ages out at expiry. Reconnect is the only path.
            warn!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                provider = %account.provider,
                "credential carries no refresh token; account moves to expired (reconnect required)"
            );
            expire_account(tx, account.id).await?;
            report.expired += 1;
            return Ok(());
        }
    };

    // The refresh grant at the validated endpoint.
    let form = refresh_form(&client.client_id, client.client_secret.as_deref(), &refresh_token);
    let now = Utc::now();
    let response = match transport.exchange(&endpoints.token, &form).await {
        Ok(response) => response,
        Err(e) if e.kind == TransportFailureKind::InvalidGrant => {
            // Dead refresh token — the self-heal-to-reconnect path. The
            // credential is left to the store's lazy expiry (no store write
            // from here).
            warn!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                provider = %account.provider,
                "provider rejected the refresh grant (invalid_grant); account moves to expired (reconnect required)"
            );
            expire_account(tx, account.id).await?;
            report.expired += 1;
            return Ok(());
        }
        Err(e) => {
            // Provider refusal / network / guard refusal — retryable, zero
            // writes, account stays due.
            debug!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                "refresh exchange failed; account left due ({e})"
            );
            report.skipped += 1;
            tx.rollback().await?;
            return Ok(());
        }
    };

    // Honest lifetimes only: a response with no usable expiry is unstoreable.
    let expires_at: DateTime<Utc> = match response.expires_at(now) {
        Some(expires_at) => expires_at,
        None => {
            warn!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                provider = %account.provider,
                "provider returned no expires_in; unstoreable response refused, account left due"
            );
            report.skipped += 1;
            tx.rollback().await?;
            return Ok(());
        }
    };

    // The successor bundle: a provider-returned refresh token wins; when the
    // provider returns none (Google), the previous refresh token persists.
    let successor = TokenBundle::new(
        response.access_token.clone(),
        response
            .refresh_token
            .clone()
            .or_else(|| bundle.refresh_token().map(str::to_string)),
        expires_at,
        response.scope.clone().or_else(|| bundle.scope().map(str::to_string)),
    );

    // Rotate through the store (lineage preserved), then mirror.
    match store
        .rotate(
            account.company_id,
            &account.provider,
            &account.account_ref,
            successor,
            expires_at,
        )
        .await
    {
        Ok(_) => {}
        Err(e) if e.is_transport() => {
            debug!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                "credential store unreachable at rotate; account left due ({e})"
            );
            report.skipped += 1;
            tx.rollback().await?;
            return Ok(());
        }
        Err(OAuthCredentialFailure { code, message }) => {
            warn!(
                target: "integrations.oauth.refresh",
                account_id = %account.id,
                provider = %account.provider,
                "rotate refused ({code}: {message}); account moves to expired"
            );
            expire_account(tx, account.id).await?;
            report.expired += 1;
            return Ok(());
        }
    }

    let mirrored = sqlx::query(
        r#"UPDATE integrations.integration_accounts
              SET expires_at = $2,
                  last_refreshed_at = now()
            WHERE id = $1"#,
    )
    .bind(account.id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    if mirrored.rows_affected() != 1 {
        warn!(
            target: "integrations.oauth.refresh",
            account_id = %account.id,
            "account mirror affected no rows; rolled back"
        );
        report.skipped += 1;
        tx.rollback().await?;
        return Ok(());
    }
    tx.commit().await?;
    report.refreshed += 1;
    debug!(
        target: "integrations.oauth.refresh",
        account_id = %account.id,
        provider = %account.provider,
        purpose = PURPOSE_OAUTH_TOKEN,
        "refreshed before expiry; successor mirrored"
    );
    Ok(())
}

/// Move an account to the terminal-but-reconnectable `expired` status and
/// commit its transaction.
async fn expire_account(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"UPDATE integrations.integration_accounts
              SET status = 'expired'
            WHERE id = $1"#,
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
