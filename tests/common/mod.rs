//! Shared test helpers: a live pool, a fake target (records maps / ignores / rejects by event_type), a
//! REAL backbone-payment target (a settled notification drives create_payment), a capturing sink, and
//! the OAuth fakes — a credential store recording every verb call, and (as the transport port lands)
//! an outbound transport recording every URL it is handed.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use backbone_integrations::application::service::integrations_events::{IntegrationEvent, IntegrationEventSink};
// The OAuth credential port's public shapes, re-exported so probe binaries can `use common::{..}`.
// Not every binary that includes this module consumes every name — same spirit as the
// `#![allow(dead_code)]` above.
#[allow(unused_imports)]
pub use backbone_integrations::application::service::integrations_oauth_ports::{
    OAuthCredentialFailure, OAuthCredentialStore, PURPOSE_OAUTH_TOKEN, TokenBundle,
};
use backbone_integrations::application::service::integrations_ports::*;
use backbone_integrations::IntegrationsModule;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub fn dburl() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/backbone_integrations".into())
}
pub async fn pool() -> PgPool {
    PgPool::connect(&dburl()).await.expect("connect")
}

/// Build the module through its public builder — the surface a composing service uses. Routing the write
/// service through `IntegrationsModule::builder().build()` makes the module wiring (struct field + builder)
/// a tested surface, so a regen that drops the field fails a test, not just a compile.
pub async fn module(pool: PgPool) -> IntegrationsModule {
    IntegrationsModule::builder()
        .with_database(pool)
        .build()
        .expect("module build")
}

/// A fake target: maps `payment_settled` to a synthetic ref, IGNORES `payment_pending`, rejects a key in
/// `reject`. Records each mapped op.
#[derive(Clone, Default)]
pub struct FakeTarget {
    pub maps: Arc<Mutex<Vec<MapRequest>>>,
    pub reject: Arc<Mutex<Option<(String, String)>>>,
}
impl FakeTarget {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn rejecting(code: &str, message: &str) -> Self {
        let f = Self::default();
        *f.reject.lock().unwrap() = Some((code.into(), message.into()));
        f
    }
    pub fn map_count(&self) -> usize {
        self.maps.lock().unwrap().len()
    }
}
#[async_trait::async_trait]
impl TargetPort for FakeTarget {
    async fn map(&self, req: &MapRequest) -> Result<MapOutcome, MapRejected> {
        self.maps.lock().unwrap().push(req.clone());
        if let Some((code, message)) = self.reject.lock().unwrap().clone() {
            return Err(MapRejected { code, message });
        }
        if req.event_type == "payment_pending" {
            return Ok(MapOutcome::Ignored("payment not yet settled".into()));
        }
        Ok(MapOutcome::Mapped(MappedRef { internal_ref_type: "payment".into(), internal_ref_id: Uuid::new_v4() }))
    }
}

/// The ACL over the REAL backbone-payment module: a settled-payment notification becomes a customer receipt.
pub struct RealPaymentTarget {
    pub payment: backbone_payment::application::service::payment_write_service::PaymentWriteService,
}
impl RealPaymentTarget {
    pub fn new(pool: PgPool) -> Self {
        Self { payment: backbone_payment::application::service::payment_write_service::PaymentWriteService::new(pool) }
    }
}
#[async_trait::async_trait]
impl TargetPort for RealPaymentTarget {
    async fn map(&self, req: &MapRequest) -> Result<MapOutcome, MapRejected> {
        use backbone_payment::application::service::payment_write_service::NewPayment;
        use rust_decimal::Decimal;
        if req.event_type == "payment_pending" {
            return Ok(MapOutcome::Ignored("payment not yet settled".into()));
        }
        let p = &req.payload;
        let amount: Decimal = p.get("amount").and_then(|v| v.as_str()).and_then(|s| s.parse().ok())
            .ok_or(MapRejected { code: "bad_payload".into(), message: "missing amount".into() })?;
        let customer: Uuid = p.get("customer_id").and_then(|v| v.as_str()).and_then(|s| s.parse().ok())
            .ok_or(MapRejected { code: "bad_payload".into(), message: "missing customer_id".into() })?;
        let id = self.payment.create_payment(NewPayment {
            payment_number: format!("MID-{}", req.external_id),
            company_id: req.company_id, branch_id: None,
            payment_type: "receive".into(), party_type: Some("customer".into()), party_id: Some(customer),
            posting_date: chrono::Utc::now().date_naive(), currency: None, mode_of_payment_id: None,
            bank_account_id: Uuid::new_v4(), party_account_id: Uuid::new_v4(),
            paid_amount: amount, reference_no: Some(req.external_id.clone()), allocations: vec![],
            method: None, provider_txn_id: None,
            withholding_amount: Decimal::ZERO, withholding_account_id: None, withholding_tax_type: "none".into(),
        }).await.map_err(|e| MapRejected { code: "payment_rejected".into(), message: e.to_string() })?;
        Ok(MapOutcome::Mapped(MappedRef { internal_ref_type: "payment".into(), internal_ref_id: id }))
    }
}

#[derive(Clone, Default)]
pub struct CapturingSink {
    pub events: Arc<Mutex<Vec<IntegrationEvent>>>,
}
impl CapturingSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn mapped(&self) -> usize {
        self.events.lock().unwrap().iter().filter(|e| matches!(e, IntegrationEvent::IntegrationEventMapped(_))).count()
    }
    pub fn ignored(&self) -> usize {
        self.events.lock().unwrap().iter().filter(|e| matches!(e, IntegrationEvent::IntegrationEventIgnored { .. })).count()
    }
    pub fn failed(&self) -> usize {
        self.events.lock().unwrap().iter().filter(|e| matches!(e, IntegrationEvent::IntegrationEventFailed { .. })).count()
    }
}
impl IntegrationEventSink for CapturingSink {
    fn publish(&self, event: &IntegrationEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

pub struct DroppingSink;
impl IntegrationEventSink for DroppingSink {
    fn publish(&self, _e: &IntegrationEvent) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// OAuth credential store fake
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata-only record of one port call — mirrors the real store's
/// metadata-only response discipline, so assertions on the log never hold
/// token material either. `expires_at` is recorded on issue/rotate because
/// the honest-expiry contract (the stored credential carries now + expires_in)
/// is proven from this log.
#[derive(Debug, Clone, PartialEq)]
pub enum StoreCall {
    Issued { company_id: Uuid, provider: String, account_ref: String, purpose: String, expires_at: DateTime<Utc> },
    Read { company_id: Uuid, provider: String, account_ref: String },
    Rotated { company_id: Uuid, provider: String, account_ref: String, expires_at: DateTime<Utc> },
    Revoked { company_id: Uuid, provider: String, account_ref: String },
}

/// One stored credential row (the fake's internal shape — the plain strings
/// exist ONLY here, in test memory, so `read_token` can rebuild a bundle).
struct StoredFakeCredential {
    company_id: Uuid,
    provider: String,
    account_ref: String,
    access_token: String,
    refresh_token: Option<String>,
    scope: Option<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl StoredFakeCredential {
    fn matches(&self, company_id: Uuid, provider: &str, account_ref: &str) -> bool {
        self.company_id == company_id && self.provider == provider && self.account_ref == account_ref
    }
}

/// An in-memory [`OAuthCredentialStore`] that mirrors the real store's verb
/// semantics: duplicate `issue` on a live scope is refused (rotation is the
/// only replacement), `rotate` supersedes the active credential (lineage kept
/// as the ordered row list), `read_token` refuses not-found / terminal /
/// expired honestly with lazy expiry at read time, `revoke` is idempotent
/// once a scope has had a credential.
///
/// Every call is recorded in a metadata-only log ([`StoreCall`]); an
/// injectable failure short-circuits before the log to simulate a store
/// outage (the retryable transport code).
#[derive(Clone, Default)]
pub struct FakeStore {
    calls: Arc<Mutex<Vec<StoreCall>>>,
    rows: Arc<Mutex<Vec<StoredFakeCredential>>>,
    fail_with: Arc<Mutex<Option<OAuthCredentialFailure>>>,
}

impl FakeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every subsequent verb fail with this error (short-circuits before
    /// the call log — an unreachable store observes nothing).
    pub fn fail_with(&self, failure: OAuthCredentialFailure) {
        *self.fail_with.lock().unwrap() = Some(failure);
    }

    pub fn clear_failure(&self) {
        *self.fail_with.lock().unwrap() = None;
    }

    /// The metadata-only call log, in order.
    pub fn calls(&self) -> Vec<StoreCall> {
        self.calls.lock().unwrap().clone()
    }

    pub fn issue_count(&self) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| matches!(c, StoreCall::Issued { .. })).count()
    }

    pub fn rotate_count(&self) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| matches!(c, StoreCall::Rotated { .. })).count()
    }

    pub fn revoke_count(&self) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| matches!(c, StoreCall::Revoked { .. })).count()
    }

    pub fn read_count(&self) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| matches!(c, StoreCall::Read { .. })).count()
    }

    fn gate(&self) -> Result<(), OAuthCredentialFailure> {
        match self.fail_with.lock().unwrap().clone() {
            Some(f) => Err(f),
            None => Ok(()),
        }
    }

    fn active_row_index(
        rows: &[StoredFakeCredential],
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
    ) -> Option<usize> {
        // Latest non-revoked row for the scope — the successor of a rotation
        // shadows its predecessor, like the store's active-by-lineage read.
        rows.iter()
            .rposition(|r| !r.revoked && r.matches(company_id, provider, account_ref))
    }
}

#[async_trait::async_trait]
impl OAuthCredentialStore for FakeStore {
    async fn issue(
        &self,
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
        purpose: &str,
        bundle: TokenBundle,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, OAuthCredentialFailure> {
        self.gate()?;
        let mut rows = self.rows.lock().unwrap();
        if Self::active_row_index(&rows, company_id, provider, account_ref).is_some() {
            return Err(OAuthCredentialFailure::duplicate_active());
        }
        let id = Uuid::new_v4();
        rows.push(StoredFakeCredential {
            company_id,
            provider: provider.to_string(),
            account_ref: account_ref.to_string(),
            access_token: bundle.access_token().to_string(),
            refresh_token: bundle.refresh_token().map(str::to_string),
            scope: bundle.scope().map(str::to_string),
            expires_at,
            revoked: false,
        });
        drop(rows);
        self.calls.lock().unwrap().push(StoreCall::Issued {
            company_id,
            provider: provider.to_string(),
            account_ref: account_ref.to_string(),
            purpose: purpose.to_string(),
            expires_at,
        });
        Ok(id)
    }

    async fn read_token(
        &self,
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
    ) -> Result<TokenBundle, OAuthCredentialFailure> {
        self.gate()?;
        self.calls.lock().unwrap().push(StoreCall::Read {
            company_id,
            provider: provider.to_string(),
            account_ref: account_ref.to_string(),
        });
        let rows = self.rows.lock().unwrap();
        let row = match Self::active_row_index(&rows, company_id, provider, account_ref) {
            Some(i) => &rows[i],
            None => {
                // Honest three-way refusal, matching the store's read: never
                // issued → NotFound; issued but terminal → NotActive.
                return match rows.iter().rev().find(|r| r.matches(company_id, provider, account_ref)) {
                    Some(_) => Err(OAuthCredentialFailure::not_active("revoked")),
                    None => Err(OAuthCredentialFailure::not_found()),
                };
            }
        };
        if row.expires_at <= Utc::now() {
            // Lazy expiry at read time — the observable refusal, exactly as
            // the store's read-time CAS makes an expired row unreadable.
            return Err(OAuthCredentialFailure::expired());
        }
        Ok(TokenBundle::new(
            row.access_token.clone(),
            row.refresh_token.clone(),
            row.expires_at,
            row.scope.clone(),
        ))
    }

    async fn rotate(
        &self,
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
        bundle: TokenBundle,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, OAuthCredentialFailure> {
        self.gate()?;
        let mut rows = self.rows.lock().unwrap();
        let predecessor = match Self::active_row_index(&rows, company_id, provider, account_ref) {
            Some(i) => i,
            None => return Err(OAuthCredentialFailure::not_found()),
        };
        // An expired-but-still-active row is exactly what rotation repairs —
        // the successor shadows it regardless of its expiry.
        rows[predecessor].revoked = true;
        rows.push(StoredFakeCredential {
            company_id,
            provider: provider.to_string(),
            account_ref: account_ref.to_string(),
            access_token: bundle.access_token().to_string(),
            refresh_token: bundle.refresh_token().map(str::to_string),
            scope: bundle.scope().map(str::to_string),
            expires_at,
            revoked: false,
        });
        drop(rows);
        self.calls.lock().unwrap().push(StoreCall::Rotated {
            company_id,
            provider: provider.to_string(),
            account_ref: account_ref.to_string(),
            expires_at,
        });
        Ok(Uuid::new_v4())
    }

    async fn revoke(
        &self,
        company_id: Uuid,
        provider: &str,
        account_ref: &str,
    ) -> Result<(), OAuthCredentialFailure> {
        self.gate()?;
        let mut rows = self.rows.lock().unwrap();
        let any = rows.iter().any(|r| r.matches(company_id, provider, account_ref));
        if !any {
            return Err(OAuthCredentialFailure::not_found());
        }
        // Idempotent: revoking an already-revoked scope stays a success.
        for row in rows.iter_mut() {
            if row.matches(company_id, provider, account_ref) {
                row.revoked = true;
            }
        }
        drop(rows);
        self.calls.lock().unwrap().push(StoreCall::Revoked {
            company_id,
            provider: provider.to_string(),
            account_ref: account_ref.to_string(),
        });
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OAuth transport fake
// ─────────────────────────────────────────────────────────────────────────────

#[allow(unused_imports)]
use backbone_integrations::infrastructure::http::{
    IdentityClaims, OAuthTransport, TokenResponse, TransportFailure,
};

/// Metadata-only record of one outbound call the flow attempted — the URL and
/// host it was handed (a guarded endpoint by construction: the trait accepts
/// nothing else) and which verb ran. Proves "zero calls on rejection paths"
/// by absence in this log.
#[derive(Debug, Clone, PartialEq)]
pub struct TransportCall {
    pub verb: &'static str,
    pub url: String,
    pub host: String,
}

/// A scripted [`OAuthTransport`]: records every endpoint it is handed and
/// answers from configurable state — the token response, the identity claims,
/// an injectable failure. No network, no real HTTP client; the probe suite
/// drives provider behavior (audience mismatch, nonce mismatch, missing
/// expiry, invalid_grant, ...) by scripting this transport and asserting on
/// its call log.
#[derive(Clone)]
pub struct FakeTransport {
    calls: Arc<Mutex<Vec<TransportCall>>>,
    token_response: Arc<Mutex<TokenResponse>>,
    identity: Arc<Mutex<IdentityClaims>>,
    failure: Arc<Mutex<Option<TransportFailure>>>,
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            token_response: Arc::new(Mutex::new(TokenResponse {
                access_token: String::new(),
                refresh_token: None,
                expires_in: None,
                scope: None,
                id_token: None,
                token_type: None,
            })),
            identity: Arc::new(Mutex::new(IdentityClaims::default())),
            failure: Arc::new(Mutex::new(None)),
        }
    }
}

impl FakeTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// The well-behaved provider: a 24h-class access token with refresh, and
    /// an identity matching `account_ref` with the expected audience/nonce.
    pub fn happy(email: &str, audience: &str, nonce: &str) -> Self {
        let t = Self::default();
        *t.token_response.lock().unwrap() = TokenResponse {
            access_token: "FAKE-ACCESS-TOKEN".into(),
            refresh_token: Some("FAKE-REFRESH-TOKEN".into()),
            expires_in: Some(86_400),
            scope: Some("https://mail.google.com/".into()),
            id_token: Some("FAKE-ID-TOKEN".into()),
            token_type: Some("Bearer".into()),
        };
        *t.identity.lock().unwrap() = IdentityClaims {
            sub: Some(format!("sub-{email}")),
            email: Some(email.into()),
            email_verified: Some(true),
            audience: Some(audience.into()),
            nonce: Some(nonce.into()),
        };
        t
    }

    /// A provider shaped like the real Google/Microsoft endpoints: the
    /// userinfo response carries only profile claims (sub/email — NO
    /// audience, NO nonce), and the audience + nonce live in the token
    /// response's id_token, which the server decodes. The id_token is
    /// minted here as an unsigned JWT-shaped triple whose payload carries
    /// `aud` + `nonce` — the echo of what the authorize request sent.
    pub fn realistic_idtoken_echo(email: &str, audience: &str, nonce: &str) -> Self {
        use base64::Engine;
        let t = Self::default();
        let claims = serde_json::json!({ "aud": audience, "nonce": nonce });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(claims.to_string().as_bytes());
        *t.token_response.lock().unwrap() = TokenResponse {
            access_token: "FAKE-ACCESS-TOKEN".into(),
            refresh_token: Some("FAKE-REFRESH-TOKEN".into()),
            expires_in: Some(86_400),
            scope: Some("https://mail.google.com/".into()),
            id_token: Some(format!("e30.{payload_b64}.")),
            token_type: Some("Bearer".into()),
        };
        *t.identity.lock().unwrap() = IdentityClaims {
            sub: Some(format!("sub-{email}")),
            email: Some(email.into()),
            email_verified: Some(true),
            audience: None,
            nonce: None,
        };
        t
    }

    pub fn set_token_response(&self, r: TokenResponse) {
        *self.token_response.lock().unwrap() = r;
    }

    pub fn set_identity(&self, c: IdentityClaims) {
        *self.identity.lock().unwrap() = c;
    }

    pub fn fail_with(&self, f: TransportFailure) {
        *self.failure.lock().unwrap() = Some(f);
    }

    pub fn clear_failure(&self) {
        *self.failure.lock().unwrap() = None;
    }

    pub fn calls(&self) -> Vec<TransportCall> {
        self.calls.lock().unwrap().clone()
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    pub fn urls(&self) -> Vec<String> {
        self.calls.lock().unwrap().iter().map(|c| c.url.clone()).collect()
    }
}

#[async_trait::async_trait]
impl OAuthTransport for FakeTransport {
    async fn exchange(
        &self,
        endpoint: &backbone_integrations::infrastructure::http::ValidatedEndpoint,
        _form: &backbone_integrations::infrastructure::http::TokenRequestForm,
    ) -> Result<TokenResponse, TransportFailure> {
        self.calls.lock().unwrap().push(TransportCall {
            verb: "exchange",
            url: endpoint.as_str().to_string(),
            host: endpoint.host().to_string(),
        });
        if let Some(f) = self.failure.lock().unwrap().clone() {
            return Err(f);
        }
        Ok(self.token_response.lock().unwrap().clone())
    }

    async fn fetch_identity(
        &self,
        endpoint: &backbone_integrations::infrastructure::http::ValidatedEndpoint,
        _access_token: &str,
    ) -> Result<IdentityClaims, TransportFailure> {
        self.calls.lock().unwrap().push(TransportCall {
            verb: "identity",
            url: endpoint.as_str().to_string(),
            host: endpoint.host().to_string(),
        });
        if let Some(f) = self.failure.lock().unwrap().clone() {
            return Err(f);
        }
        Ok(self.identity.lock().unwrap().clone())
    }
}
