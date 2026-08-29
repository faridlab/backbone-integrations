//! OAuth credential port + fake semantics (no database required).
//!
//! Proves the port's contract on the in-memory fake the OAuth flow tests
//! drive: the store's verb semantics (duplicate issue refused, rotate keeps
//! one active successor, revoke idempotent, honest three-way read refusal
//! with lazy expiry), the metadata-only call log (token material never
//! appears in it), company scoping, the injectable transport outage, and
//! that the trait is dyn-compatible — the shape a composing host binds
//! behind an `Arc<dyn OAuthCredentialStore>`.

mod common;

// FakeStore/StoreCall and the re-exported port shapes come through `common`;
// TokenBundle/failure/trait types it does not re-export come from the crate.
use common::{FakeStore, StoreCall, PURPOSE_OAUTH_TOKEN};
use uuid::Uuid;

use backbone_integrations::application::service::integrations_oauth_ports::{
    OAuthCredentialFailure, OAuthCredentialStore, TokenBundle,
};

use chrono::{Duration, Utc};

fn bundle(access: &str, refresh: Option<&str>, expires_at: chrono::DateTime<Utc>) -> TokenBundle {
    TokenBundle::new(access.into(), refresh.map(str::to_string), expires_at, Some("https://mail.google.com/".into()))
}

#[tokio::test]
async fn issue_then_read_roundtrip() {
    let store = FakeStore::new();
    let company = Uuid::new_v4();
    let expiry = Utc::now() + Duration::hours(24);

    let id = store
        .issue(company, "gmail", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-1", Some("REFRESH-1"), expiry), expiry)
        .await
        .expect("first issue succeeds");
    assert!(!id.is_nil());

    let read = store.read_token(company, "gmail", "user@example.com").await.expect("read after issue");
    assert_eq!(read.access_token(), "ACCESS-1");
    assert_eq!(read.refresh_token(), Some("REFRESH-1"));
    assert_eq!(read.expires_at(), expiry, "the honest expiry is what comes back");
}

#[tokio::test]
async fn duplicate_issue_is_refused_rotation_is_the_replacement() {
    let store = FakeStore::new();
    let company = Uuid::new_v4();
    let expiry = Utc::now() + Duration::hours(24);

    store
        .issue(company, "gmail", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-1", Some("REFRESH-1"), expiry), expiry)
        .await
        .expect("first issue");

    let err = store
        .issue(company, "gmail", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-2", Some("REFRESH-2"), expiry), expiry)
        .await
        .expect_err("second active credential must be refused");
    assert_eq!(err.code, OAuthCredentialFailure::CODE_DUPLICATE_ACTIVE);
    assert!(!err.is_transport());

    // Rotation IS the sanctioned replacement — it succeeds where issue was refused.
    store
        .rotate(company, "gmail", "user@example.com", bundle("ACCESS-2", Some("REFRESH-2"), expiry), expiry)
        .await
        .expect("rotate replaces the active credential");
    let read = store.read_token(company, "gmail", "user@example.com").await.expect("read after rotate");
    assert_eq!(read.access_token(), "ACCESS-2", "the successor shadows the predecessor");
}

#[tokio::test]
async fn read_refusals_are_honest_three_way() {
    let store = FakeStore::new();
    let company = Uuid::new_v4();

    let never = store.read_token(company, "outlook", "user@example.com").await.expect_err("never issued");
    assert_eq!(never.code, OAuthCredentialFailure::CODE_NOT_FOUND);

    let expiry = Utc::now() + Duration::hours(24);
    store
        .issue(company, "outlook", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-1", Some("REFRESH-1"), expiry), expiry)
        .await
        .expect("issue");

    // Lazy expiry: a row past its honest expiry refuses Expired at read time…
    let past = Utc::now() - Duration::minutes(1);
    store
        .rotate(company, "outlook", "user@example.com", bundle("ACCESS-EXPIRED", None, past), past)
        .await
        .expect("rotate installs a past-expiry successor (the case refresh repairs)");
    let expired = store.read_token(company, "outlook", "user@example.com").await.expect_err("past expiry");
    assert_eq!(expired.code, OAuthCredentialFailure::CODE_EXPIRED);

    // …and terminal status refuses NotActive, never a silent empty success.
    store.revoke(company, "outlook", "user@example.com").await.expect("revoke");
    let revoked = store.read_token(company, "outlook", "user@example.com").await.expect_err("revoked scope");
    assert_eq!(revoked.code, OAuthCredentialFailure::CODE_NOT_ACTIVE);
}

#[tokio::test]
async fn rotate_requires_an_active_predecessor() {
    let store = FakeStore::new();
    let company = Uuid::new_v4();
    let expiry = Utc::now() + Duration::hours(24);

    let err = store
        .rotate(company, "gmail", "user@example.com", bundle("ACCESS-1", None, expiry), expiry)
        .await
        .expect_err("rotate with nothing issued");
    assert_eq!(err.code, OAuthCredentialFailure::CODE_NOT_FOUND);
    assert_eq!(store.rotate_count(), 0, "failed rotate leaves no call record");
}

#[tokio::test]
async fn revoke_is_idempotent_and_honest_about_never_issued() {
    let store = FakeStore::new();
    let company = Uuid::new_v4();
    let expiry = Utc::now() + Duration::hours(24);

    let never = store.revoke(company, "gmail", "user@example.com").await.expect_err("revoke never-issued scope");
    assert_eq!(never.code, OAuthCredentialFailure::CODE_NOT_FOUND);

    store
        .issue(company, "gmail", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-1", None, expiry), expiry)
        .await
        .expect("issue");
    store.revoke(company, "gmail", "user@example.com").await.expect("revoke");
    store.revoke(company, "gmail", "user@example.com").await.expect("second revoke is a no-op success");

    // Re-issue after revocation is the store's documented recovery path.
    store
        .issue(company, "gmail", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-2", None, expiry), expiry)
        .await
        .expect("re-issue after revocation");
}

#[tokio::test]
async fn call_log_is_metadata_only_and_records_the_honest_expiry() {
    let store = FakeStore::new();
    let company = Uuid::new_v4();
    let expiry = Utc::now() + Duration::hours(24);

    store
        .issue(company, "gmail", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("SECRET-ACCESS-XYZ", Some("SECRET-REFRESH-XYZ"), expiry), expiry)
        .await
        .expect("issue");
    store.read_token(company, "gmail", "user@example.com").await.expect("read");
    store
        .rotate(company, "gmail", "user@example.com", bundle("SECRET-ACCESS-2", Some("SECRET-REFRESH-2"), expiry), expiry)
        .await
        .expect("rotate");
    store.revoke(company, "gmail", "user@example.com").await.expect("revoke");

    let calls = store.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(store.issue_count(), 1);
    assert_eq!(store.read_count(), 1);
    assert_eq!(store.rotate_count(), 1);
    assert_eq!(store.revoke_count(), 1);

    // The honest-expiry contract is provable from the log alone.
    match &calls[0] {
        StoreCall::Issued { expires_at, purpose, account_ref, provider, company_id } => {
            assert_eq!(*expires_at, expiry, "issue records now + expires_in, never None");
            assert_eq!(purpose, PURPOSE_OAUTH_TOKEN);
            assert_eq!(provider, "gmail");
            assert_eq!(account_ref, "user@example.com");
            assert_eq!(*company_id, company);
        }
        other => panic!("first call must be Issued, got {other:?}"),
    }
    if let StoreCall::Rotated { expires_at, .. } = &calls[2] {
        assert_eq!(*expires_at, expiry, "rotate records the successor's honest expiry");
    } else {
        panic!("third call must be Rotated");
    }

    // Metadata-only: token material never appears anywhere in the log.
    let log_debug = format!("{calls:?}");
    assert!(!log_debug.contains("SECRET"), "token material leaked into the call log: {log_debug}");
}

#[tokio::test]
async fn scopes_are_company_fenced() {
    let store = FakeStore::new();
    let company_a = Uuid::new_v4();
    let company_b = Uuid::new_v4();
    let expiry = Utc::now() + Duration::hours(24);

    store
        .issue(company_a, "gmail", "shared@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-A", None, expiry), expiry)
        .await
        .expect("company A issues its own credential");
    store
        .issue(company_b, "gmail", "shared@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-B", None, expiry), expiry)
        .await
        .expect("company B issues the same provider+account_ref independently — no cross-tenant DuplicateActive");

    let read_a = store.read_token(company_a, "gmail", "shared@example.com").await.expect("A reads A");
    assert_eq!(read_a.access_token(), "ACCESS-A");
    let read_b = store.read_token(company_b, "gmail", "shared@example.com").await.expect("B reads B");
    assert_eq!(read_b.access_token(), "ACCESS-B");

    store.revoke(company_a, "gmail", "shared@example.com").await.expect("A revokes only its own");
    assert!(store.read_token(company_a, "gmail", "shared@example.com").await.is_err());
    store.read_token(company_b, "gmail", "shared@example.com").await.expect("B is untouched by A's revoke");
}

#[tokio::test]
async fn injected_failure_is_the_retryable_transport_code_and_logs_nothing() {
    let store = FakeStore::new();
    let company = Uuid::new_v4();
    let expiry = Utc::now() + Duration::hours(24);

    store.fail_with(OAuthCredentialFailure::transport("store unreachable"));
    let err = store
        .issue(company, "gmail", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-1", None, expiry), expiry)
        .await
        .expect_err("injected outage");
    assert!(err.is_transport());
    assert_eq!(store.calls().len(), 0, "an unreachable store observes no calls");

    store.clear_failure();
    store
        .issue(company, "gmail", "user@example.com", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-1", None, expiry), expiry)
        .await
        .expect("issue succeeds after the outage clears");
    assert_eq!(store.issue_count(), 1);
}

#[tokio::test]
async fn the_port_binds_as_a_trait_object() {
    // The composing host holds the store as an Arc<dyn OAuthCredentialStore>;
    // prove the bound works end-to-end on the fake.
    let store: std::sync::Arc<dyn OAuthCredentialStore> = std::sync::Arc::new(FakeStore::new());
    let company = Uuid::new_v4();
    let expiry = Utc::now() + Duration::hours(24);
    store
        .issue(company, "google_calendar", "subject-123", PURPOSE_OAUTH_TOKEN, bundle("ACCESS-1", Some("REFRESH-1"), expiry), expiry)
        .await
        .expect("issue through the trait object");
    let read = store.read_token(company, "google_calendar", "subject-123").await.expect("read through the trait object");
    assert_eq!(read.access_token(), "ACCESS-1");
}
