//! Golden cases — the connector-hub oracle: a settled notification maps to an internal action; a webhook
//! retry is idempotent; a "pending" notification is intentionally ignored; an unmappable event fails.

mod common;
use common::*;

use backbone_integrations::application::service::integrations_events::LoggingSink;
use backbone_integrations::application::service::integrations_write_service::*;
use serde_json::json;
use uuid::Uuid;

async fn connector(svc: &IntegrationsWriteService, company: Uuid) -> Uuid {
    svc.register_connector(NewConnector {
        company_id: company, provider: format!("midtrans-{}", Uuid::new_v4()),
        kind: "payment_gateway".into(), direction: "inbound".into(),
    }).await.unwrap()
}
fn event(company: Uuid, conn: Uuid, ext: &str, etype: &str) -> InboundEvent {
    InboundEvent {
        company_id: company, connector_id: conn, event_type: etype.into(), external_id: ext.into(), business_key: ext.into(),
        raw: "{...}".into(),
        payload: json!({"amount": "150000", "customer_id": Uuid::new_v4().to_string(), "order_id": "SO-1"}),
    }
}

// IGC-1 — a settled notification maps to an internal action and publishes IntegrationEventMapped.
#[tokio::test]
async fn igc1_settled_maps() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = IntegrationsWriteService::new(pool.clone());
    let conn = connector(&svc, company).await;
    let target = FakeTarget::new();
    let sink = CapturingSink::new();

    let out = svc.receive_event(event(company, conn, "n-1", "payment_settled"), &target, &sink).await.unwrap();
    assert_eq!(out.status, "mapped");
    assert!(out.mapped_ref_id.is_some());
    assert_eq!(sink.mapped(), 1);
    assert_eq!(target.map_count(), 1);
}

// IGC-2 — a webhook retry (same connector + external_id) is idempotent: no re-map.
#[tokio::test]
async fn igc2_retry_idempotent() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = IntegrationsWriteService::new(pool.clone());
    let conn = connector(&svc, company).await;
    let target = FakeTarget::new();
    let sink = CapturingSink::new();

    let first = svc.receive_event(event(company, conn, "n-2", "payment_settled"), &target, &sink).await.unwrap();
    let second = svc.receive_event(event(company, conn, "n-2", "payment_settled"), &target, &sink).await.unwrap();
    assert!(!first.duplicate);
    assert!(second.duplicate);
    assert_eq!(first.event_id, second.event_id);
    assert_eq!(target.map_count(), 1, "mapped once — no double-applied payment from a retry");
    assert_eq!(sink.mapped(), 1);
}

// IGC-3 — a "pending" notification is intentionally IGNORED (no internal action).
#[tokio::test]
async fn igc3_pending_ignored() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = IntegrationsWriteService::new(pool.clone());
    let conn = connector(&svc, company).await;
    let sink = CapturingSink::new();

    let out = svc.receive_event(event(company, conn, "n-3", "payment_pending"), &FakeTarget::new(), &sink).await.unwrap();
    assert_eq!(out.status, "ignored");
    assert!(out.mapped_ref_id.is_none());
    assert_eq!(sink.ignored(), 1);
    let (status, reason): (String, Option<String>) = sqlx::query_as(
        "SELECT status::text, error_detail FROM integrations.integration_events WHERE id=$1")
        .bind(out.event_id).fetch_one(&pool).await.unwrap();
    assert_eq!(status, "ignored");
    assert_eq!(reason.as_deref(), Some("payment not yet settled"));
}

// IGC-4 — an unmappable event is recorded 'failed' with the reason and publishes IntegrationEventFailed.
#[tokio::test]
async fn igc4_unmappable_fails() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = IntegrationsWriteService::new(pool.clone());
    let conn = connector(&svc, company).await;
    let sink = CapturingSink::new();

    let out = svc.receive_event(event(company, conn, "n-4", "payment_settled"),
        &FakeTarget::rejecting("bad_payload", "missing customer"), &sink).await.unwrap();
    assert_eq!(out.status, "failed");
    assert_eq!(sink.failed(), 1);
    let err: Option<String> = sqlx::query_scalar("SELECT error_detail FROM integrations.integration_events WHERE id=$1")
        .bind(out.event_id).fetch_one(&pool).await.unwrap();
    assert_eq!(err.as_deref(), Some("missing customer"));
    let _ = LoggingSink;
}

// IGC-5 — failure recovery (completeness council 2026-07-11): a settled notification that FAILED to map (a
// real payment we didn't book) is visible via `failures()` and re-driven by `retry_failed` once the cause
// is fixed. Without it that money is stuck 'failed' forever (a re-delivery just dedups).
#[tokio::test]
async fn igc5_failures_report_and_retry() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = IntegrationsWriteService::new(pool.clone());
    let conn = connector(&svc, company).await;
    let sink = CapturingSink::new();

    // The payment module is "down" — the settled notification fails to map.
    let out = svc.receive_event(event(company, conn, "n-9", "payment_settled"),
        &FakeTarget::rejecting("target_down", "payment module unavailable"), &sink).await.unwrap();
    assert_eq!(out.status, "failed");

    // The operator sees the failed notification from the API alone — which, why.
    let fails = svc.failures(conn).await.unwrap();
    assert_eq!(fails.len(), 1);
    assert_eq!(fails[0].business_key, "n-9");
    assert_eq!(fails[0].error_detail.as_deref(), Some("payment module unavailable"));

    // The cause is fixed; retry_failed re-drives it → the event maps, a real internal ref is recorded.
    let n = svc.retry_failed(conn, &FakeTarget::new(), &sink).await.unwrap();
    assert_eq!(n, 1, "the stuck payment notification is finally booked");
    let (status, mapped): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status::text, mapped_ref_id FROM integrations.integration_events WHERE id=$1")
        .bind(out.event_id).fetch_one(&pool).await.unwrap();
    assert_eq!(status, "mapped");
    assert!(mapped.is_some());
    assert!(svc.failures(conn).await.unwrap().is_empty());
}
