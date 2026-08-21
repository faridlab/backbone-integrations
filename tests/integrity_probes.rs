//! Integrity probes — the connector-hub invariants: external_id required, an inactive connector is
//! rejected, dedup is PER-CONNECTOR, and the lifecycle event is durable.

mod common;
use common::*;

use backbone_integrations::application::service::integrations_write_service::*;
use serde_json::json;
use uuid::Uuid;

async fn connector(svc: &IntegrationsWriteService, company: Uuid, provider: &str) -> Uuid {
    svc.register_connector(NewConnector {
        company_id: company, provider: provider.into(), kind: "payment_gateway".into(), direction: "inbound".into(),
    }).await.unwrap()
}
fn event(company: Uuid, conn: Uuid, ext: &str) -> InboundEvent {
    InboundEvent {
        company_id: company, connector_id: conn, event_type: "payment_settled".into(), external_id: ext.into(), business_key: ext.into(),
        raw: "{}".into(), payload: json!({"amount": "1000", "customer_id": Uuid::new_v4().to_string()}),
    }
}

// IIP-1 — an inbound event needs an external_id (the dedup key).
#[tokio::test]
async fn iip1_external_id_required() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = module(pool.clone()).await.integrations_write_service.clone();
    let conn = connector(&svc, company, &format!("p-{}", Uuid::new_v4())).await;
    let r = svc.receive_event(event(company, conn, "  "), &FakeTarget::new(), &CapturingSink::new()).await;
    assert!(matches!(r, Err(IntegrationError::Invalid(_))));
}

// IIP-2 — an inactive connector rejects events.
#[tokio::test]
async fn iip2_inactive_connector_rejected() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = module(pool.clone()).await.integrations_write_service.clone();
    let conn = connector(&svc, company, &format!("p-{}", Uuid::new_v4())).await;
    sqlx::query("UPDATE integrations.integration_connectors SET status='inactive' WHERE id=$1")
        .bind(conn).execute(&pool).await.unwrap();
    let r = svc.receive_event(event(company, conn, "n-x"), &FakeTarget::new(), &CapturingSink::new()).await;
    assert!(matches!(r, Err(IntegrationError::InvalidState(_))));
}

// IIP-3 — dedup is PER-CONNECTOR: the same external_id on two connectors both map (providers reuse ids).
#[tokio::test]
async fn iip3_dedup_is_per_connector() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = module(pool.clone()).await.integrations_write_service.clone();
    let a = connector(&svc, company, &format!("midtrans-{}", Uuid::new_v4())).await;
    let b = connector(&svc, company, &format!("xendit-{}", Uuid::new_v4())).await;
    let target = FakeTarget::new();

    let ra = svc.receive_event(event(company, a, "TXN-42"), &target, &CapturingSink::new()).await.unwrap();
    let rb = svc.receive_event(event(company, b, "TXN-42"), &target, &CapturingSink::new()).await.unwrap();
    assert!(!ra.duplicate);
    assert!(!rb.duplicate, "the same external id on a different connector is a distinct event");
    assert_ne!(ra.event_id, rb.event_id);
    assert_eq!(target.map_count(), 2);
}

// IIP-4 — the lifecycle event is durable: with the in-proc publish lost, IntegrationEventMapped is still
// staged in the outbox for the relay.
#[tokio::test]
async fn iip4_lifecycle_event_durable() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = module(pool.clone()).await.integrations_write_service.clone();
    let conn = connector(&svc, company, &format!("p-{}", Uuid::new_v4())).await;
    let out = svc.receive_event(event(company, conn, &format!("n-{}", Uuid::new_v4())), &FakeTarget::new(), &DroppingSink).await.unwrap();
    let staged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM integrations.outbox_events WHERE aggregate_id=$1 AND event_type='IntegrationEventMapped'")
        .bind(out.event_id.to_string()).fetch_one(&pool).await.unwrap();
    assert_eq!(staged, 1, "IntegrationEventMapped durably staged despite the lost publish");
}

// IIP-5 — TWO distinct settled notifications for ONE order (same business_key, DIFFERENT notification id)
// map only ONCE — no double-applied payment (maturity council 2026-07-11). A gateway sends multiple
// notifications per order; dedup is on the business action, not the raw notification id.
#[tokio::test]
async fn iip5_second_settled_notification_dedups() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = module(pool.clone()).await.integrations_write_service.clone();
    let conn = connector(&svc, company, &format!("midtrans-{}", Uuid::new_v4())).await;
    let target = FakeTarget::new();

    // Two DIFFERENT notification ids for the SAME order settlement.
    let mk = |notif: &str| InboundEvent {
        company_id: company, connector_id: conn, event_type: "payment_settled".into(),
        external_id: notif.into(), business_key: "SO-9:settled".into(),
        raw: "{}".into(), payload: json!({"amount": "1000", "customer_id": Uuid::new_v4().to_string()}),
    };
    let a = svc.receive_event(mk("notif-A"), &target, &CapturingSink::new()).await.unwrap();
    let b = svc.receive_event(mk("notif-B"), &target, &CapturingSink::new()).await.unwrap();

    assert!(!a.duplicate);
    assert!(b.duplicate, "the second settled notification for the same order is a duplicate, not a new map");
    assert_eq!(a.event_id, b.event_id);
    assert_eq!(target.map_count(), 1, "the payment is applied ONCE for the order, not twice");
}
