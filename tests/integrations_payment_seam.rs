//! The payment-gateway seam against the REAL backbone-payment module. A settled-payment notification is
//! mapped to a genuine customer receipt via the `TargetPort` over REAL payment. Proves the connector lands
//! a real internal record through the module's public write path. ZERO normal Cargo edge — payment is
//! reached through the port, a dev-dependency only in the test.

mod common;
use common::*;

use backbone_integrations::application::service::integrations_write_service::*;
use serde_json::json;
use uuid::Uuid;

// ISEAM-1 — a Midtrans settled-payment notification becomes a REAL payment in backbone-payment.
#[tokio::test]
async fn iseam1_settled_notification_becomes_real_payment() {
    let pool = pool().await;
    let company = Uuid::new_v4();
    let svc = IntegrationsWriteService::new(pool.clone());
    let target = RealPaymentTarget::new(pool.clone());
    let sink = CapturingSink::new();

    let conn = svc.register_connector(NewConnector {
        company_id: company, provider: format!("midtrans-{}", Uuid::new_v4()),
        kind: "payment_gateway".into(), direction: "inbound".into(),
    }).await.unwrap();

    let customer = Uuid::new_v4();
    let txn = format!("TXN-{}", Uuid::new_v4());
    let out = svc.receive_event(InboundEvent {
        company_id: company, connector_id: conn, event_type: "payment_settled".into(), external_id: txn.clone(), business_key: format!("{txn}:settled"),
        raw: "{...midtrans...}".into(),
        payload: json!({"amount": "250000", "customer_id": customer.to_string(), "order_id": "SO-9"}),
    }, &target, &sink).await.unwrap();

    assert_eq!(out.status, "mapped");
    let payment_id = out.mapped_ref_id.expect("mapped to a payment");

    // A REAL payment exists in backbone-payment, a customer receipt for the settled amount, carrying the
    // gateway transaction id as the reference.
    let (ptype, amount, reference): (String, rust_decimal::Decimal, Option<String>) = sqlx::query_as(
        "SELECT payment_type::text, paid_amount, reference_no FROM payment.payment_entries WHERE id=$1")
        .bind(payment_id).fetch_one(&pool).await.unwrap();
    assert_eq!(ptype, "receive", "a customer receipt");
    assert_eq!(amount, rust_decimal::Decimal::new(250000, 0));
    assert_eq!(reference.as_deref(), Some(txn.as_str()), "the gateway txn id is the payment reference");

    // The integration event records the link back to the internal payment.
    let mapped_ref: Option<Uuid> = sqlx::query_scalar(
        "SELECT mapped_ref_id FROM integrations.integration_events WHERE id=$1")
        .bind(out.event_id).fetch_one(&pool).await.unwrap();
    assert_eq!(mapped_ref, Some(payment_id));
}
