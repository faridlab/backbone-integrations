//! Shared test helpers: a live pool, a fake target (records maps / ignores / rejects by event_type), a
//! REAL backbone-payment target (a settled notification drives create_payment), and a capturing sink.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use backbone_integrations::application::service::integrations_events::{IntegrationEvent, IntegrationEventSink};
use backbone_integrations::application::service::integrations_ports::*;
use sqlx::PgPool;
use uuid::Uuid;

pub fn dburl() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/backbone_integrations".into())
}
pub async fn pool() -> PgPool {
    PgPool::connect(&dburl()).await.expect("connect")
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
