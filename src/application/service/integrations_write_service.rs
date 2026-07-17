//! The hand-authored integrations write path (user-owned; survives regen).
//!
//! The connector hub: receive an inbound provider event **idempotently** on (connector, external_id) —
//! providers deliver webhooks at-least-once, so a retry must not re-map (double-apply a payment / create a
//! duplicate order) — map it to an internal action via a `TargetPort`, or record it as intentionally
//! ignored. Posts NO GL. Integrations reaches a module only through its public contract (the port).

use backbone_orm::company_scope;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::infrastructure::persistence::{
    IntegrationConnectorRepository, IntegrationEventRepository, NewConnectorRow, NewEventRow,
};

use super::integrations_events::*;
use super::integrations_ports::*;

#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("mapping rejected: {0}")]
    MappingRejected(String),
}

pub struct NewConnector {
    pub company_id: Uuid,
    pub provider: String,
    pub kind: String,      // payment_gateway | marketplace | bank_feed | courier
    pub direction: String, // inbound | outbound | both
}

/// An inbound provider event (already parsed into `payload`).
pub struct InboundEvent {
    pub company_id: Uuid,
    pub connector_id: Uuid,
    pub event_type: String,
    /// The provider's raw notification id — audit only (NOT the dedup key; it varies per notification).
    pub external_id: String,
    /// The BUSINESS action identity (order/transaction ref + terminal state, e.g. "SO-9:settled") — the
    /// dedup key, stable across the multiple notifications a provider sends per order.
    pub business_key: String,
    pub raw: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReceiveOutcome {
    pub event_id: Uuid,
    pub status: String, // mapped | ignored | failed | duplicate
    pub mapped_ref_id: Option<Uuid>,
    pub duplicate: bool,
}

/// A failed event, surfaced so an operator can see + retry an unbooked action without touching the ledger.
#[derive(Debug, Clone, PartialEq)]
pub struct FailedEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub external_id: String,
    pub business_key: String,
    pub error_detail: Option<String>,
}

pub struct IntegrationsWriteService {
    pool: PgPool,
    connectors: IntegrationConnectorRepository,
    events: IntegrationEventRepository,
}

impl IntegrationsWriteService {
    pub fn new(pool: PgPool) -> Self {
        let connectors = IntegrationConnectorRepository::new(pool.clone());
        let events = IntegrationEventRepository::new(pool.clone());
        Self { pool, connectors, events }
    }

    /// Register a connector to an external provider.
    pub async fn register_connector(&self, c: NewConnector) -> Result<Uuid, IntegrationError> {
        if c.provider.trim().is_empty() {
            return Err(IntegrationError::Invalid("connector needs a provider".into()));
        }
        let id = Uuid::new_v4();
        // RLS scope (ADR-0008): company is on the DTO — scope the insert so it passes the WITH CHECK fence.
        let r = company_scope::with_company_scope(
            Some(c.company_id),
            self.connectors.insert_connector(&self.pool, &NewConnectorRow {
                id,
                company_id: c.company_id,
                provider: &c.provider,
                kind: &c.kind,
                direction: &c.direction,
            }),
        )
        .await;
        match r {
            Ok(_) => Ok(id),
            Err(e) if e.as_database_error().map(|d| d.is_unique_violation()).unwrap_or(false) =>
                Err(IntegrationError::Invalid("a connector for this provider already exists".into())),
            Err(e) => Err(e.into()),
        }
    }

    /// Receive an inbound event: dedup on (connector, external_id), map it to an internal action via the
    /// `TargetPort`, and record the outcome. A retried webhook returns the original with `duplicate=true` —
    /// it never re-maps. Emits `IntegrationEventMapped` / `IntegrationEventFailed` / `IntegrationEventIgnored`.
    pub async fn receive_event(
        &self,
        e: InboundEvent,
        mapper: &dyn TargetPort,
        events: &dyn IntegrationEventSink,
    ) -> Result<ReceiveOutcome, IntegrationError> {
        if e.external_id.trim().is_empty() {
            return Err(IntegrationError::Invalid("an inbound event needs an external_id".into()));
        }
        if e.business_key.trim().is_empty() {
            return Err(IntegrationError::Invalid("an inbound event needs a business_key (the order/transaction ref + state)".into()));
        }
        // RLS scope (ADR-0008): the inbound event carries its company — scope every read/write below to it,
        // so a webhook is fenced to the tenant that owns the connector even off the request path (a
        // provider callback has no ambient scope of its own).
        // The connector must exist and be active.
        let conn = company_scope::with_company_scope(
            Some(e.company_id),
            self.connectors.fetch_gate(&self.pool, e.connector_id),
        )
        .await?
        .ok_or(IntegrationError::NotFound("connector"))?;
        if !conn.is_active {
            return Err(IntegrationError::InvalidState("connector is not active"));
        }
        let connector_kind = conn.kind;

        // Claim the (connector, business_key) dedup slot — a webhook retry OR a second notification for the
        // same business action conflicts here; a new business action does not.
        let inserted = company_scope::with_company_scope(
            Some(e.company_id),
            self.events.claim_event(&self.pool, &NewEventRow {
                id: Uuid::new_v4(),
                company_id: e.company_id,
                connector_id: e.connector_id,
                event_type: &e.event_type,
                external_id: &e.external_id,
                business_key: &e.business_key,
                raw: &e.raw,
            }),
        )
        .await?;

        let Some(event_id) = inserted else {
            let row = company_scope::with_company_scope(
                Some(e.company_id),
                self.events.fetch_by_business_key(&self.pool, e.connector_id, &e.business_key),
            )
            .await?;
            return Ok(ReceiveOutcome {
                event_id: row.id, status: row.status,
                mapped_ref_id: row.mapped_ref_id, duplicate: true,
            });
        };

        let req = MapRequest {
            company_id: e.company_id, connector_kind, event_type: e.event_type.clone(),
            external_id: e.external_id.clone(),
            // Forward the BUSINESS key (not the per-notification event id) so the target dedups the effect
            // on an order-scoped key — the second layer against a double-applied payment.
            idempotency_key: e.business_key.clone(), payload: e.payload.clone(),
        };
        match mapper.map(&req).await {
            Ok(MapOutcome::Mapped(mref)) => {
                let ev = IntegrationEvent::IntegrationEventMapped(IntegrationEventMapped {
                    event_id, company_id: e.company_id, connector_id: e.connector_id, event_type: e.event_type.clone(),
                    external_id: e.external_id.clone(),
                    internal_ref_type: mref.internal_ref_type.clone(), internal_ref_id: mref.internal_ref_id,
                });
                let mut tx = self.pool.begin().await?;
                company_scope::bind_company_on(&mut tx, e.company_id).await?;
                self.events
                    .mark_mapped(&mut tx, event_id, &mref.internal_ref_type, mref.internal_ref_id)
                    .await?;
                stage(&mut tx, &ev).await?;
                tx.commit().await?;
                events.publish(&ev);
                Ok(ReceiveOutcome { event_id, status: "mapped".into(), mapped_ref_id: Some(mref.internal_ref_id), duplicate: false })
            }
            Ok(MapOutcome::Ignored(reason)) => {
                let ev = IntegrationEvent::IntegrationEventIgnored {
                    event_id, connector_id: e.connector_id, external_id: e.external_id.clone(), reason: reason.clone(),
                };
                let mut tx = self.pool.begin().await?;
                company_scope::bind_company_on(&mut tx, e.company_id).await?;
                self.events.mark_ignored(&mut tx, event_id, &reason).await?;
                stage(&mut tx, &ev).await?;
                tx.commit().await?;
                events.publish(&ev);
                Ok(ReceiveOutcome { event_id, status: "ignored".into(), mapped_ref_id: None, duplicate: false })
            }
            Err(rej) => {
                let ev = IntegrationEvent::IntegrationEventFailed {
                    event_id, company_id: e.company_id, connector_id: e.connector_id,
                    external_id: e.external_id.clone(), reason: rej.code.clone(),
                };
                let mut tx = self.pool.begin().await?;
                company_scope::bind_company_on(&mut tx, e.company_id).await?;
                self.events.mark_failed(&mut tx, event_id, &rej.message).await?;
                stage(&mut tx, &ev).await?;
                tx.commit().await?;
                events.publish(&ev);
                Ok(ReceiveOutcome { event_id, status: "failed".into(), mapped_ref_id: None, duplicate: false })
            }
        }
    }

    /// The failure report for a connector — the failed events with their keys + error — so an operator can
    /// see WHICH provider events (e.g. settled payments) failed to book, WITHOUT querying the private ledger
    /// (completeness council 2026-07-11).
    pub async fn failures(&self, connector_id: Uuid) -> Result<Vec<FailedEvent>, IntegrationError> {
        // RLS scope (ADR-0008), ID-only pattern: the connector id alone identifies the report, so the read
        // rides the request-dedicated connection's `app.company_id` — another tenant's connector returns
        // nothing. A non-request caller must wrap this in `with_company_scope(Some(company_id))`.
        let rows = self.events.fetch_failed(&self.pool, connector_id).await?;
        Ok(rows.into_iter().map(|r| FailedEvent {
            event_id: r.id, event_type: r.event_type, external_id: r.external_id,
            business_key: r.business_key, error_detail: r.error_detail,
        }).collect())
    }

    /// Re-drive a connector's FAILED events through the target after the cause is fixed — the recovery path
    /// the dedup would otherwise weld shut (a re-delivered webhook dedups and never re-maps). Re-invokes the
    /// `TargetPort` under the SAME business-key idempotency the target enforces, so it can't double-apply; a
    /// still-`failed` event that now maps transitions `failed → mapped`. Returns the number newly mapped
    /// (completeness council 2026-07-11).
    pub async fn retry_failed(
        &self,
        connector_id: Uuid,
        mapper: &dyn TargetPort,
        events: &dyn IntegrationEventSink,
    ) -> Result<usize, IntegrationError> {
        // RLS scope (ADR-0008), ID-only pattern: identified by the connector id alone, so this first read
        // rides the request-dedicated connection. Having read the connector's company, every read/write
        // below carries it explicitly — the retry loop is long-running and may outlive the request scope.
        let conn = self
            .connectors
            .fetch_for_retry(&self.pool, connector_id)
            .await?
            .ok_or(IntegrationError::NotFound("connector"))?;
        let company_id = conn.company_id;
        let connector_kind = conn.kind;

        let rows = company_scope::with_company_scope(
            Some(company_id),
            self.events.fetch_failed(&self.pool, connector_id),
        )
        .await?;

        let mut mapped = 0usize;
        for row in &rows {
            let event_id = row.id;
            let business_key = row.business_key.clone();
            let req = MapRequest {
                company_id, connector_kind: connector_kind.clone(), event_type: row.event_type.clone(),
                external_id: row.external_id.clone(), idempotency_key: business_key.clone(),
                payload: serde_json::from_str(&row.payload).unwrap_or(serde_json::Value::Null),
            };
            match mapper.map(&req).await {
                Ok(MapOutcome::Mapped(mref)) => {
                    let ev = IntegrationEvent::IntegrationEventMapped(IntegrationEventMapped {
                        event_id, company_id, connector_id, event_type: row.event_type.clone(),
                        external_id: row.external_id.clone(),
                        internal_ref_type: mref.internal_ref_type.clone(), internal_ref_id: mref.internal_ref_id,
                    });
                    let mut tx = self.pool.begin().await?;
                    company_scope::bind_company_on(&mut tx, company_id).await?;
                    let m = self
                        .events
                        .retry_mark_mapped(&mut tx, event_id, &mref.internal_ref_type, mref.internal_ref_id)
                        .await?;
                    if m == 1 {
                        stage(&mut tx, &ev).await?;
                        tx.commit().await?;
                        events.publish(&ev);
                        mapped += 1;
                    } else {
                        tx.rollback().await?;
                    }
                }
                Ok(MapOutcome::Ignored(reason)) => {
                    company_scope::with_company_scope(
                        Some(company_id),
                        self.events.retry_mark_ignored(&self.pool, event_id, &reason),
                    )
                    .await?;
                }
                Err(rej) => {
                    company_scope::with_company_scope(
                        Some(company_id),
                        self.events.set_error_detail(&self.pool, event_id, &rej.message),
                    )
                    .await?;
                }
            }
        }
        Ok(mapped)
    }
}

async fn stage(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, event: &IntegrationEvent) -> Result<(), IntegrationError> {
    let (etype, agg_id) = match event {
        IntegrationEvent::IntegrationEventMapped(m) => ("IntegrationEventMapped", m.event_id),
        IntegrationEvent::IntegrationEventFailed { event_id, .. } => ("IntegrationEventFailed", *event_id),
        IntegrationEvent::IntegrationEventIgnored { event_id, .. } => ("IntegrationEventIgnored", *event_id),
    };
    let record = backbone_outbox::OutboxRecord::new(
        etype, "IntegrationEvent", agg_id.to_string(),
        serde_json::to_value(event).map_err(|e| IntegrationError::Invalid(e.to_string()))?,
        Utc::now(),
    );
    backbone_outbox::outbox::stage(&mut **tx, "integrations", &record)
        .await.map_err(|e| IntegrationError::Invalid(format!("outbox stage: {e}")))?;
    Ok(())
}
