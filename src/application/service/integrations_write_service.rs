//! The hand-authored integrations write path (user-owned; survives regen).
//!
//! The connector hub: receive an inbound provider event **idempotently** on (connector, external_id) —
//! providers deliver webhooks at-least-once, so a retry must not re-map (double-apply a payment / create a
//! duplicate order) — map it to an internal action via a `TargetPort`, or record it as intentionally
//! ignored. Posts NO GL. Integrations reaches a module only through its public contract (the port).

use backbone_orm::company_scope;
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

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
}

impl IntegrationsWriteService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Register a connector to an external provider.
    pub async fn register_connector(&self, c: NewConnector) -> Result<Uuid, IntegrationError> {
        if c.provider.trim().is_empty() {
            return Err(IntegrationError::Invalid("connector needs a provider".into()));
        }
        let id = Uuid::new_v4();
        // RLS scope (ADR-0008): company is on the DTO — scope the insert so it passes the WITH CHECK fence.
        let insert_q = sqlx::query(
            r#"INSERT INTO integrations.integration_connectors
                 (id, company_id, provider, kind, direction, is_active)
               VALUES ($1,$2,$3,$4::connector_kind,$5::connector_direction,true)"#,
        )
        .bind(id).bind(c.company_id).bind(&c.provider).bind(&c.kind).bind(&c.direction);
        let r = company_scope::with_company_scope(
            Some(c.company_id),
            company_scope::execute_scoped(&self.pool, insert_q),
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
            company_scope::fetch_optional_row_scoped(
                &self.pool,
                sqlx::query(
                    r#"SELECT kind::text AS kind, is_active FROM integrations.integration_connectors
                       WHERE id=$1 AND (metadata->>'deleted_at') IS NULL"#,
                )
                .bind(e.connector_id),
            ),
        )
        .await?
        .ok_or(IntegrationError::NotFound("connector"))?;
        if !conn.get::<bool, _>("is_active") {
            return Err(IntegrationError::InvalidState("connector is not active"));
        }
        let connector_kind: String = conn.get("kind");

        // Claim the (connector, business_key) dedup slot — a webhook retry OR a second notification for the
        // same business action conflicts here; a new business action does not.
        let claim_q = sqlx::query_scalar(
            r#"INSERT INTO integrations.integration_events
                 (id, company_id, connector_id, event_type, external_id, business_key, status, payload)
               VALUES ($1,$2,$3,$4,$5,$6,'received'::integration_status,$7)
               ON CONFLICT (connector_id, business_key) DO NOTHING
               RETURNING id"#,
        )
        .bind(Uuid::new_v4()).bind(e.company_id).bind(e.connector_id).bind(&e.event_type)
        .bind(&e.external_id).bind(&e.business_key).bind(&e.raw);
        let inserted: Option<Uuid> = company_scope::with_company_scope(
            Some(e.company_id),
            company_scope::fetch_optional_scalar_scoped(&self.pool, claim_q),
        )
        .await?;

        let Some(event_id) = inserted else {
            let dup_q = sqlx::query(
                r#"SELECT id, status::text AS status, mapped_ref_id FROM integrations.integration_events
                   WHERE connector_id=$1 AND business_key=$2"#,
            )
            .bind(e.connector_id).bind(&e.business_key);
            let row = company_scope::with_company_scope(
                Some(e.company_id),
                company_scope::fetch_one_row_scoped(&self.pool, dup_q),
            )
            .await?;
            return Ok(ReceiveOutcome {
                event_id: row.get("id"), status: row.get("status"),
                mapped_ref_id: row.get("mapped_ref_id"), duplicate: true,
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
                sqlx::query(
                    r#"UPDATE integrations.integration_events
                       SET status='mapped'::integration_status, mapped_ref_type=$2, mapped_ref_id=$3
                       WHERE id=$1 AND status='received'::integration_status"#,
                )
                .bind(event_id).bind(&mref.internal_ref_type).bind(mref.internal_ref_id)
                .execute(&mut *tx).await?;
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
                sqlx::query(
                    r#"UPDATE integrations.integration_events SET status='ignored'::integration_status, error_detail=$2
                       WHERE id=$1 AND status='received'::integration_status"#,
                )
                .bind(event_id).bind(&reason).execute(&mut *tx).await?;
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
                sqlx::query(
                    r#"UPDATE integrations.integration_events SET status='failed'::integration_status, error_detail=$2
                       WHERE id=$1 AND status='received'::integration_status"#,
                )
                .bind(event_id).bind(&rej.message).execute(&mut *tx).await?;
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
        let rows = company_scope::fetch_all_rows_scoped(
            &self.pool,
            sqlx::query(
                r#"SELECT id, event_type, external_id, business_key, error_detail
                   FROM integrations.integration_events
                   WHERE connector_id=$1 AND status='failed'::integration_status
                   ORDER BY (metadata->>'created_at') NULLS FIRST"#,
            )
            .bind(connector_id),
        )
        .await?;
        Ok(rows.iter().map(|r| FailedEvent {
            event_id: r.get("id"), event_type: r.get("event_type"), external_id: r.get("external_id"),
            business_key: r.get("business_key"), error_detail: r.get("error_detail"),
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
        let conn = company_scope::fetch_optional_row_scoped(
            &self.pool,
            sqlx::query(
                "SELECT company_id, kind::text AS kind FROM integrations.integration_connectors WHERE id=$1")
                .bind(connector_id),
        )
        .await?
        .ok_or(IntegrationError::NotFound("connector"))?;
        let company_id: Uuid = conn.get("company_id");
        let connector_kind: String = conn.get("kind");

        let rows = company_scope::with_company_scope(
            Some(company_id),
            company_scope::fetch_all_rows_scoped(
                &self.pool,
                sqlx::query(
                    r#"SELECT id, event_type, external_id, business_key, payload FROM integrations.integration_events
                       WHERE connector_id=$1 AND status='failed'::integration_status"#,
                )
                .bind(connector_id),
            ),
        )
        .await?;

        let mut mapped = 0usize;
        for row in &rows {
            let event_id: Uuid = row.get("id");
            let business_key: String = row.get("business_key");
            let req = MapRequest {
                company_id, connector_kind: connector_kind.clone(), event_type: row.get("event_type"),
                external_id: row.get("external_id"), idempotency_key: business_key.clone(),
                payload: serde_json::from_str(&row.get::<String, _>("payload")).unwrap_or(serde_json::Value::Null),
            };
            match mapper.map(&req).await {
                Ok(MapOutcome::Mapped(mref)) => {
                    let ev = IntegrationEvent::IntegrationEventMapped(IntegrationEventMapped {
                        event_id, company_id, connector_id, event_type: row.get("event_type"),
                        external_id: row.get("external_id"),
                        internal_ref_type: mref.internal_ref_type.clone(), internal_ref_id: mref.internal_ref_id,
                    });
                    let mut tx = self.pool.begin().await?;
                    company_scope::bind_company_on(&mut tx, company_id).await?;
                    let m = sqlx::query(
                        r#"UPDATE integrations.integration_events
                           SET status='mapped'::integration_status, mapped_ref_type=$2, mapped_ref_id=$3, error_detail=NULL
                           WHERE id=$1 AND status='failed'::integration_status"#,
                    )
                    .bind(event_id).bind(&mref.internal_ref_type).bind(mref.internal_ref_id)
                    .execute(&mut *tx).await?;
                    if m.rows_affected() == 1 {
                        stage(&mut tx, &ev).await?;
                        tx.commit().await?;
                        events.publish(&ev);
                        mapped += 1;
                    } else {
                        tx.rollback().await?;
                    }
                }
                Ok(MapOutcome::Ignored(reason)) => {
                    let ignore_q = sqlx::query(
                        r#"UPDATE integrations.integration_events SET status='ignored'::integration_status, error_detail=$2
                           WHERE id=$1 AND status='failed'::integration_status"#,
                    )
                    .bind(event_id).bind(&reason);
                    company_scope::with_company_scope(
                        Some(company_id),
                        company_scope::execute_scoped(&self.pool, ignore_q),
                    )
                    .await?;
                }
                Err(rej) => {
                    let detail_q = sqlx::query(
                        "UPDATE integrations.integration_events SET error_detail=$2 WHERE id=$1 AND status='failed'::integration_status")
                    .bind(event_id).bind(&rej.message);
                    company_scope::with_company_scope(
                        Some(company_id),
                        company_scope::execute_scoped(&self.pool, detail_q),
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
