//! Inbound target port (hand-authored, user-owned) — the ACL to the internal module a connector feeds.
//!
//! An inbound provider event maps to an INTERNAL action through the target module's PUBLIC contract — a
//! settled payment notification → `backbone-payment` `create_payment`; a marketplace order →
//! `backbone-selling`; a bank-feed line → `backbone-banking`. Integrations never imports those modules — a
//! composing service wires the real target behind this port; the seam test drives the REAL module. Zero
//! normal Cargo edge. Not every event needs an action: a "pending" notification is intentionally IGNORED.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A request to map a parsed inbound event into an internal action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MapRequest {
    pub company_id: Uuid,
    pub connector_kind: String, // payment_gateway | marketplace | bank_feed | courier
    pub event_type: String,
    pub external_id: String,
    /// Stable per-event key (the integration event id) — the target forwards it so a re-map of a stranded
    /// event can't create a duplicate internal record.
    pub idempotency_key: String,
    pub payload: serde_json::Value,
}

/// The internal record an event mapped to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MappedRef {
    pub internal_ref_type: String, // payment | sales_order | bank_transaction
    pub internal_ref_id: Uuid,
}

/// The outcome of mapping — either an internal record was created/changed, or the event was intentionally
/// ignored (no internal action required for this provider event, e.g. a "pending" notification).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MapOutcome {
    Mapped(MappedRef),
    Ignored(String), // reason
}

/// The target rejected the mapping (unmappable payload / business-rule failure). `code` is stable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MapRejected {
    pub code: String,
    pub message: String,
}

/// The inbound mapping seam. A composing service implements it over the target module.
#[async_trait::async_trait]
pub trait TargetPort: Send + Sync {
    async fn map(&self, req: &MapRequest) -> Result<MapOutcome, MapRejected>;
}
