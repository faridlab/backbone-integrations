//! Integrations domain events (hand-authored, user-owned) — the processing surface.
//!
//! Tenancy (ADR-0029): the payloads keep their `company_id` field as the legacy
//! tenancy twin. The module's own tables carry no company column — the composing
//! service's tenancy decorator owns org scoping — but the event payloads route
//! through the module's outbox (whose rows keep a tenant column for the
//! cross-tenant relay) and onto consumers that may still be company-fenced.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An inbound event was mapped to an internal record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrationEventMapped {
    pub event_id: Uuid,
    /// Legacy tenancy twin (ADR-0029) — see the module docs above.
    pub company_id: Uuid,
    pub connector_id: Uuid,
    pub event_type: String,
    pub external_id: String,
    pub internal_ref_type: String,
    pub internal_ref_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum IntegrationEvent {
    IntegrationEventMapped(IntegrationEventMapped),
    IntegrationEventFailed { event_id: Uuid, /// Legacy tenancy twin (ADR-0029) — see the module docs above.
                             company_id: Uuid, connector_id: Uuid, external_id: String, reason: String },
    IntegrationEventIgnored { event_id: Uuid, /// Legacy tenancy twin (ADR-0029) — see the module docs above.
                              company_id: Uuid, connector_id: Uuid, external_id: String, reason: String },
}

pub trait IntegrationEventSink: Send + Sync {
    fn publish(&self, event: &IntegrationEvent);
}

#[derive(Debug, Default, Clone)]
pub struct LoggingSink;

impl IntegrationEventSink for LoggingSink {
    fn publish(&self, event: &IntegrationEvent) {
        tracing::info!(?event, "integration event");
    }
}
