//! Integrations domain events (hand-authored, user-owned) — the processing surface.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An inbound event was mapped to an internal record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrationEventMapped {
    pub event_id: Uuid,
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
    IntegrationEventFailed { event_id: Uuid, company_id: Uuid, connector_id: Uuid, external_id: String, reason: String },
    IntegrationEventIgnored { event_id: Uuid, company_id: Uuid, connector_id: Uuid, external_id: String, reason: String },
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
