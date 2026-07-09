use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::IntegrationStatus;
use super::AuditMetadata;

/// Strongly-typed ID for IntegrationEvent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IntegrationEventId(pub Uuid);

impl IntegrationEventId {
    pub fn new(id: Uuid) -> Self { Self(id) }
    pub fn generate() -> Self { Self(Uuid::new_v4()) }
    pub fn into_inner(self) -> Uuid { self.0 }
}

impl std::fmt::Display for IntegrationEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for IntegrationEventId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl From<Uuid> for IntegrationEventId {
    fn from(id: Uuid) -> Self { Self(id) }
}

impl From<IntegrationEventId> for Uuid {
    fn from(id: IntegrationEventId) -> Self { id.0 }
}

impl AsRef<Uuid> for IntegrationEventId {
    fn as_ref(&self) -> &Uuid { &self.0 }
}

impl std::ops::Deref for IntegrationEventId {
    type Target = Uuid;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IntegrationEvent {
    pub id: Uuid,
    pub company_id: Uuid,
    pub connector_id: Uuid,
    pub event_type: String,
    pub external_id: String,
    pub business_key: String,
    pub status: IntegrationStatus,
    pub payload: String,
    pub mapped_ref_type: Option<String>,
    pub mapped_ref_id: Option<Uuid>,
    pub error_detail: Option<String>,
    #[serde(default)]
    #[sqlx(json)]
    pub metadata: AuditMetadata,
}

impl IntegrationEvent {
    /// Create a builder for IntegrationEvent
    pub fn builder() -> IntegrationEventBuilder {
        IntegrationEventBuilder::default()
    }

    /// Create a new IntegrationEvent with required fields
    pub fn new(company_id: Uuid, connector_id: Uuid, event_type: String, external_id: String, business_key: String, status: IntegrationStatus, payload: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            company_id,
            connector_id,
            event_type,
            external_id,
            business_key,
            status,
            payload,
            mapped_ref_type: None,
            mapped_ref_id: None,
            error_detail: None,
            metadata: AuditMetadata::default(),
        }
    }

    /// Get the entity's unique identifier
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    /// Get a strongly-typed ID for this entity
    pub fn typed_id(&self) -> IntegrationEventId {
        IntegrationEventId(self.id)
    }

    /// Get when this entity was created
    pub fn created_at(&self) -> Option<&DateTime<Utc>> {
        self.metadata.created_at.as_ref()
    }

    /// Get when this entity was last updated
    pub fn updated_at(&self) -> Option<&DateTime<Utc>> {
        self.metadata.updated_at.as_ref()
    }

    /// Check if this entity is soft deleted
    pub fn is_deleted(&self) -> bool {
        self.metadata.deleted_at.is_some()
    }

    /// Check if this entity is active (not deleted)
    pub fn is_active(&self) -> bool {
        self.metadata.deleted_at.is_none()
    }

    /// Get when this entity was deleted
    pub fn deleted_at(&self) -> Option<&DateTime<Utc>> {
        self.metadata.deleted_at.as_ref()
    }

    /// Get who created this entity
    pub fn created_by(&self) -> Option<&Uuid> {
        self.metadata.created_by.as_ref()
    }

    /// Get who last updated this entity
    pub fn updated_by(&self) -> Option<&Uuid> {
        self.metadata.updated_by.as_ref()
    }

    /// Get who deleted this entity
    pub fn deleted_by(&self) -> Option<&Uuid> {
        self.metadata.deleted_by.as_ref()
    }

    /// Get the current status
    pub fn status(&self) -> &IntegrationStatus {
        &self.status
    }


    // ==========================================================
    // Fluent Setters (with_* for optional fields)
    // ==========================================================

    /// Set the mapped_ref_type field (chainable)
    pub fn with_mapped_ref_type(mut self, value: String) -> Self {
        self.mapped_ref_type = Some(value);
        self
    }

    /// Set the mapped_ref_id field (chainable)
    pub fn with_mapped_ref_id(mut self, value: Uuid) -> Self {
        self.mapped_ref_id = Some(value);
        self
    }

    /// Set the error_detail field (chainable)
    pub fn with_error_detail(mut self, value: String) -> Self {
        self.error_detail = Some(value);
        self
    }

    // ==========================================================
    // Partial Update
    // ==========================================================

    /// Apply partial updates from a map of field name to JSON value
    pub fn apply_patch(&mut self, fields: std::collections::HashMap<String, serde_json::Value>) {
        for (key, value) in fields {
            match key.as_str() {
                "company_id" => {
                    if let Ok(v) = serde_json::from_value(value) { self.company_id = v; }
                }
                "connector_id" => {
                    if let Ok(v) = serde_json::from_value(value) { self.connector_id = v; }
                }
                "event_type" => {
                    if let Ok(v) = serde_json::from_value(value) { self.event_type = v; }
                }
                "external_id" => {
                    if let Ok(v) = serde_json::from_value(value) { self.external_id = v; }
                }
                "business_key" => {
                    if let Ok(v) = serde_json::from_value(value) { self.business_key = v; }
                }
                "status" => {
                    if let Ok(v) = serde_json::from_value(value) { self.status = v; }
                }
                "payload" => {
                    if let Ok(v) = serde_json::from_value(value) { self.payload = v; }
                }
                "mapped_ref_type" => {
                    if let Ok(v) = serde_json::from_value(value) { self.mapped_ref_type = v; }
                }
                "mapped_ref_id" => {
                    if let Ok(v) = serde_json::from_value(value) { self.mapped_ref_id = v; }
                }
                "error_detail" => {
                    if let Ok(v) = serde_json::from_value(value) { self.error_detail = v; }
                }
                _ => {} // ignore unknown fields
            }
        }
    }

    // <<< CUSTOM METHODS START >>>
    // <<< CUSTOM METHODS END >>>
}

impl super::Entity for IntegrationEvent {
    type Id = Uuid;

    fn entity_id(&self) -> &Self::Id {
        &self.id
    }

    fn entity_type() -> &'static str {
        "IntegrationEvent"
    }
}

impl backbone_core::PersistentEntity for IntegrationEvent {
    fn entity_id(&self) -> String {
        self.id.to_string()
    }
    fn set_entity_id(&mut self, id: String) {
        if let Ok(uuid) = uuid::Uuid::parse_str(&id) {
            self.id = uuid;
        }
    }
    fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.metadata.created_at
    }
    fn set_created_at(&mut self, ts: chrono::DateTime<chrono::Utc>) {
        self.metadata.created_at = Some(ts);
    }
    fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.metadata.updated_at
    }
    fn set_updated_at(&mut self, ts: chrono::DateTime<chrono::Utc>) {
        self.metadata.updated_at = Some(ts);
    }
    fn deleted_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.metadata.deleted_at
    }
    fn set_deleted_at(&mut self, ts: Option<chrono::DateTime<chrono::Utc>>) {
        self.metadata.deleted_at = ts;
    }
}

impl backbone_orm::EntityRepoMeta for IntegrationEvent {
    fn column_types() -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        m.insert("id".to_string(), "uuid".to_string());
        m.insert("company_id".to_string(), "uuid".to_string());
        m.insert("connector_id".to_string(), "uuid".to_string());
        m.insert("mapped_ref_id".to_string(), "uuid".to_string());
        m.insert("status".to_string(), "integration_status".to_string());
        m
    }
    fn search_fields() -> &'static [&'static str] {
        &["event_type", "external_id", "business_key", "payload"]
    }
}

/// Builder for IntegrationEvent entity
///
/// Provides a fluent API for constructing IntegrationEvent instances.
/// System fields (id, metadata, timestamps) are auto-initialized.
#[derive(Debug, Clone, Default)]
pub struct IntegrationEventBuilder {
    company_id: Option<Uuid>,
    connector_id: Option<Uuid>,
    event_type: Option<String>,
    external_id: Option<String>,
    business_key: Option<String>,
    status: Option<IntegrationStatus>,
    payload: Option<String>,
    mapped_ref_type: Option<String>,
    mapped_ref_id: Option<Uuid>,
    error_detail: Option<String>,
}

impl IntegrationEventBuilder {
    /// Set the company_id field (required)
    pub fn company_id(mut self, value: Uuid) -> Self {
        self.company_id = Some(value);
        self
    }

    /// Set the connector_id field (required)
    pub fn connector_id(mut self, value: Uuid) -> Self {
        self.connector_id = Some(value);
        self
    }

    /// Set the event_type field (required)
    pub fn event_type(mut self, value: String) -> Self {
        self.event_type = Some(value);
        self
    }

    /// Set the external_id field (required)
    pub fn external_id(mut self, value: String) -> Self {
        self.external_id = Some(value);
        self
    }

    /// Set the business_key field (required)
    pub fn business_key(mut self, value: String) -> Self {
        self.business_key = Some(value);
        self
    }

    /// Set the status field (default: `IntegrationStatus::default()`)
    pub fn status(mut self, value: IntegrationStatus) -> Self {
        self.status = Some(value);
        self
    }

    /// Set the payload field (required)
    pub fn payload(mut self, value: String) -> Self {
        self.payload = Some(value);
        self
    }

    /// Set the mapped_ref_type field (optional)
    pub fn mapped_ref_type(mut self, value: String) -> Self {
        self.mapped_ref_type = Some(value);
        self
    }

    /// Set the mapped_ref_id field (optional)
    pub fn mapped_ref_id(mut self, value: Uuid) -> Self {
        self.mapped_ref_id = Some(value);
        self
    }

    /// Set the error_detail field (optional)
    pub fn error_detail(mut self, value: String) -> Self {
        self.error_detail = Some(value);
        self
    }

    /// Build the IntegrationEvent entity
    ///
    /// Returns Err if any required field without a default is missing.
    pub fn build(self) -> Result<IntegrationEvent, String> {
        let company_id = self.company_id.ok_or_else(|| "company_id is required".to_string())?;
        let connector_id = self.connector_id.ok_or_else(|| "connector_id is required".to_string())?;
        let event_type = self.event_type.ok_or_else(|| "event_type is required".to_string())?;
        let external_id = self.external_id.ok_or_else(|| "external_id is required".to_string())?;
        let business_key = self.business_key.ok_or_else(|| "business_key is required".to_string())?;
        let payload = self.payload.ok_or_else(|| "payload is required".to_string())?;

        Ok(IntegrationEvent {
            id: Uuid::new_v4(),
            company_id,
            connector_id,
            event_type,
            external_id,
            business_key,
            status: self.status.unwrap_or(IntegrationStatus::default()),
            payload,
            mapped_ref_type: self.mapped_ref_type,
            mapped_ref_id: self.mapped_ref_id,
            error_detail: self.error_detail,
            metadata: AuditMetadata::default(),
        })
    }
}
