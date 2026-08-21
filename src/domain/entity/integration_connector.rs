use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::ConnectorKind;
use super::ConnectorDirection;
use super::ConnectorStatus;
use super::AuditMetadata;

/// Strongly-typed ID for IntegrationConnector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IntegrationConnectorId(pub Uuid);

impl IntegrationConnectorId {
    pub fn new(id: Uuid) -> Self { Self(id) }
    pub fn generate() -> Self { Self(Uuid::new_v4()) }
    pub fn into_inner(self) -> Uuid { self.0 }
}

impl std::fmt::Display for IntegrationConnectorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for IntegrationConnectorId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl From<Uuid> for IntegrationConnectorId {
    fn from(id: Uuid) -> Self { Self(id) }
}

impl From<IntegrationConnectorId> for Uuid {
    fn from(id: IntegrationConnectorId) -> Self { id.0 }
}

impl AsRef<Uuid> for IntegrationConnectorId {
    fn as_ref(&self) -> &Uuid { &self.0 }
}

impl std::ops::Deref for IntegrationConnectorId {
    type Target = Uuid;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IntegrationConnector {
    pub id: Uuid,
    pub company_id: Uuid,
    pub provider: String,
    pub kind: ConnectorKind,
    pub direction: ConnectorDirection,
    pub status: ConnectorStatus,
    #[serde(default)]
    #[sqlx(json)]
    pub metadata: AuditMetadata,
}

impl IntegrationConnector {
    /// Create a builder for IntegrationConnector
    pub fn builder() -> IntegrationConnectorBuilder {
        <IntegrationConnectorBuilder as Default>::default()
    }

    /// Create a new IntegrationConnector with required fields
    pub fn new(company_id: Uuid, provider: String, kind: ConnectorKind, direction: ConnectorDirection, status: ConnectorStatus) -> Self {
        Self {
            id: Uuid::new_v4(),
            company_id,
            provider,
            kind,
            direction,
            status,
            metadata: AuditMetadata::default(),
        }
    }

    /// Get the entity's unique identifier
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    /// Get a strongly-typed ID for this entity
    pub fn typed_id(&self) -> IntegrationConnectorId {
        IntegrationConnectorId(self.id)
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
    pub fn status(&self) -> &ConnectorStatus {
        &self.status
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
                "provider" => {
                    if let Ok(v) = serde_json::from_value(value) { self.provider = v; }
                }
                "kind" => {
                    if let Ok(v) = serde_json::from_value(value) { self.kind = v; }
                }
                "direction" => {
                    if let Ok(v) = serde_json::from_value(value) { self.direction = v; }
                }
                "status" => {
                    if let Ok(v) = serde_json::from_value(value) { self.status = v; }
                }
                _ => {} // ignore unknown fields
            }
        }
    }

    // <<< CUSTOM METHODS START >>>
    // <<< CUSTOM METHODS END >>>
}

impl super::Entity for IntegrationConnector {
    type Id = Uuid;

    fn entity_id(&self) -> &Self::Id {
        &self.id
    }

    fn entity_type() -> &'static str {
        "IntegrationConnector"
    }
}

impl backbone_core::PersistentEntity for IntegrationConnector {
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

impl backbone_orm::EntityRepoMeta for IntegrationConnector {
    fn column_types() -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        m.insert("id".to_string(), "uuid".to_string());
        m.insert("company_id".to_string(), "uuid".to_string());
        m.insert("kind".to_string(), "connector_kind".to_string());
        m.insert("direction".to_string(), "connector_direction".to_string());
        m.insert("status".to_string(), "connector_status".to_string());
        m
    }
    fn search_fields() -> &'static [&'static str] {
        &["provider"]
    }
    fn company_field() -> Option<&'static str> {
        Some("company_id")
    }
}

/// Builder for IntegrationConnector entity
///
/// Provides a fluent API for constructing IntegrationConnector instances.
/// System fields (id, metadata, timestamps) are auto-initialized.
#[derive(Debug, Clone, Default)]
pub struct IntegrationConnectorBuilder {
    company_id: Option<Uuid>,
    provider: Option<String>,
    kind: Option<ConnectorKind>,
    direction: Option<ConnectorDirection>,
    status: Option<ConnectorStatus>,
}

impl IntegrationConnectorBuilder {
    /// Set the company_id field (required)
    pub fn company_id(mut self, value: Uuid) -> Self {
        self.company_id = Some(value);
        self
    }

    /// Set the provider field (required)
    pub fn provider(mut self, value: String) -> Self {
        self.provider = Some(value);
        self
    }

    /// Set the kind field (required)
    pub fn kind(mut self, value: ConnectorKind) -> Self {
        self.kind = Some(value);
        self
    }

    /// Set the direction field (default: `ConnectorDirection::default()`)
    pub fn direction(mut self, value: ConnectorDirection) -> Self {
        self.direction = Some(value);
        self
    }

    /// Set the status field (default: `ConnectorStatus::default()`)
    pub fn status(mut self, value: ConnectorStatus) -> Self {
        self.status = Some(value);
        self
    }

    /// Build the IntegrationConnector entity
    ///
    /// Returns Err if any required field without a default is missing.
    pub fn build(self) -> Result<IntegrationConnector, String> {
        let company_id = self.company_id.ok_or_else(|| "company_id is required".to_string())?;
        let provider = self.provider.ok_or_else(|| "provider is required".to_string())?;
        let kind = self.kind.ok_or_else(|| "kind is required".to_string())?;

        Ok(IntegrationConnector {
            id: Uuid::new_v4(),
            company_id,
            provider,
            kind,
            direction: self.direction.unwrap_or_default(),
            status: self.status.unwrap_or_default(),
            metadata: AuditMetadata::default(),
        })
    }
}
