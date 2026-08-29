use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::OAuthProvider;
use super::IntegrationAccountStatus;
use super::AuditMetadata;

/// Strongly-typed ID for IntegrationAccount
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IntegrationAccountId(pub Uuid);

impl IntegrationAccountId {
    pub fn new(id: Uuid) -> Self { Self(id) }
    pub fn generate() -> Self { Self(Uuid::new_v4()) }
    pub fn into_inner(self) -> Uuid { self.0 }
}

impl std::fmt::Display for IntegrationAccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for IntegrationAccountId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl From<Uuid> for IntegrationAccountId {
    fn from(id: Uuid) -> Self { Self(id) }
}

impl From<IntegrationAccountId> for Uuid {
    fn from(id: IntegrationAccountId) -> Self { id.0 }
}

impl AsRef<Uuid> for IntegrationAccountId {
    fn as_ref(&self) -> &Uuid { &self.0 }
}

impl std::ops::Deref for IntegrationAccountId {
    type Target = Uuid;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IntegrationAccount {
    pub id: Uuid,
    pub company_id: Uuid,
    pub provider: OAuthProvider,
    pub account_ref: String,
    pub status: IntegrationAccountStatus,
    pub scopes: String,
    pub pkce_verifier: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_refreshed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    #[sqlx(json)]
    pub metadata: AuditMetadata,
}

impl IntegrationAccount {
    /// Create a builder for IntegrationAccount
    pub fn builder() -> IntegrationAccountBuilder {
        <IntegrationAccountBuilder as Default>::default()
    }

    /// Create a new IntegrationAccount with required fields
    pub fn new(company_id: Uuid, provider: OAuthProvider, account_ref: String, status: IntegrationAccountStatus, scopes: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            company_id,
            provider,
            account_ref,
            status,
            scopes,
            pkce_verifier: None,
            expires_at: None,
            last_refreshed_at: None,
            metadata: AuditMetadata::default(),
        }
    }

    /// Get the entity's unique identifier
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    /// Get a strongly-typed ID for this entity
    pub fn typed_id(&self) -> IntegrationAccountId {
        IntegrationAccountId(self.id)
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
    pub fn status(&self) -> &IntegrationAccountStatus {
        &self.status
    }


    // ==========================================================
    // Fluent Setters (with_* for optional fields)
    // ==========================================================

    /// Set the pkce_verifier field (chainable)
    pub fn with_pkce_verifier(mut self, value: String) -> Self {
        self.pkce_verifier = Some(value);
        self
    }

    /// Set the expires_at field (chainable)
    pub fn with_expires_at(mut self, value: DateTime<Utc>) -> Self {
        self.expires_at = Some(value);
        self
    }

    /// Set the last_refreshed_at field (chainable)
    pub fn with_last_refreshed_at(mut self, value: DateTime<Utc>) -> Self {
        self.last_refreshed_at = Some(value);
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
                "provider" => {
                    if let Ok(v) = serde_json::from_value(value) { self.provider = v; }
                }
                "account_ref" => {
                    if let Ok(v) = serde_json::from_value(value) { self.account_ref = v; }
                }
                "status" => {
                    if let Ok(v) = serde_json::from_value(value) { self.status = v; }
                }
                "scopes" => {
                    if let Ok(v) = serde_json::from_value(value) { self.scopes = v; }
                }
                "pkce_verifier" => {
                    if let Ok(v) = serde_json::from_value(value) { self.pkce_verifier = v; }
                }
                "expires_at" => {
                    if let Ok(v) = serde_json::from_value(value) { self.expires_at = v; }
                }
                "last_refreshed_at" => {
                    if let Ok(v) = serde_json::from_value(value) { self.last_refreshed_at = v; }
                }
                _ => {} // ignore unknown fields
            }
        }
    }

    // <<< CUSTOM METHODS START >>>
    // <<< CUSTOM METHODS END >>>
}

impl super::Entity for IntegrationAccount {
    type Id = Uuid;

    fn entity_id(&self) -> &Self::Id {
        &self.id
    }

    fn entity_type() -> &'static str {
        "IntegrationAccount"
    }
}

impl backbone_core::PersistentEntity for IntegrationAccount {
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

impl backbone_orm::EntityRepoMeta for IntegrationAccount {
    fn column_types() -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        m.insert("id".to_string(), "uuid".to_string());
        m.insert("company_id".to_string(), "uuid".to_string());
        m.insert("provider".to_string(), "o_auth_provider".to_string());
        m.insert("status".to_string(), "integration_account_status".to_string());
        m
    }
    fn search_fields() -> &'static [&'static str] {
        &["account_ref", "scopes"]
    }
    fn company_field() -> Option<&'static str> {
        Some("company_id")
    }
}

/// Builder for IntegrationAccount entity
///
/// Provides a fluent API for constructing IntegrationAccount instances.
/// System fields (id, metadata, timestamps) are auto-initialized.
#[derive(Debug, Clone, Default)]
pub struct IntegrationAccountBuilder {
    company_id: Option<Uuid>,
    provider: Option<OAuthProvider>,
    account_ref: Option<String>,
    status: Option<IntegrationAccountStatus>,
    scopes: Option<String>,
    pkce_verifier: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    last_refreshed_at: Option<DateTime<Utc>>,
}

impl IntegrationAccountBuilder {
    /// Set the company_id field (required)
    pub fn company_id(mut self, value: Uuid) -> Self {
        self.company_id = Some(value);
        self
    }

    /// Set the provider field (required)
    pub fn provider(mut self, value: OAuthProvider) -> Self {
        self.provider = Some(value);
        self
    }

    /// Set the account_ref field (required)
    pub fn account_ref(mut self, value: String) -> Self {
        self.account_ref = Some(value);
        self
    }

    /// Set the status field (default: `IntegrationAccountStatus::default()`)
    pub fn status(mut self, value: IntegrationAccountStatus) -> Self {
        self.status = Some(value);
        self
    }

    /// Set the scopes field (default: `"".to_string()`)
    pub fn scopes(mut self, value: String) -> Self {
        self.scopes = Some(value);
        self
    }

    /// Set the pkce_verifier field (optional)
    pub fn pkce_verifier(mut self, value: String) -> Self {
        self.pkce_verifier = Some(value);
        self
    }

    /// Set the expires_at field (optional)
    pub fn expires_at(mut self, value: DateTime<Utc>) -> Self {
        self.expires_at = Some(value);
        self
    }

    /// Set the last_refreshed_at field (optional)
    pub fn last_refreshed_at(mut self, value: DateTime<Utc>) -> Self {
        self.last_refreshed_at = Some(value);
        self
    }

    /// Build the IntegrationAccount entity
    ///
    /// Returns Err if any required field without a default is missing.
    pub fn build(self) -> Result<IntegrationAccount, String> {
        let company_id = self.company_id.ok_or_else(|| "company_id is required".to_string())?;
        let provider = self.provider.ok_or_else(|| "provider is required".to_string())?;
        let account_ref = self.account_ref.ok_or_else(|| "account_ref is required".to_string())?;

        Ok(IntegrationAccount {
            id: Uuid::new_v4(),
            company_id,
            provider,
            account_ref,
            status: self.status.unwrap_or_default(),
            scopes: self.scopes.unwrap_or("".to_string()),
            pkce_verifier: self.pkce_verifier,
            expires_at: self.expires_at,
            last_refreshed_at: self.last_refreshed_at,
            metadata: AuditMetadata::default(),
        })
    }
}
