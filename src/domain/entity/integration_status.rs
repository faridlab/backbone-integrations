use serde::{Deserialize, Serialize};
use sqlx::Type;
use std::str::FromStr;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "integration_status", rename_all = "snake_case")]
pub enum IntegrationStatus {
    Received,
    Mapped,
    Ignored,
    Failed,
}

impl std::fmt::Display for IntegrationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Received => write!(f, "received"),
            Self::Mapped => write!(f, "mapped"),
            Self::Ignored => write!(f, "ignored"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl FromStr for IntegrationStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "received" => Ok(Self::Received),
            "mapped" => Ok(Self::Mapped),
            "ignored" => Ok(Self::Ignored),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("Unknown IntegrationStatus variant: {}", s)),
        }
    }
}

impl Default for IntegrationStatus {
    fn default() -> Self {
        Self::Received
    }
}
