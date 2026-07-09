use serde::{Deserialize, Serialize};
use sqlx::Type;
use std::str::FromStr;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "connector_kind", rename_all = "snake_case")]
pub enum ConnectorKind {
    PaymentGateway,
    Marketplace,
    BankFeed,
    Courier,
}

impl std::fmt::Display for ConnectorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PaymentGateway => write!(f, "payment_gateway"),
            Self::Marketplace => write!(f, "marketplace"),
            Self::BankFeed => write!(f, "bank_feed"),
            Self::Courier => write!(f, "courier"),
        }
    }
}

impl FromStr for ConnectorKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "payment_gateway" => Ok(Self::PaymentGateway),
            "marketplace" => Ok(Self::Marketplace),
            "bank_feed" => Ok(Self::BankFeed),
            "courier" => Ok(Self::Courier),
            _ => Err(format!("Unknown ConnectorKind variant: {}", s)),
        }
    }
}

impl Default for ConnectorKind {
    fn default() -> Self {
        Self::PaymentGateway
    }
}
