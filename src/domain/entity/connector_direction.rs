use serde::{Deserialize, Serialize};
use sqlx::Type;
use std::str::FromStr;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "connector_direction", rename_all = "snake_case")]
pub enum ConnectorDirection {
    Inbound,
    Outbound,
    Both,
}

impl std::fmt::Display for ConnectorDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inbound => write!(f, "inbound"),
            Self::Outbound => write!(f, "outbound"),
            Self::Both => write!(f, "both"),
        }
    }
}

impl FromStr for ConnectorDirection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "inbound" => Ok(Self::Inbound),
            "outbound" => Ok(Self::Outbound),
            "both" => Ok(Self::Both),
            _ => Err(format!("Unknown ConnectorDirection variant: {}", s)),
        }
    }
}

impl Default for ConnectorDirection {
    fn default() -> Self {
        Self::Inbound
    }
}
