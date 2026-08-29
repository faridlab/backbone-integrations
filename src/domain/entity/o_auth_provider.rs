use serde::{Deserialize, Serialize};
use sqlx::Type;
use std::str::FromStr;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "o_auth_provider", rename_all = "snake_case")]
pub enum OAuthProvider {
    Gmail,
    Outlook,
    GoogleCalendar,
    MicrosoftCalendar,
}

impl std::fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gmail => write!(f, "gmail"),
            Self::Outlook => write!(f, "outlook"),
            Self::GoogleCalendar => write!(f, "google_calendar"),
            Self::MicrosoftCalendar => write!(f, "microsoft_calendar"),
        }
    }
}

impl FromStr for OAuthProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gmail" => Ok(Self::Gmail),
            "outlook" => Ok(Self::Outlook),
            "google_calendar" => Ok(Self::GoogleCalendar),
            "microsoft_calendar" => Ok(Self::MicrosoftCalendar),
            _ => Err(format!("Unknown OAuthProvider variant: {}", s)),
        }
    }
}

impl Default for OAuthProvider {
    fn default() -> Self {
        Self::Gmail
    }
}
