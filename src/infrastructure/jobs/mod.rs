//! Scheduled jobs (hand-authored, user-owned).
//!
//! The module's scheduled job lives here: `refresh_oauth_credentials` — the
//! refresh-before-expiry sweep over OAuth accounts, declared in
//! `schema/hooks/index.hook.yaml` under `scheduled_jobs` (posture `pull`,
//! pickup lock, per-account commits).

pub mod refresh_oauth_credentials;

pub use refresh_oauth_credentials::{
    refresh_oauth_credentials, refresh_oauth_credentials_for_companies, RefreshReport,
    RefreshSchedule,
};
