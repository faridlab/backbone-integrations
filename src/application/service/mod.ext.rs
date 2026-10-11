// This directory's extension (hand-written; ADR-0031). The generated mod.rs (lib.rs for
// src/) pulls it in with include!, so its lines resolve against this directory.

pub mod integrations_ports;
pub mod integrations_events;
pub mod integrations_write_service;
pub mod integrations_oauth_ports;
pub mod integrations_oauth;
pub use integrations_ports::{MapOutcome, MapRejected, MapRequest, MappedRef, TargetPort};
pub use integrations_events::{IntegrationEvent, IntegrationEventMapped, IntegrationEventSink, LoggingSink};
pub use integrations_write_service::{FailedEvent, InboundEvent, IntegrationError, IntegrationsWriteService, NewConnector, ReceiveOutcome};
pub use integrations_oauth_ports::{OAuthCredentialFailure, OAuthCredentialStore, PURPOSE_OAUTH_TOKEN, TokenBundle, TokenMetadata};
pub use integrations_oauth::{
    AccountStatus, AuthorizeRequest, AuthorizeResponse, CompleteOutcome, CompleteRequest,
    IntegrationsOauthConfig, IntegrationsOauthService, OauthError, RefreshSummary,
    STATE_TTL_SECONDS,
};
