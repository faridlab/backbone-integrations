// This directory's extension (hand-written; ADR-0031). The generated mod.rs (lib.rs for
// src/) pulls it in with include!, so its lines resolve against this directory.

// The hand-authored write path: receive an inbound provider event idempotently and map it via TargetPort,
// plus the port + receiver types a composing service needs to wire the seam from one place.
pub use application::service::IntegrationsWriteService;
pub use application::service::{TargetPort, MapRequest, MapOutcome, MapRejected, MappedRef};
pub use application::service::{InboundEvent, ReceiveOutcome, NewConnector, FailedEvent, IntegrationError};
pub use application::service::{IntegrationEvent, IntegrationEventMapped, IntegrationEventSink, LoggingSink};
// The OAuth credential port (ADR-0024 amendment: the store is reached through a port, never a
// Cargo edge) — the types a composing host needs to bind the credential store for the OAuth flow.
pub use application::service::{OAuthCredentialFailure, OAuthCredentialStore, PURPOSE_OAUTH_TOKEN, TokenBundle, TokenMetadata};
// The one OAuth generation: the service + config a composing host binds (with the two ports it
// runs on), and the outbound endpoint-guard surface its transport belongs to.
pub use application::service::{
    AccountStatus, AuthorizeRequest, AuthorizeResponse, CompleteOutcome, CompleteRequest,
    IntegrationsOauthConfig, IntegrationsOauthService, OauthError, RefreshSummary,
    STATE_TTL_SECONDS,
};
pub use infrastructure::http::{OAuthTransport, ReqwestOAuthTransport};
