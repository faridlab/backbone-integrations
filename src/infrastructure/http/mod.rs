//! Outbound HTTP for the one OAuth generation (hand-authored, user-owned).
//!
//! Everything that leaves the process toward an OAuth provider passes through
//! [`endpoint_guard`]: the compile-time provider registry, the fail-closed
//! endpoint guard, and the transport port with its reqwest implementation.

pub mod endpoint_guard;

pub use endpoint_guard::{
    assert_public_resolution, ip_is_public, EndpointKey, EndpointOverrides, IdentityClaims,
    InvalidEndpoint, OAuthClientConfig, OAuthClientConfigs, OAuthTransport, ProviderAdapter,
    ProviderEndpointOverride, ProviderRegistry, ReqwestOAuthTransport, TokenRequestForm,
    TokenResponse, TransportFailure, TransportFailureKind, ValidatedEndpoint, ValidatedEndpoints,
};
