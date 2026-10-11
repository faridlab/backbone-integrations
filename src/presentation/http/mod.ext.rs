// This directory's extension (hand-written; ADR-0031). The generated mod.rs (lib.rs for
// src/) pulls it in with include!, so its lines resolve against this directory.

pub mod oauth_handler;
pub use oauth_handler::{create_oauth_routes, require_principal, OAuthPrincipal};
