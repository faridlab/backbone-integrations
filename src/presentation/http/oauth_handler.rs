//! The verb-shaped OAuth HTTP surface (hand-authored, user-owned).
//!
//! Five verbs, no generic CRUD anywhere on it:
//!
//! - `POST /oauth/authorize` — initiation (`write:integrations`): returns the
//!   provider consent URL bound to a freshly minted account row.
//! - `GET /oauth/callback` — the provider redirect target. PUBLIC (the
//!   provider cannot carry the caller's auth), and side-effect-free by
//!   construction: it verifies the signed state and serves a page whose only
//!   act is auto-submitting an invisible POST form — a safe method never
//!   writes.
//! - `POST /oauth/complete` — the form target (`write:integrations`):
//!   code exchange + identity gauntlet + store + transition. Accepts the
//!   RFC-8058-style form body the page submits AND a plain JSON body.
//! - `POST /oauth/:id/disconnect` — revoke credential + terminal account
//!   status (`delete:integrations`).
//! - `GET /oauth/:id/status` — metadata-only account view (any authenticated
//!   principal of the owning company).
//!
//! Authorization fails closed: every route except the callback sits behind
//! [`require_principal`] (401 without a validated principal extension — the
//! composing host's auth layer inserts it) and enforces its own permission
//! (403 without it). No god flag grants every verb.
//!
//! No response ever carries token material — the account row holds none, and
//! the store is reachable only through the service's port calls.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::application::service::integrations_oauth::{
    AuthorizeRequest, AuthorizeResponse, CompleteOutcome, CompleteRequest, IntegrationsOauthService,
    OauthError,
};

/// The validated principal the composing host's auth layer inserts into the
/// request extensions. Present ⇒ authenticated; the permission list carries
/// the module-scope grants (`write:integrations`, `delete:integrations` …).
#[derive(Debug, Clone)]
pub struct OAuthPrincipal {
    pub company_id: Uuid,
    pub user_id: Option<Uuid>,
    pub permissions: Vec<String>,
}

impl OAuthPrincipal {
    fn has(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }
}

/// Auth-required layer: 401 unless a validated principal extension is on the
/// request (fail closed — absence of auth information is never access).
pub async fn require_principal(req: axum::extract::Request, next: Next) -> Response {
    if req.extensions().get::<OAuthPrincipal>().is_none() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "OAUTH_UNAUTHENTICATED",
            "authentication required: no validated principal on the request",
        );
    }
    next.run(req).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Error → HTTP
// ─────────────────────────────────────────────────────────────────────────────

fn error_response(status: StatusCode, code: &str, message: impl std::fmt::Display) -> Response {
    (
        status,
        Json(serde_json::json!({
            "success": false,
            "error": code,
            "message": message.to_string(),
        })),
    )
        .into_response()
}

impl IntoResponse for OauthError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            OauthError::Invalid(_) => (StatusCode::BAD_REQUEST, "OAUTH_INVALID_INPUT"),
            OauthError::State(_) => (StatusCode::BAD_REQUEST, "OAUTH_STATE_REJECTED"),
            OauthError::Identity(_) => (StatusCode::BAD_REQUEST, "OAUTH_IDENTITY_REJECTED"),
            OauthError::Unstoreable(_) => (StatusCode::BAD_GATEWAY, "OAUTH_UNSTOREABLE_TOKEN"),
            OauthError::NotFound => (StatusCode::NOT_FOUND, "OAUTH_ACCOUNT_NOT_FOUND"),
            OauthError::ProviderUnconfigured(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "OAUTH_PROVIDER_UNCONFIGURED")
            }
            OauthError::Transport(_) => (StatusCode::BAD_GATEWAY, "OAUTH_PROVIDER_TRANSPORT"),
            OauthError::Store(_) => (StatusCode::SERVICE_UNAVAILABLE, "OAUTH_CREDENTIAL_STORE"),
            OauthError::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, "OAUTH_DATABASE"),
        };
        error_response(status, code, self)
    }
}

fn forbidden(permission: &str) -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "OAUTH_FORBIDDEN",
        format!("this route requires the {permission:?} permission"),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Route handlers
// ─────────────────────────────────────────────────────────────────────────────

/// `POST /oauth/authorize` — start one authorization.
async fn authorize(
    State(service): State<Arc<IntegrationsOauthService>>,
    axum::Extension(principal): axum::Extension<OAuthPrincipal>,
    Json(req): Json<AuthorizeRequest>,
) -> Response {
    if !principal.has("write:integrations") {
        return forbidden("write:integrations");
    }
    match service.authorize(principal.company_id, req).await {
        Ok(out) => (StatusCode::OK, Json(serde_json::json!({ "success": true, "data": out }))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// The provider's redirect query: the code + signed state, or the provider's
/// own refusal (`error=access_denied` when the user declines consent).
#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /oauth/callback` — public, side-effect-free. Serves the auto-POST
/// page; every failure is an error page, never a redirect to any URL the
/// query carried.
async fn callback(
    State(service): State<Arc<IntegrationsOauthService>>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if let Some(err) = q.error.as_deref().filter(|e| !e.trim().is_empty()) {
        return error_page(StatusCode::BAD_REQUEST, "the provider refused the authorization", err);
    }
    let (Some(code), Some(state)) = (q.code.as_deref(), q.state.as_deref()) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "incomplete callback",
            "the callback is missing its code or signed state",
        );
    };
    match service.callback_page(code, state) {
        Ok(page) => Html(page).into_response(),
        Err(e) => error_page(StatusCode::BAD_REQUEST, "the connection could not continue", &e.to_string()),
    }
}

/// `POST /oauth/complete` — exchange + gauntlet + store + transition. The
/// callback page posts a urlencoded form; an API caller may post JSON. The
/// body shape is dispatched on the content type — never parsed twice.
async fn complete(
    State(service): State<Arc<IntegrationsOauthService>>,
    axum::Extension(principal): axum::Extension<OAuthPrincipal>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !principal.has("write:integrations") {
        return forbidden("write:integrations");
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let req = if content_type.starts_with("application/json") {
        match serde_json::from_slice::<CompleteRequest>(&body) {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, "OAUTH_INVALID_INPUT", format!("malformed JSON body: {e}"))
            }
        }
    } else {
        match parse_form_complete(&body) {
            Some(r) => r,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "OAUTH_INVALID_INPUT",
                    "body must be the callback form (code + state) or JSON with those fields",
                )
            }
        }
    };
    match service.complete(principal.company_id, req).await {
        Ok(out) => (StatusCode::OK, Json(serde_json::json!({ "success": true, "data": out }))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /oauth/:id/disconnect` — revoke + terminal status.
async fn disconnect(
    State(service): State<Arc<IntegrationsOauthService>>,
    axum::Extension(principal): axum::Extension<OAuthPrincipal>,
    Path(account_id): Path<Uuid>,
) -> Response {
    if !principal.has("delete:integrations") {
        return forbidden("delete:integrations");
    }
    match service.disconnect(principal.company_id, account_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /oauth/:id/status` — metadata only.
async fn status(
    State(service): State<Arc<IntegrationsOauthService>>,
    axum::Extension(principal): axum::Extension<OAuthPrincipal>,
    Path(account_id): Path<Uuid>,
) -> Response {
    match service.status(principal.company_id, account_id).await {
        Ok(out) => (StatusCode::OK, Json(serde_json::json!({ "success": true, "data": out }))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The router
// ─────────────────────────────────────────────────────────────────────────────

/// Build the OAuth verb routes. The callback is PUBLIC (the provider cannot
/// carry the caller's credentials); every other route requires a validated
/// principal and enforces its own permission.
pub fn create_oauth_routes(service: Arc<IntegrationsOauthService>) -> Router {
    let public = Router::new().route("/oauth/callback", get(callback)).with_state(service.clone());
    let authed = Router::new()
        .route("/oauth/authorize", post(authorize))
        .route("/oauth/complete", post(complete))
        .route("/oauth/:id/disconnect", post(disconnect))
        .route("/oauth/:id/status", get(status))
        .layer(middleware::from_fn(require_principal))
        .with_state(service);
    public.merge(authed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Form body parsing (the callback page's urlencoded POST)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the auto-POST form body (`code=...&state=...`). Returns `None`
/// unless BOTH fields are present and non-empty. Values are
/// percent-decoded (`+` as space, `%XX` escapes) — the page's own encoding,
/// applied to strings the provider influenced.
fn parse_form_complete(body: &[u8]) -> Option<CompleteRequest> {
    let text = std::str::from_utf8(body).ok()?;
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    for pair in text.split('&') {
        let (key, value) = pair.split_once('=')?;
        let decoded = percent_decode(value);
        match key {
            "code" => code = Some(decoded),
            "state" => state = Some(decoded),
            _ => {}
        }
    }
    let code = code.filter(|c| !c.is_empty())?;
    let state = state.filter(|s| !s.is_empty())?;
    Some(CompleteRequest { code, state })
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if let Some(byte) = bytes.get(i + 1..i + 3).and_then(decode_hex_pair) {
                    out.push(byte);
                    i += 3;
                } else {
                    // Truncated or non-hex escape: keep the byte as-is.
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_hex_pair(pair: &[u8]) -> Option<u8> {
    let hi = (pair.first()?).to_ascii_uppercase();
    let lo = (pair.get(1)?).to_ascii_uppercase();
    let digit = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    Some(digit(hi)? * 16 + digit(lo)?)
}

/// A terminal page for a failed callback — plain text (nothing in it is
/// machine-consumed), status 400, no redirect anywhere.
fn error_page(status: StatusCode, title: &str, detail: &str) -> Response {
    let escaped = detail
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    (
        status,
        Html(format!(
            "<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Connection not completed</title></head>\n<body>\n  <h1>{title}</h1>\n  <p>{escaped}</p>\n  <p>Close this window and start the connection again.</p>\n</body>\n</html>\n"
        )),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_body_parses_code_and_state() {
        let req = parse_form_complete(b"code=4%2F0Ax4PKb&state=abc.def").unwrap();
        assert_eq!(req.code, "4/0Ax4PKb");
        assert_eq!(req.state, "abc.def");
        // Plus is space, missing field is refused, empty values are refused.
        assert_eq!(percent_decode("a+b"), "a b");
        assert!(parse_form_complete(b"code=only").is_none());
        assert!(parse_form_complete(b"code=&state=x").is_none());
        assert!(parse_form_complete(b"state=x").is_none());
    }

    #[test]
    fn percent_decode_handles_odd_input_without_panicking() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%2z"), "%2z");
        assert_eq!(percent_decode("%41%42"), "AB");
        assert_eq!(percent_decode("caf%C3%A9"), "café");
    }
}
