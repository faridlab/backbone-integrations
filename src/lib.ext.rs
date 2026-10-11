//! The module's extension (hand-written; ADR-0031): what the module adds beside its
//! generated services. The generated module and builder carry `ModuleExt` and
//! `ModuleBuilderExt` and dereference to them, so their fields read as `module.field`.

#[allow(unused_imports)]
use super::*;

/// State the module adds; read through the generated module's `Deref`.
pub struct ModuleExt {
    /// The hand-authored receive/retry/map path. The module's reason for existing — without this field
    /// it's unreachable through the public API (CLAUDE.md: "MUST register every service in the {Domain}Module builder").
    pub integrations_write_service: Arc<IntegrationsWriteService>,
    /// The one OAuth generation service. `Option` because composition opts in
    /// (`with_oauth` + the two ports); `oauth_routes()` is empty without it.
    pub integrations_oauth: Option<Arc<IntegrationsOauthService>>,
}

/// State the builder adds.
pub struct ModuleBuilderExt {
    // OAuth generation fields (the one flow's construction inputs)
    oauth_config: Option<IntegrationsOauthConfig>,
    oauth_transport: Option<Arc<dyn OAuthTransport>>,
    oauth_store: Option<Arc<dyn OAuthCredentialStore>>,
}

impl Default for ModuleBuilderExt {
    fn default() -> Self {
        Self {
            oauth_config: None,
            oauth_transport: None,
            oauth_store: None,
        }
    }
}

impl ModuleBuilderExt {
    /// Build the extension's state from what the generated build made.
    #[allow(unused_variables, clippy::redundant_clone)]
    pub(crate) fn build(self, parts: &ModuleParts<'_>) -> anyhow::Result<ModuleExt> {
        let db_pool = parts.db_pool.clone();
        // IntegrationsWrite service — the hand-authored receive/retry/map path; constructed alongside the
        // generated CRUD services so the module ships its whole public surface from the builder.
        let integrations_write_service = Arc::new(IntegrationsWriteService::new(db_pool.clone()));
        // The one OAuth generation. Constructed only when composition opted in; a partial opt-in
        // (config without both ports) is a build error, and IntegrationsOauthService::build
        // re-validates everything fail-closed: the named env var must hold the state-signing key,
        // public_base must be present, and every endpoint override must pass the guard.
        let integrations_oauth = match (self.oauth_config, self.oauth_transport, self.oauth_store) {
            (Some(config), transport, Some(store)) => {
                let transport = match transport {
                    Some(t) => t,
                    None => Arc::new(ReqwestOAuthTransport::new()
                        .map_err(|e| anyhow::anyhow!("building the default OAuth transport: {e}"))?),
                };
                Some(Arc::new(IntegrationsOauthService::build(
                    db_pool.clone(),
                    config,
                    transport,
                    store,
                )?))
            }
            (Some(_), _, None) => {
                return Err(anyhow::anyhow!(
                    "with_oauth needs the credential store bound through the port: with_oauth_store(..)"
                ))
            }
            (None, _, _) => None,
        };
        Ok(ModuleExt {
            integrations_write_service,
            integrations_oauth,
        })
    }
}

impl crate::ThisModule {
    /// Production-safe router: connector admin CRUD + event READ-only.
    ///
    /// Integration events are produced by the idempotent `receive_event` path, not
    /// hand-mutated, so the generic event write/bulk endpoints are deliberately
    /// excluded here — a caller cannot bypass the dedup/map state machine through
    /// this surface. Mount this (or `readonly_routes()`) for production; reserve
    /// `all_crud_routes()` for trusted/admin/seeding only.
    pub fn guarded_routes(&self) -> Router {
        use presentation::http::{
            create_integration_connector_routes,
            create_integration_event_read_routes,
        };
        Router::new()
            .merge(create_integration_connector_routes(self.integration_connector_service.clone()))
            .merge(create_integration_event_read_routes(self.integration_event_service.clone()))
    }
    /// The verb-shaped OAuth surface (authorize / callback / complete /
    /// disconnect / status). Empty when the module was built without
    /// `with_oauth` — mounting it anyway is safe, it contributes no routes.
    pub fn oauth_routes(&self) -> Router {
        use presentation::http::create_oauth_routes;
        match &self.integrations_oauth {
            Some(service) => create_oauth_routes(service.clone()),
            None => Router::new(),
        }
    }
}

impl crate::ThisModuleBuilder {
    /// Opt the module into the one OAuth generation. The config carries the
    /// deployment's public base, per-provider clients, and endpoint overrides
    /// — every override passes the endpoint guard at build time (a bad one
    /// fails the build), and the state-signing key is read from the
    /// environment variable the config names (never a file value).
    pub fn with_oauth(mut self, config: IntegrationsOauthConfig) -> Self {
        self.oauth_config = Some(config);
        self
    }
    /// The outbound OAuth transport (token exchange + server-side identity
    /// read). Defaults to [`ReqwestOAuthTransport`] when omitted.
    pub fn with_oauth_transport(mut self, transport: Arc<dyn OAuthTransport>) -> Self {
        self.oauth_transport = Some(transport);
        self
    }
    /// Bind the credential store through the port (ADR-0024 amendment: no
    /// Cargo edge — the host adapts its store onto these verbs).
    pub fn with_oauth_store(mut self, store: Arc<dyn OAuthCredentialStore>) -> Self {
        self.oauth_store = Some(store);
        self
    }
}
