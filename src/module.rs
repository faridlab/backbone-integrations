//! Module composition root.
//!
//! Wires the single `Example` service into a module struct via the builder
//! pattern. Parent applications consume this by:
//!
//! ```rust,ignore
//! let module = Module::builder()
//!     .with_database(pool.clone())
//!     .build()?;
//! let router = module.http_routes();
//! ```

use std::sync::Arc;

use axum::Router;
use sqlx::PgPool;

use crate::application::service::ExampleService;
use crate::infrastructure::persistence::ExampleRepository;
use crate::presentation::http::create_example_routes;

/// Skeleton module composition root.
pub struct Module {
    pub example_service: Arc<ExampleService>,
}

impl Module {
    /// Start building a new module.
    pub fn builder() -> ModuleBuilder {
        ModuleBuilder::new()
    }

    /// Compose all HTTP routes exposed by this module.
    pub fn http_routes(&self) -> Router {
        Router::new().merge(create_example_routes(self.example_service.clone()))
    }
}

/// Builder for [`Module`].
pub struct ModuleBuilder {
    db_pool: Option<PgPool>,
}

impl ModuleBuilder {
    pub fn new() -> Self {
        Self { db_pool: None }
    }

    /// Provide the database connection pool to wire into every repository.
    pub fn with_database(mut self, pool: PgPool) -> Self {
        self.db_pool = Some(pool);
        self
    }

    /// Build the module with the configured dependencies.
    pub fn build(self) -> anyhow::Result<Module> {
        let db_pool = self
            .db_pool
            .ok_or_else(|| anyhow::anyhow!("Database pool not configured"))?;

        // Example service
        let example_repository = Arc::new(ExampleRepository::new(db_pool.clone()));
        let example_service =
            Arc::new(ExampleService::with_repository(example_repository.clone()));

        Ok(Module { example_service })
    }
}

impl Default for ModuleBuilder {
    fn default() -> Self {
        Self::new()
    }
}
