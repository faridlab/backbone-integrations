// This directory's extension (hand-written; ADR-0031). The generated mod.rs (lib.rs for
// src/) pulls it in with include!, so its lines resolve against this directory.

// The hand-written integrations SQL's parameter/projection types (see
// `integration_connector_repository` and `integration_event_repository`, both declared `user_owned` in
// metaphor.codegen.yaml).
pub use integration_connector_repository::{ConnectorGateRow, ConnectorRetryRow, NewConnectorRow};
pub use integration_event_repository::{EventOutcomeRow, FailedEventRow, NewEventRow};
