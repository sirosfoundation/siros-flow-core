//! siros-flow-service — the deployable flow service (design §4.2).
//!
//! **A general service**: every definition in the configured
//! definitions directory is loaded, validated, and exposed — `POST
//! /flows/{flow}/start` starts any of them; the driver walks any
//! definition's steps generically. No flow is hard-coded here; the
//! EHIC flow, the pre-auth parity flow, and whatever else the
//! deployment ships are all data in `flows/`.
//!
//! The P-bw1 primitive set: `presentation` (verifier-core
//! in-process), `bind` (the core's vocabulary), `issuance` (an issuer
//! backend over its session API — the integrator surface), `store`,
//! `end`. The deep-link carrier is the response shape (`response_uri`
//! in the OID4VP request; the offer deep link in the flow's reply).

pub use issuer_client::{IssuanceOutcome, IssuerClient, IssuerCoreClient};
pub use state::FlowServiceState;
pub use store::{ArmedStep, FlowRecord, FlowStore, MemoryFlowStore};

pub mod app;
pub mod config;
pub mod driver;
pub mod http;
pub mod issuer_client;
pub mod keys;
pub mod local_status;
pub mod plugins;
pub mod presentation;
pub mod state;
pub mod store;

/// The family's clock (the issuer service's — one clock across the
/// deployment's components).
pub mod status {
    pub use siros_issuer_service::status::now_unix;
}
