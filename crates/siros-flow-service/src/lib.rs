//! siros-flow-service — the deployable flow service (design §4.2).
//!
//! The P-bw1 skeleton: the `FlowStore` trait with the **clear/sealed
//! record split** (§5.5) and the in-memory reference backend. The
//! primitive implementations over the cores (presentation via
//! verifier-core, issuance via issuer-core), the carriers, and the
//! HTTP surface land with the P-bw1 increments — the traits they will
//! cross are this crate's, not the core's.

use std::collections::HashMap;
use std::sync::RwLock;

use siros_flow_core::engine::FlowInstance;
use siros_flow_core::{Error, Result};

/// The stored flow record: the clear/sealed split (§5.5). In the
/// clear — flow id, definition digest, state, position, armed
/// handles, timestamps, bind verdicts (names and parameters, never
/// values). Sealed under a per-flow data key — everything
/// subject-shaped (presentation claims, holder keys, derived values,
/// caller inputs). The engine unseals into memory for one step and
/// re-seals; the plaintext context never leaves the process.
#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub instance: FlowInstance,
    /// The sealed subject-shaped context (the vault's envelope;
    /// opaque bytes here — the vault owns the key material).
    pub sealed_context: Vec<u8>,
    /// A monotonically increasing version — the CAS token (§8.6:
    /// `step` transitions compare-and-set on it).
    pub version: u64,
}

/// The flow store (§8.6): insert, get, a CAS `step`, arm/take per
/// response-bearing step, and the sweep. The in-memory backend serves
/// tests and single-process dev; MongoDB is the production backend
/// behind the same contract (the SessionStore discipline).
#[async_trait::async_trait]
pub trait FlowStore: Send + Sync {
    async fn insert(&self, record: FlowRecord) -> Result<()>;
    async fn get(&self, flow_id: &str) -> Result<Option<FlowRecord>>;
    /// Advance under CAS: the transition applies only if the record is
    /// still at `expected_version` — a concurrent response and a
    /// sweep cannot interleave (the `take_transaction` discipline).
    async fn step(
        &self,
        flow_id: &str,
        expected_version: u64,
        instance: FlowInstance,
        sealed_context: Vec<u8>,
    ) -> Result<FlowRecord>;
    /// The retention sweep (§10): expire past-TTL instances, purge
    /// sealed data per the retention policy. One call, the backend's
    /// own atomicity.
    async fn sweep(&self, now_unix: i64, retention_after_final_secs: i64) -> Result<()>;
}

/// The in-memory reference backend (single-process dev and tests).
#[derive(Default)]
pub struct MemoryFlowStore {
    records: RwLock<HashMap<String, FlowRecord>>,
}

impl MemoryFlowStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl FlowStore for MemoryFlowStore {
    async fn insert(&self, record: FlowRecord) -> Result<()> {
        let mut records = self.records.write().map_err(|_| store_poisoned())?;
        let id = record.instance.flow.clone();
        if records.contains_key(&id) {
            return Err(Error::invalid_input(format!(
                "a flow instance {id:?} already exists"
            )));
        }
        records.insert(id, record);
        Ok(())
    }

    async fn get(&self, flow_id: &str) -> Result<Option<FlowRecord>> {
        let records = self.records.read().map_err(|_| store_poisoned())?;
        Ok(records.get(flow_id).cloned())
    }

    async fn step(
        &self,
        flow_id: &str,
        expected_version: u64,
        instance: FlowInstance,
        sealed_context: Vec<u8>,
    ) -> Result<FlowRecord> {
        let mut records = self.records.write().map_err(|_| store_poisoned())?;
        let record = records
            .get_mut(flow_id)
            .ok_or_else(|| Error::invalid_input(format!("no such flow instance {flow_id:?}")))?;
        if record.version != expected_version {
            return Err(Error::illegal_transition(
                "the flow record moved since it was read — retry on the current version",
            ));
        }
        record.version += 1;
        record.instance = instance;
        record.sealed_context = sealed_context;
        Ok(record.clone())
    }

    async fn sweep(&self, now_unix: i64, retention_after_final_secs: i64) -> Result<()> {
        let mut records = self.records.write().map_err(|_| store_poisoned())?;
        // Expire non-final instances past their TTL; drop sealed data
        // from final instances past retention (the skeleton's policy:
        // the record skeleton survives until the hard delete).
        for record in records.values_mut() {
            if !record.instance.state.is_final() && record.instance.expires_at_unix < now_unix {
                record.instance.state = siros_flow_core::engine::transition(
                    record.instance.state,
                    siros_flow_core::engine::FlowEvent::Expired,
                )?;
                record.sealed_context = Vec::new();
            } else if record.instance.state.is_final()
                && record.instance.expires_at_unix + retention_after_final_secs < now_unix
            {
                record.sealed_context = Vec::new();
            }
        }
        Ok(())
    }
}

fn store_poisoned() -> Error {
    Error::new(
        siros_flow_core::error::code::CONFIGURATION,
        "the flow store lock is poisoned",
    )
}
