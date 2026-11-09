//! The flow store (design §8.6): the clear/sealed record split (§5.5)
//! with the **armed-step handle index** — the Mode B `challenge_handle`
//! / deferred `transaction` CAS discipline, generalized to any
//! response-bearing step.

use std::collections::HashMap;
use std::sync::RwLock;

use siros_flow_core::engine::FlowInstance;
use siros_flow_core::{Error, Result};

/// The armed response-bearing step (clear data: handles and ids, never
/// subject values).
#[derive(Debug, Clone, PartialEq)]
pub struct ArmedStep {
    /// The response handle (the response_uri path — opaque, unguessable).
    pub handle: String,
    /// The step id that armed it.
    pub step_id: String,
    /// The step's sealed verifier-side state (the OID4VP session).
    pub sealed_step: Vec<u8>,
}

/// The stored flow record: the clear/sealed split (§5.5). In the
/// clear — the instance (state, position, digest), the armed step,
/// the version. Sealed under the vault — everything subject-shaped:
/// the whole FlowContext (inputs, presentation claims, holder keys,
/// derived values, issuance refs, verdicts).
#[derive(Debug, Clone)]
pub struct FlowRecord {
    /// The instance id (the store's key — `<flow>_<random>`); the
    /// definition name rides `instance.flow`.
    pub instance_id: String,
    pub instance: FlowInstance,
    /// The armed step, if one is waiting for its response.
    pub armed: Option<ArmedStep>,
    /// The sealed FlowContext (the vault's envelope).
    pub sealed_context: Vec<u8>,
    /// The CAS token: every `step`/`take` compares-and-sets on it.
    pub version: u64,
}

impl FlowRecord {
    /// A fresh record: instance started, empty context sealed.
    pub fn new(instance_id: String, instance: FlowInstance, sealed_context: Vec<u8>) -> Self {
        Self {
            instance_id,
            instance,
            armed: None,
            sealed_context,
            version: 0,
        }
    }
}

/// The flow store contract.
#[async_trait::async_trait]
pub trait FlowStore: Send + Sync {
    async fn insert(&self, record: FlowRecord) -> Result<()>;
    async fn get(&self, flow_instance: &str) -> Result<Option<FlowRecord>>;
    /// Advance under CAS: applies only at `expected_version` — a
    /// concurrent response and a sweep cannot interleave.
    async fn update(
        &self,
        flow_instance: &str,
        expected_version: u64,
        instance: FlowInstance,
        armed: Option<ArmedStep>,
        sealed_context: Vec<u8>,
    ) -> Result<FlowRecord>;
    /// Find the record an armed response handle belongs to
    /// (read-only: the DPoP-less check-then-take discipline — verify
    /// BEFORE claiming, like Mode B's peek).
    async fn find_by_handle(&self, handle: &str) -> Result<Option<FlowRecord>>;
    /// Claim the armed step by handle (single-use, atomic): the arm
    /// clears under the lock; a second take misses.
    async fn take_by_handle(&self, handle: &str) -> Result<Option<FlowRecord>>;
    /// The retention sweep (§10): expire past-TTL instances, purge
    /// sealed data past retention.
    async fn sweep(&self, now_unix: i64, retention_after_final_secs: i64) -> Result<()>;
}

/// The in-memory reference backend (single-process dev and tests;
/// MongoDB is the production backend behind the same contract).
#[derive(Default)]
pub struct MemoryFlowStore {
    records: RwLock<HashMap<String, FlowRecord>>,
    by_handle: RwLock<HashMap<String, String>>,
}

impl MemoryFlowStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl FlowStore for MemoryFlowStore {
    async fn insert(&self, record: FlowRecord) -> Result<()> {
        let mut records = self.records.write().map_err(|_| poisoned())?;
        let mut handles = self.by_handle.write().map_err(|_| poisoned())?;
        let id = record.instance_id.clone();
        if records.contains_key(&id) {
            return Err(Error::invalid_input(format!(
                "a flow instance {id:?} already exists"
            )));
        }
        if let Some(armed) = &record.armed {
            handles.insert(armed.handle.clone(), id.clone());
        }
        records.insert(id, record);
        Ok(())
    }

    async fn get(&self, flow_instance: &str) -> Result<Option<FlowRecord>> {
        let records = self.records.read().map_err(|_| poisoned())?;
        Ok(records.get(flow_instance).cloned())
    }

    async fn update(
        &self,
        flow_instance: &str,
        expected_version: u64,
        instance: FlowInstance,
        armed: Option<ArmedStep>,
        sealed_context: Vec<u8>,
    ) -> Result<FlowRecord> {
        let mut records = self.records.write().map_err(|_| poisoned())?;
        let mut handles = self.by_handle.write().map_err(|_| poisoned())?;
        let record = records.get_mut(flow_instance).ok_or_else(|| {
            Error::invalid_input(format!("no such flow instance {flow_instance:?}"))
        })?;
        if record.version != expected_version {
            return Err(Error::illegal_transition(
                "the flow record moved since it was read — retry on the current version",
            ));
        }
        // Swap the armed handle index entry.
        if let Some(previous) = &record.armed {
            handles.remove(&previous.handle);
        }
        if let Some(new_armed) = &armed {
            handles.insert(new_armed.handle.clone(), flow_instance.to_owned());
        }
        record.version += 1;
        record.instance = instance;
        record.armed = armed;
        record.sealed_context = sealed_context;
        Ok(record.clone())
    }

    async fn find_by_handle(&self, handle: &str) -> Result<Option<FlowRecord>> {
        let handles = self.by_handle.read().map_err(|_| poisoned())?;
        let Some(flow_instance) = handles.get(handle) else {
            return Ok(None);
        };
        let records = self.records.read().map_err(|_| poisoned())?;
        Ok(records.get(flow_instance).cloned())
    }

    async fn take_by_handle(&self, handle: &str) -> Result<Option<FlowRecord>> {
        let mut handles = self.by_handle.write().map_err(|_| poisoned())?;
        let mut records = self.records.write().map_err(|_| poisoned())?;
        let Some(flow_instance) = handles.remove(handle) else {
            return Ok(None);
        };
        let Some(record) = records.get_mut(&flow_instance) else {
            return Ok(None);
        };
        // The arm clears under the lock (single-use — the handle
        // index removal IS the claim; no version bump, the Mode B
        // take discipline); the snapshot carries the sealed step the
        // caller verifies against.
        let snapshot = record.clone();
        if let Some(armed) = &record.armed {
            if armed.handle == handle {
                record.armed = None;
            }
        }
        Ok(Some(snapshot))
    }

    async fn sweep(&self, now_unix: i64, retention_after_final_secs: i64) -> Result<()> {
        let mut records = self.records.write().map_err(|_| poisoned())?;
        let mut handles = self.by_handle.write().map_err(|_| poisoned())?;
        for (id, record) in records.iter_mut() {
            if !record.instance.state.is_final() && record.instance.expires_at_unix < now_unix {
                record.instance.state = siros_flow_core::engine::transition(
                    record.instance.state,
                    siros_flow_core::engine::FlowEvent::Expired,
                )?;
                record.sealed_context = Vec::new();
                if let Some(armed) = record.armed.take() {
                    handles.remove(&armed.handle);
                }
                let _ = id;
            } else if record.instance.state.is_final()
                && record.instance.expires_at_unix + retention_after_final_secs < now_unix
            {
                record.sealed_context = Vec::new();
            }
        }
        Ok(())
    }
}

fn poisoned() -> Error {
    Error::new(
        siros_flow_core::error::code::CONFIGURATION,
        "the flow store lock is poisoned",
    )
}
