//! The FlowStore contract (design §8.6): the CAS discipline — a
//! transition applies only at the expected record version — and the
//! sweep's bounded lifetimes (§10). The in-memory backend is the
//! reference; the contract is the source of truth.

use siros_flow_core::engine::{FlowInstance, FlowState};
use siros_flow_service::{FlowRecord, FlowStore, MemoryFlowStore};

fn instance(flow: &str) -> FlowInstance {
    let definition = siros_flow_core::language::FlowDefinition::from_yaml(&format!(
        "flow: {flow}\nlanguage_version: 1\nsteps:\n  - end\n"
    ))
    .unwrap();
    FlowInstance::start(&definition, 1_000, 300).unwrap()
}

#[tokio::test]
async fn insert_get_and_the_cas_step() {
    let store = MemoryFlowStore::new();
    store
        .insert(FlowRecord {
            instance: instance("cas"),
            sealed_context: vec![1, 2, 3],
            version: 0,
        })
        .await
        .unwrap();

    let record = store.get("cas").await.unwrap().unwrap();
    assert_eq!(record.version, 0);
    assert_eq!(record.instance.state, FlowState::Running);

    // The step applies at the expected version and bumps it.
    let mut moved = record.instance.clone();
    moved
        .step(siros_flow_core::engine::FlowEvent::StepArmed)
        .unwrap();
    let updated = store
        .step("cas", record.version, moved, vec![4, 5, 6])
        .await
        .unwrap();
    assert_eq!(updated.version, 1);
    assert_eq!(updated.instance.state, FlowState::Waiting);

    // A stale version refuses — a concurrent response and a sweep
    // cannot interleave (the take_transaction discipline).
    let stale = store
        .step("cas", 0, updated.instance.clone(), Vec::new())
        .await
        .unwrap_err();
    assert_eq!(stale.code, "illegal_transition");
}

#[tokio::test]
async fn the_sweep_expires_and_purges_sealed_context() {
    let store = MemoryFlowStore::new();
    store
        .insert(FlowRecord {
            instance: instance("sweep-me"),
            sealed_context: vec![7, 7, 7],
            version: 0,
        })
        .await
        .unwrap();
    // Past TTL, not final: expired this pass, sealed data dropped.
    store.sweep(2_000, 3_600).await.unwrap();
    let record = store.get("sweep-me").await.unwrap().unwrap();
    assert_eq!(record.instance.state, FlowState::Expired);
    assert!(record.sealed_context.is_empty());
    // The record skeleton survives (handles and verdicts outlive the
    // data — the retention discipline, §10).
    assert_eq!(record.instance.flow, "sweep-me");
}

#[tokio::test]
async fn an_unknown_flow_refuses() {
    let store = MemoryFlowStore::new();
    let error = store.get("nope").await;
    assert!(error.is_err() || error.unwrap().is_none());
    let duplicate = store
        .insert(FlowRecord {
            instance: instance("dup"),
            sealed_context: vec![],
            version: 0,
        })
        .await;
    duplicate.unwrap();
    let duplicate = store
        .insert(FlowRecord {
            instance: instance("dup"),
            sealed_context: vec![],
            version: 0,
        })
        .await
        .unwrap_err();
    assert!(duplicate.message.contains("already exists"));
}
