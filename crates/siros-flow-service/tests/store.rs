//! The FlowStore contract (design §8.6): the CAS discipline and the
//! armed-step handle index — the Mode B `challenge_handle` /
//! deferred `transaction` discipline, generalized. The in-memory
//! backend is the reference; the contract is the source of truth.

use siros_flow_core::engine::{FlowInstance, FlowState};
use siros_flow_service::{ArmedStep, FlowRecord, FlowStore, MemoryFlowStore};

fn instance(flow: &str) -> FlowInstance {
    let definition = siros_flow_core::language::FlowDefinition::from_yaml(&format!(
        "flow: {flow}\nlanguage_version: 1\nsteps:\n  - presentation: {{id: p, request: [{{id: pid, format: dc+sd-jwt, meta: {{vct_values: [urn:eudi:pid:1]}}}}]}}\n  - end\n"
    ))
    .unwrap();
    FlowInstance::start(&definition, 1_000, 300).unwrap()
}

#[tokio::test]
async fn insert_update_and_the_version_cas() {
    let store = MemoryFlowStore::new();
    store
        .insert(FlowRecord::new(
            "cas".to_owned(),
            instance("cas"),
            vec![1, 2, 3],
        ))
        .await
        .unwrap();
    let record = store.get("cas").await.unwrap().unwrap();
    assert_eq!(record.version, 0);
    assert_eq!(record.instance.state, FlowState::Running);

    // The update applies at the expected version and bumps it.
    let mut moved = record.instance.clone();
    moved
        .step(siros_flow_core::engine::FlowEvent::StepArmed)
        .unwrap();
    let updated = store
        .update(
            "cas",
            record.version,
            moved,
            None,
            vec![4, 5, 6],
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(updated.version, 1);

    // A stale version refuses — a concurrent response and a sweep
    // cannot interleave.
    let stale = store
        .update(
            "cas",
            0,
            updated.instance.clone(),
            None,
            Vec::new(),
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(stale.code, "illegal_transition");
}

#[tokio::test]
async fn the_request_object_peeks_without_claiming() {
    // The wallet may fetch the request object repeatedly (§8.6): the
    // peek is read-only — the claim stays take_by_handle's
    // single-use discipline.
    let store = MemoryFlowStore::new();
    let mut record = FlowRecord::new("peek".to_owned(), instance("peek"), vec![7, 7, 7]);
    record.armed = Some(ArmedStep {
        handle: "fr_peekhandle".to_owned(),
        step_id: "p".to_owned(),
        sealed_step: vec![9, 9],
        jar: "the public request object".to_owned(),
    });
    store.insert(record).await.unwrap();

    // Repeated peeks: the same object, the arm still armed.
    for _ in 0..3 {
        assert_eq!(
            store
                .peek_request_object("fr_peekhandle")
                .await
                .unwrap()
                .as_deref(),
            Some("the public request object")
        );
    }
    // An unknown handle peeks nothing.
    assert_eq!(store.peek_request_object("fr_nope").await.unwrap(), None);
    // The claim still works after the peeks.
    let taken = store.take_by_handle("fr_peekhandle").await.unwrap();
    assert!(taken.is_some());
    // And the arm is cleared: neither a peek nor a second take finds it.
    assert_eq!(
        store.peek_request_object("fr_peekhandle").await.unwrap(),
        None
    );
    assert!(store
        .take_by_handle("fr_peekhandle")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn the_handle_index_arms_finds_and_takes_single_use() {
    let store = MemoryFlowStore::new();
    let mut record = FlowRecord::new("handles".to_owned(), instance("handles"), vec![7, 7, 7]);
    record.armed = Some(ArmedStep {
        handle: "fr_testhandle".to_owned(),
        step_id: "p".to_owned(),
        sealed_step: vec![9, 9],
        jar: "the public request object".to_owned(),
    });
    store.insert(record).await.unwrap();

    // Find (read-only — the Mode B peek: verify before claim).
    let found = store
        .find_by_handle("fr_testhandle")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.instance_id, "handles");
    assert_eq!(found.armed.as_ref().unwrap().step_id, "p");
    // An unknown handle misses.
    assert!(store.find_by_handle("fr_other").await.unwrap().is_none());

    // Take (single-use): the snapshot carries the arm; the record's
    // arm clears under the lock; a second take misses.
    let taken = store
        .take_by_handle("fr_testhandle")
        .await
        .unwrap()
        .unwrap();
    assert!(taken.armed.is_some(), "the claim snapshot carries the arm");
    assert!(
        store
            .take_by_handle("fr_testhandle")
            .await
            .unwrap()
            .is_none(),
        "the arm is single-use"
    );
    // The record no longer carries the arm (the walk re-arms or
    // advances).
    let record = store.get("handles").await.unwrap().unwrap();
    assert!(record.armed.is_none());
}

#[tokio::test]
async fn the_sweep_expires_and_purges_sealed_context() {
    let store = MemoryFlowStore::new();
    store
        .insert(FlowRecord::new(
            "sweep-me".to_owned(),
            instance("sweep-me"),
            vec![7, 7, 7],
        ))
        .await
        .unwrap();
    store.sweep(2_000, 3_600).await.unwrap();
    let record = store.get("sweep-me").await.unwrap().unwrap();
    assert_eq!(record.instance.state, FlowState::Expired);
    assert!(record.sealed_context.is_empty());
    // The skeleton survives (handles and digests outlive the data).
    assert_eq!(record.instance_id, "sweep-me");
}

#[tokio::test]
async fn a_duplicate_instance_refuses() {
    let store = MemoryFlowStore::new();
    store
        .insert(FlowRecord::new("dup".to_owned(), instance("dup"), vec![]))
        .await
        .unwrap();
    let error = store
        .insert(FlowRecord::new("dup".to_owned(), instance("dup"), vec![]))
        .await
        .unwrap_err();
    assert!(error.message.contains("already exists"));
}
