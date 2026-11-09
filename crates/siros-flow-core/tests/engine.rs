//! The flow lifecycle (design §8.6): generic over definitions, the
//! position is data, illegal transitions refuse with stable codes —
//! the `session.rs` discipline, new machine. Source of truth: the
//! design doc's lifecycle, not any implementation convenience.

use siros_flow_core::engine::{
    transition, FlowEvent as Ev, FlowInstance, FlowState as St, StepState,
};
use siros_flow_core::language::FlowDefinition;

#[test]
fn the_legal_lifecycle_transitions() {
    assert_eq!(transition(St::Created, Ev::Started).unwrap(), St::Running);
    assert_eq!(transition(St::Running, Ev::StepArmed).unwrap(), St::Waiting);
    assert_eq!(
        transition(St::Waiting, Ev::StepCompleted).unwrap(),
        St::Running
    );
    assert_eq!(
        transition(St::Running, Ev::FlowCompleted).unwrap(),
        St::Completed
    );
    assert_eq!(transition(St::Running, Ev::Ended).unwrap(), St::Completed);
    assert_eq!(transition(St::Waiting, Ev::Ended).unwrap(), St::Completed);
    assert_eq!(transition(St::Running, Ev::StepFailed).unwrap(), St::Failed);
    assert_eq!(transition(St::Waiting, Ev::StepFailed).unwrap(), St::Failed);
    assert_eq!(transition(St::Running, Ev::Expired).unwrap(), St::Expired);
    assert_eq!(
        transition(St::Created, Ev::ErrorOccurred).unwrap(),
        St::Failed
    );
}

#[test]
fn illegal_transitions_refuse_with_the_stable_code() {
    for (state, event) in [
        (St::Created, Ev::StepArmed),
        (St::Created, Ev::StepCompleted),
        (St::Running, Ev::StepCompleted),
        (St::Waiting, Ev::StepArmed),
        (St::Completed, Ev::Started),
        (St::Completed, Ev::StepCompleted),
        (St::Failed, Ev::StepCompleted),
        (St::Expired, Ev::Started),
    ] {
        let error = transition(state, event).unwrap_err();
        assert_eq!(
            error.code, "illegal_transition",
            "{state:?} + {event:?} must refuse"
        );
    }
}

#[test]
fn final_states_are_final() {
    for state in [St::Completed, St::Failed, St::Expired] {
        assert!(state.is_final());
        for event in [Ev::Started, Ev::StepArmed, Ev::StepCompleted, Ev::Ended] {
            assert!(
                transition(state, event).is_err(),
                "final is final: {state:?} rejects {event:?}"
            );
        }
    }
}

#[test]
fn an_instance_starts_over_its_definition_with_all_steps_pending() {
    let definition = FlowDefinition::from_yaml(
        "flow: instance-shape\nlanguage_version: 1\nsteps:\n  - presentation: {id: p, request: [{id: pid, format: dc+sd-jwt, meta: {vct_values: [urn:eudi:pid:1]}}]}\n  - bind: {id: b, primitive: same-key, params: {left: {step: p, credential: pid, path: [cnf, jwk]}, right: {step: p, credential: pid, path: [cnf, jwk]}}}\n  - end\n",
    )
    .unwrap();
    let instance = FlowInstance::start(&definition, 1_000, 300).unwrap();
    assert_eq!(instance.state, St::Running);
    assert_eq!(instance.position.cursor, 0);
    assert_eq!(instance.position.steps["p"], StepState::Pending);
    assert_eq!(instance.position.steps["b"], StepState::Pending);
    // `end` carries no id: the per-step map keys on step ids only.
    assert_eq!(instance.position.steps.len(), 2);
    // The digest rides the instance: the identity the PDP evidence
    // pins (§9).
    assert_eq!(instance.definition_digest, definition.digest());
    assert_eq!(instance.flow, "instance-shape");
}

#[test]
fn an_instance_moves_only_by_events() {
    let definition = FlowDefinition::from_yaml(
        "flow: moves-by-events\nlanguage_version: 1\nsteps:\n  - presentation: {id: p, request: [{id: pid, format: dc+sd-jwt, meta: {vct_values: [urn:eudi:pid:1]}}]}\n  - end\n",
    )
    .unwrap();
    let mut instance = FlowInstance::start(&definition, 1_000, 300).unwrap();
    instance.step(Ev::StepArmed).unwrap();
    assert_eq!(instance.state, St::Waiting);
    instance.step(Ev::StepCompleted).unwrap();
    assert_eq!(instance.state, St::Running);
    instance.step(Ev::Ended).unwrap();
    assert_eq!(instance.state, St::Completed);
    // Final is final.
    let error = instance.step(Ev::StepArmed).unwrap_err();
    assert_eq!(error.code, "illegal_transition");
}

#[test]
fn the_wire_labels_are_stable() {
    assert_eq!(St::Created.label(), "created");
    assert_eq!(St::Running.label(), "running");
    assert_eq!(St::Waiting.label(), "waiting");
    assert_eq!(St::Completed.label(), "completed");
    assert_eq!(St::Failed.label(), "failed");
    assert_eq!(St::Expired.label(), "expired");
    assert_eq!(StepState::Pending.label(), "pending");
    assert_eq!(StepState::Armed.label(), "armed");
    assert_eq!(StepState::Done.label(), "done");
    assert_eq!(StepState::Failed.label(), "failed");
}
