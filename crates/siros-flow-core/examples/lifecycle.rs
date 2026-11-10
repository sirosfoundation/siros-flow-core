//! Drive a flow instance through its lifecycle — the state machine the
//! service's drivers turn with the carrier events (§6.2).
//!
//! ```sh
//! cargo run -p siros-flow-core --example lifecycle -- flows/ehic-pid-presentation.yaml
//! ```
//!
//! Two rules the example demonstrates:
//! - **`FlowInstance::step` is the only way state moves** — every legal
//!   combination advances, every illegal one is a refusal with the stable
//!   `illegal_transition` code the host must not "recover".
//! - **Final is final**: a completed flow accepts no event at all.

use siros_flow_core::engine::{FlowEvent as Ev, FlowInstance, FlowState as St};
use siros_flow_core::language::FlowDefinition;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "flows/payment-receipt.yaml".to_owned());
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("reading {path}: {e}");
        std::process::exit(1);
    });
    let definition =
        FlowDefinition::from_yaml(&text).unwrap_or_else(|e| panic!("parse refused: {e}"));

    let now = 1_760_000_000;
    let mut instance =
        FlowInstance::start(&definition, now, 3600).expect("a definition starts a flow");
    assert_eq!(instance.state, St::Running);
    println!(
        "started:  {} ({})",
        instance.flow, instance.definition_digest
    );

    // The happy path: a wallet-facing step arms, the wallet answers, the
    // step completes — Running → Waiting → Running per step.
    instance
        .step(Ev::StepArmed)
        .expect("arming a step is legal");
    assert_eq!(instance.state, St::Waiting);
    instance
        .step(Ev::StepCompleted)
        .expect("completing an armed step is legal");
    assert_eq!(instance.state, St::Running);
    println!("stepped:  Running → Waiting → Running");

    // The expiry path: the TTL lapses (retention/sweep sends Expired).
    instance.step(Ev::Expired).expect("expiry mid-run is legal");
    assert_eq!(instance.state, St::Expired);
    println!("expired:  Running → Expired");

    // Illegal transitions are refusals, never silent no-ops: a completed
    // or expired flow accepts no further event.
    let refused = match instance.step(Ev::Started) {
        Err(e) => e,
        Ok(()) => panic!("re-starting an expired flow must refuse"),
    };
    assert_eq!(
        refused.code,
        siros_flow_core::code::ILLEGAL_TRANSITION,
        "the stable code, not a panic"
    );
    println!("refused:  Started in Expired → illegal_transition");
}
