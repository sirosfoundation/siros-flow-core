//! The flow lifecycle (design §8.6): one state machine per flow
//! *instance*, generic over definitions — the position in the
//! definition is data (a step cursor + per-step states), so a flow
//! may present, issue, and present again (§5.2: steps interleave).
//! Illegal transitions are refusals with stable codes — the
//! `session.rs` discipline, new machine.

use std::collections::BTreeMap;

use crate::error::Result;
use crate::language::FlowDefinition;

/// The lifecycle (§8.6): `created → running ⇄ waiting →
/// completed | failed | expired`, where `waiting` means a
/// response-bearing step has armed its handle and the engine is
/// parked on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    Created,
    Running,
    Waiting,
    Completed,
    Failed,
    Expired,
}

impl FlowState {
    /// The wire label (evidence, SSE payloads, status JSON).
    pub fn label(&self) -> &'static str {
        match self {
            FlowState::Created => "created",
            FlowState::Running => "running",
            FlowState::Waiting => "waiting",
            FlowState::Completed => "completed",
            FlowState::Failed => "failed",
            FlowState::Expired => "expired",
        }
    }

    pub fn is_final(&self) -> bool {
        matches!(
            self,
            FlowState::Completed | FlowState::Failed | FlowState::Expired
        )
    }
}

/// The lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEvent {
    /// The flow started (definition loaded, inputs bound).
    Started,
    /// A response-bearing step armed its handle: park.
    StepArmed,
    /// An armed step completed (its response arrived and verified):
    /// resume.
    StepCompleted,
    /// A step failed its check (a bind mismatch with
    /// `on_mismatch: fail`, a primitive refusal): the flow fails.
    StepFailed,
    /// The last step completed: the flow is done.
    FlowCompleted,
    /// The `end` step: early flow-stop (still `completed` — the flow
    /// did what its definition said, just sooner).
    Ended,
    /// Sweep: the flow expired (bounded lifetimes, §10).
    Expired,
    /// Classified error: the flow fails.
    ErrorOccurred,
}

/// One flow step's position state (§8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Pending,
    Armed,
    Done,
    Failed,
}

impl StepState {
    pub fn label(&self) -> &'static str {
        match self {
            StepState::Pending => "pending",
            StepState::Armed => "armed",
            StepState::Done => "done",
            StepState::Failed => "failed",
        }
    }
}

/// Where the instance is in its definition: the cursor plus the
/// per-step states, keyed by step id.
#[derive(Debug, Clone, Default)]
pub struct FlowPosition {
    pub cursor: usize,
    pub steps: BTreeMap<String, StepState>,
}

/// Compute the next lifecycle state. Illegal combinations are
/// refusals with the stable `illegal_transition` code — the host must
/// not "recover" them (the `session.rs` discipline).
pub fn transition(state: FlowState, event: FlowEvent) -> Result<FlowState> {
    use FlowEvent as Ev;
    use FlowState as St;

    let next = match (state, event) {
        (St::Created, Ev::Started) => St::Running,
        (St::Running, Ev::StepArmed) => St::Waiting,
        (St::Waiting, Ev::StepCompleted) => St::Running,
        (St::Running, Ev::FlowCompleted) | (St::Running, Ev::Ended) => St::Completed,
        (St::Waiting, Ev::Ended) => St::Completed,
        (St::Running | St::Waiting, Ev::StepFailed) => St::Failed,
        (St::Created | St::Running | St::Waiting, Ev::ErrorOccurred) => St::Failed,
        (St::Created | St::Running | St::Waiting, Ev::Expired) => St::Expired,
        // A completed flow may be inspected, but never moved: final is
        // final (retention/sweep owns the rest, §10).
        (state, event) => {
            return Err(crate::Error::illegal_transition(format!(
                "the flow lifecycle does not allow {} in {}",
                event_label(event),
                state.label()
            )))
        }
    };
    Ok(next)
}

fn event_label(event: FlowEvent) -> &'static str {
    match event {
        FlowEvent::Started => "started",
        FlowEvent::StepArmed => "step_armed",
        FlowEvent::StepCompleted => "step_completed",
        FlowEvent::StepFailed => "step_failed",
        FlowEvent::FlowCompleted => "flow_completed",
        FlowEvent::Ended => "ended",
        FlowEvent::Expired => "expired",
        FlowEvent::ErrorOccurred => "error_occurred",
    }
}

/// The engine's per-instance record skeleton: what the store persists
/// (the service's FlowStore owns the clear/sealed split, §5.5). The
/// definition rides by reference — the record carries the definition
/// id + digest, never the definition text (the engine resolves
/// definitions from its loaded, reviewed set).
#[derive(Debug, Clone)]
pub struct FlowInstance {
    /// The definition's name (`flow:`).
    pub flow: String,
    /// The definition's content digest (§5.4) — the identity the PDP
    /// evidence pins.
    pub definition_digest: String,
    pub state: FlowState,
    pub position: FlowPosition,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

impl FlowInstance {
    /// Start an instance over a loaded definition: Created → Running,
    /// every step Pending, the cursor at zero.
    pub fn start(definition: &FlowDefinition, now: i64, ttl_seconds: i64) -> Result<Self> {
        let mut steps = BTreeMap::new();
        for step in &definition.steps {
            if let Some(id) = step_id(step) {
                steps.insert(id.to_owned(), StepState::Pending);
            }
        }
        Ok(Self {
            flow: definition.flow.clone(),
            definition_digest: definition.digest(),
            state: transition(FlowState::Created, FlowEvent::Started)?,
            position: FlowPosition { cursor: 0, steps },
            created_at_unix: now,
            expires_at_unix: now + ttl_seconds,
        })
    }

    /// Apply a lifecycle event (the only way state moves).
    pub fn step(&mut self, event: FlowEvent) -> Result<()> {
        self.state = transition(self.state, event)?;
        Ok(())
    }
}

/// A step's id, if it has one (End does not).
pub fn step_id(step: &crate::language::Step) -> Option<&str> {
    match step {
        crate::language::Step::Presentation(p) => Some(&p.id),
        crate::language::Step::Bind(b) => Some(&b.id),
        crate::language::Step::Issuance(i) => Some(&i.id),
        crate::language::Step::Store(s) => Some(&s.id),
        crate::language::Step::Token(t) => Some(&t.id),
        crate::language::Step::Fetch(f) => Some(&f.id),
        crate::language::Step::End => None,
    }
}
