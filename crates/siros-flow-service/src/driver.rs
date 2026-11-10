//! The driver (design §4.1 "flow engine"): walks ANY loaded
//! definition's steps generically — the general service. Steps run in
//! definition order; a `when:` matcher skips its step unless the
//! recorded verdict satisfies it; a presentation step arms and parks
//! the instance `waiting`; a response resumes the walk; `bind` runs a
//! primitive; `issuance` drives the issuer backend; `store` writes a
//! declared key; `end` completes early. No flow is special-cased —
//! the EHIC flow and the parity flow are the same walk.

use serde_json::{json, Value};
use siros_flow_core::bind::BindRegistry;
use siros_flow_core::context::{FlowContext, PresentationResult, PresentedCredential};
use siros_flow_core::engine::{step_id, FlowEvent, FlowInstance, FlowState, StepState};
use siros_flow_core::language::{ContextRef, FlowDefinition, OnMismatch, Step};
use siros_flow_core::{Error, Result};

/// An issuer-core error crossing the service boundary (the vault's).
fn vault_error(error: siros_issuer_core::Error) -> Error {
    Error::configuration(format!("the vault: {error}"))
}

use crate::presentation::{arm_presentation, verify_presentation};
use crate::state::FlowServiceState;
use crate::store::{ArmedStep, FlowRecord, RecordedEvent};

/// What a walk parks on: a presentation awaiting its response.
#[derive(Debug)]
pub struct AwaitingPresentation {
    pub flow_instance: String,
    /// The signed request object (the JAR the wallet reads).
    pub jar: String,
    /// Where the wallet POSTs the `direct_post.jwt` response.
    pub response_uri: String,
    /// The request object served for the request-by-reference wallets
    /// (a real wallet fetches the JAR from a URL — only a custom
    /// driver consumes it by value).
    pub request_uri: String,
    /// The deep link a wallet opens: `openid4vp://?client_id=…&
    /// request_uri=…` (the OID4VP authorization request shape —
    /// §6.1: the carrier decides how the request reaches the
    /// wallet, and a deep link / QR carries a request_uri).
    pub deep_link: String,
    /// The carrier this step rides ("deeplink" | "dc_api") — the reply
    /// envelope carries it; a front-end branches on it (open a URI
    /// vs `credentials.get`), §7.
    pub carrier: &'static str,
}

/// The completed flow's issuance offers (deep links the wallet
/// redeems at the issuer).
pub async fn offers_of(state: &FlowServiceState, flow_instance: &str) -> Result<Vec<Value>> {
    let record =
        state.store.get(flow_instance).await?.ok_or_else(|| {
            Error::invalid_input(format!("no such flow instance {flow_instance:?}"))
        })?;
    let context: FlowContext = serde_json::from_value(
        state
            .vault
            .unseal(flow_instance, &record.sealed_context)
            .map_err(vault_error)?,
    )
    .map_err(|e| Error::configuration(format!("the sealed flow context: {e}")))?;
    Ok(context.issuance.values().cloned().collect())
}

/// Start a flow instance over a loaded definition: the caller's
/// inputs seal into the context, the walk runs from step zero.
pub async fn start_flow(
    state: &FlowServiceState,
    definition: &FlowDefinition,
    inputs: Value,
    ttl_seconds: i64,
) -> Result<AwaitingPresentation> {
    let now = crate::status::now_unix();
    let instance = FlowInstance::start(definition, now, ttl_seconds)?;
    let flow_instance = format!(
        "{}_{}",
        definition.flow,
        crate::presentation::random_handle(16)
    );

    let mut context = FlowContext::default();
    if let Value::Object(map) = inputs {
        for (key, value) in map {
            context.inputs.insert(key, value);
        }
    }
    let sealed = seal(state, &flow_instance, &context)?;
    state
        .store
        .insert(FlowRecord::new(flow_instance.clone(), instance, sealed))
        .await?;

    // Bind steps may run before the first presentation (a `when:`-free
    // bind on inputs); the walk handles them. A definition whose first
    // response-bearing step is a presentation parks there.
    match walk(state, definition, &flow_instance).await? {
        WalkOutcome::Parked(awaiting) => Ok(awaiting),
        WalkOutcome::Completed { .. } => {
            // No response-bearing step: the flow already completed
            // (still answer the park shape — the caller reads the
            // offers; v1 deployments start presentation-first flows).
            Err(Error::configuration(
                "the definition has no presentation step to park on — v1 flows start with a presentation",
            ))
        }
    }
}

pub enum WalkOutcome {
    Parked(AwaitingPresentation),
    Completed { flow_instance: String },
}

/// Resume the walk after a presentation response: verify, trust
/// (fail-closed), adopt, continue. The arm was claimed single-use by
/// the HTTP layer; the sealed step state rides the claim snapshot.
pub async fn resume_flow(
    state: &FlowServiceState,
    definition: &FlowDefinition,
    claimed: &FlowRecord,
    response: crate::presentation::PresentationResponse,
) -> Result<WalkOutcome> {
    // The store key + the vault's AAD: the INSTANCE id (the definition
    // name rides instance.flow).
    let flow_instance = claimed.instance_id.clone();
    let armed = claimed
        .armed
        .clone()
        .ok_or_else(|| Error::illegal_transition("the step's arm is already claimed"))?;

    let mut context: FlowContext = serde_json::from_value(
        state
            .vault
            .unseal(&flow_instance, &claimed.sealed_context)
            .map_err(vault_error)?,
    )
    .map_err(|e| Error::configuration(format!("the sealed flow context: {e}")))?;

    let presentation_step = definition
        .steps
        .iter()
        .find_map(|step| match step {
            Step::Presentation(p) if p.id == armed.step_id => Some(p),
            _ => None,
        })
        .ok_or_else(|| {
            Error::configuration(format!(
                "the armed step {:?} is not in the definition",
                armed.step_id
            ))
        })?;

    // Verify (verifier-core) → TRUST (the PDP, fail-closed, per
    // credential) → adopt. A credential the PDP refuses is never
    // adopted (§9).
    let verified = verify_presentation(state, &flow_instance, &armed.sealed_step, &response)?;
    let mut result = PresentationResult::default();
    for (query_id, outcome) in verified {
        if let Err(e) = state.pdp.permit_presentation(&outcome.trust_query).await {
            fail(state, &flow_instance, claimed.version).await;
            return Err(Error::new(
                siros_flow_core::error::code::PDP_DENIED,
                format!("the presented credential {query_id:?} is not trusted: {e}"),
            ));
        }
        result.credentials.insert(
            query_id,
            PresentedCredential {
                format: outcome.format,
                claims: outcome.claims,
                holder_key: outcome.holder_key,
            },
        );
    }
    for required in &presentation_step.require {
        if !result.credentials.contains_key(required) {
            fail(state, &flow_instance, claimed.version).await;
            return Err(Error::new(
                siros_flow_core::error::code::INVALID_INPUT,
                format!("the required credential {required:?} was not presented"),
            ));
        }
    }
    context.presentations.insert(armed.step_id.clone(), result);

    // The step completed; the walk resumes. NOTE: the arm already
    // advanced the cursor past this step when it parked — no second
    // increment (the definition's next step runs next).
    let mut instance = claimed.instance.clone();
    instance.state = FlowState::Running;
    position_step(&mut instance, &armed.step_id, StepState::Done);
    let sealed = seal(state, &flow_instance, &context)?;
    state
        .store
        .update(
            &flow_instance,
            claimed.version,
            instance,
            None,
            sealed,
            claimed.events.clone(),
        )
        .await?;

    walk(state, definition, &flow_instance).await
}

/// The walk: run steps in definition order from the cursor until a
/// presentation arms (park) or the definition ends (complete). A
/// The signed request object's own `client_id` (the x509_hash
/// scheme id a deep link carries — the same one the wallet parses
/// from the fetched request).
fn jar_client_id(jar: &str) -> Result<String> {
    let payload = jar
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::configuration("the request object is not a compact JWT"))?;
    let claims: serde_json::Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(payload)
            .map_err(|e| Error::configuration(format!("the request object: {e}")))?,
    )
    .map_err(|e| Error::configuration(format!("the request object: {e}")))?;
    claims["client_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::configuration("the request object has no client_id"))
}

/// failing bind (on_mismatch: fail, the default) persists the Failed
/// state before surfacing the refusal.
async fn walk(
    state: &FlowServiceState,
    definition: &FlowDefinition,
    flow_instance: &str,
) -> Result<WalkOutcome> {
    let mut record =
        state.store.get(flow_instance).await?.ok_or_else(|| {
            Error::invalid_input(format!("no such flow instance {flow_instance:?}"))
        })?;
    let mut context: FlowContext = serde_json::from_value(
        state
            .vault
            .unseal(flow_instance, &record.sealed_context)
            .map_err(vault_error)?,
    )
    .map_err(|e| Error::configuration(format!("the sealed flow context: {e}")))?;

    while record.instance.position.cursor < definition.steps.len() {
        let step = &definition.steps[record.instance.position.cursor];
        match step {
            Step::Presentation(presentation) => {
                let armed = arm_presentation(state, flow_instance, presentation)?;
                let mut instance = record.instance.clone();
                instance.state = FlowState::Waiting;
                instance.position.cursor += 1;
                position_step(&mut instance, &presentation.id, StepState::Armed);
                let sealed = seal(state, flow_instance, &context)?;
                state
                    .store
                    .update(
                        flow_instance,
                        record.version,
                        instance,
                        Some(ArmedStep {
                            handle: armed.handle.clone(),
                            step_id: presentation.id.clone(),
                            sealed_step: armed.sealed_session,
                            jar: armed.jar.clone(),
                        }),
                        sealed,
                        record.events.clone(),
                    )
                    .await?;
                // The wallet-facing URL shapes: the request object is
                // served at request-object/{handle} (request-by-
                // reference), and the deep link carries client_id +
                // request_uri (the OID4VP authorization request a
                // wallet opens — the client_id is the request
                // object's own, the x509_hash scheme).
                let request_uri = state
                    .public_url
                    .join(&format!("request-object/{}", armed.handle))
                    .map_err(|e| Error::configuration(format!("public_url: {e}")))?
                    .to_string();
                let client_id = jar_client_id(&armed.jar)?;
                let deep_link = format!(
                    "openid4vp://?client_id={}&request_uri={}",
                    urlencoding::encode(&client_id),
                    urlencoding::encode(&request_uri),
                );
                return Ok(WalkOutcome::Parked(AwaitingPresentation {
                    flow_instance: flow_instance.to_owned(),
                    jar: armed.jar,
                    response_uri: armed.response_uri.as_str().to_owned(),
                    request_uri,
                    deep_link,
                    carrier: armed.carrier,
                }));
            }
            Step::Bind(bind) => {
                // The `when:` matcher: run only when the recorded
                // verdict satisfies it — branching is visible (§5.4).
                if let Some(when) = &bind.when {
                    let satisfied = context
                        .verdicts
                        .get(&when.step)
                        .is_some_and(|verdict| verdict.matched == when.matched);
                    if !satisfied {
                        record =
                            advance(state, record, definition, flow_instance, &mut context).await?;
                        continue;
                    }
                }
                let primitive = state.bind_registry.resolve(&bind.primitive)?;
                primitive.validate_params(&bind.params)?;
                let outcome = primitive.bind(&context, &bind.params)?;
                context.verdicts.insert(
                    bind.id.clone(),
                    siros_flow_core::context::BindVerdict {
                        matched: outcome.matched,
                        primitive: bind.primitive.clone(),
                        params: bind.params.clone(),
                    },
                );
                if !outcome.matched && bind.on_mismatch == OnMismatch::Fail {
                    let message = outcome
                        .mismatch
                        .unwrap_or_else(|| "the bind check failed".to_owned());
                    fail(state, flow_instance, record.version).await;
                    return Err(Error::bind_mismatch(message));
                }
                record = advance(state, record, definition, flow_instance, &mut context).await?;
            }
            Step::Issuance(issuance) => {
                let subject = derive_subject(&context, &issuance.subject)?;
                let outcome = state
                    .issuer
                    .create_session(&issuance.credential, &subject, 300)
                    .await?;
                context.issuance.insert(
                    issuance.id.clone(),
                    json!({
                        "credential": issuance.credential,
                        "offer_uri": outcome.offer_uri,
                        "deep_link": outcome.deep_link,
                        "session_id": outcome.session_id,
                    }),
                );
                record = advance(state, record, definition, flow_instance, &mut context).await?;
            }
            Step::Store(store_step) => {
                let value = match &store_step.value {
                    Value::Object(map) if map.len() == 1 && map.contains_key("from") => {
                        let reference: ContextRef = serde_json::from_value(map["from"].clone())
                            .map_err(|e| {
                                Error::language_invalid(format!("store: the from reference: {e}"))
                            })?;
                        context.resolve(&reference)?
                    }
                    literal => literal.clone(),
                };
                // The value lands under the STEP ID (§5.5's one
                // addressing discipline — later steps reference it as
                // {step: <id>, path: [...]}).
                context.derived.insert(store_step.id.clone(), value);
                record = advance(state, record, definition, flow_instance, &mut context).await?;
            }
            Step::Token(token_step) => {
                // The plugin is the reviewed code (§6.7): the flow
                // references it by name, the registry resolves it
                // (allowlisted at load, fail-closed again here).
                let plugin = state.token_registry.resolve(&token_step.plugin)?;
                plugin.validate_params(&token_step.params)?;
                // The verified claims land in the context's derived
                // values under the step id (§5.5).
                let claims = plugin.verify(&context, &token_step.params).await?;
                context.derived.insert(token_step.id.clone(), claims);
                record = advance(state, record, definition, flow_instance, &mut context).await?;
            }
            Step::Fetch(fetch_step) => {
                let plugin = state.fetch_registry.resolve(&fetch_step.plugin)?;
                // Exactly the step's DECLARED inputs are resolved and
                // sent (surface-checked at load, §6.5: nothing else
                // leaves the context).
                let mut inputs = std::collections::BTreeMap::new();
                for (name, reference) in &fetch_step.inputs {
                    inputs.insert(name.clone(), context.resolve(reference)?);
                }
                // Fail-closed: a failed fetch fails the step (§6.5).
                let value = plugin.fetch(inputs).await?;
                context.derived.insert(fetch_step.id.clone(), value);
                record = advance(state, record, definition, flow_instance, &mut context).await?;
            }
            Step::Notify(notify_step) => {
                // §6.6: the typed event, recorded to the CLEAR part of
                // the flow's record — kinds and definition-authored
                // text, never context values (§10.1/§10.2). The SSE
                // surface (the embedding frontend's audience) streams
                // these; the WMP carrier (P-bw4) delivers them to
                // instances.
                record.events.push(RecordedEvent {
                    event: notify_step.event.clone(),
                    message: notify_step.message.clone(),
                    step_id: notify_step.id.clone(),
                    at_unix: crate::status::now_unix(),
                });
                record = advance(state, record, definition, flow_instance, &mut context).await?;
            }
            Step::End => {
                let mut instance = record.instance.clone();
                instance.step(FlowEvent::Ended)?;
                let sealed = seal(state, flow_instance, &context)?;
                state
                    .store
                    .update(
                        flow_instance,
                        record.version,
                        instance,
                        None,
                        sealed,
                        record.events.clone(),
                    )
                    .await?;
                return Ok(WalkOutcome::Completed {
                    flow_instance: flow_instance.to_owned(),
                });
            }
        }
    }
    let mut instance = record.instance.clone();
    instance.step(FlowEvent::FlowCompleted)?;
    let sealed = seal(state, flow_instance, &context)?;
    state
        .store
        .update(
            flow_instance,
            record.version,
            instance,
            None,
            sealed,
            record.events.clone(),
        )
        .await?;
    Ok(WalkOutcome::Completed {
        flow_instance: flow_instance.to_owned(),
    })
}

/// Advance the cursor past the current step and persist (CAS: the
/// walk never moves a record it did not just read).
async fn advance(
    state: &FlowServiceState,
    mut record: FlowRecord,
    definition: &FlowDefinition,
    flow_instance: &str,
    context: &mut FlowContext,
) -> Result<FlowRecord> {
    let step = &definition.steps[record.instance.position.cursor];
    if let Some(id) = step_id(step) {
        position_step(&mut record.instance, id, StepState::Done);
    }
    record.instance.position.cursor += 1;
    record.instance.state = FlowState::Running;
    let sealed = seal(state, flow_instance, context)?;
    let updated = state
        .store
        .update(
            flow_instance,
            record.version,
            record.instance.clone(),
            record.armed.clone(),
            sealed,
            record.events.clone(),
        )
        .await?;
    Ok(updated)
}

fn position_step(instance: &mut FlowInstance, id: &str, step_state: StepState) {
    instance.position.steps.insert(id.to_owned(), step_state);
}

fn seal(state: &FlowServiceState, flow_instance: &str, context: &FlowContext) -> Result<Vec<u8>> {
    state
        .vault
        .seal(
            flow_instance,
            &serde_json::to_value(context).expect("the context serializes"),
        )
        .map_err(vault_error)
}

/// The declarative subject derivation (§6.3): the `from` reference's
/// claims, merged with the `merge` map's resolved values. No
/// computation, no plugins; an unresolvable ref is a refusal.
fn derive_subject(
    context: &FlowContext,
    derivation: &siros_flow_core::language::SubjectDerivation,
) -> Result<Value> {
    let mut base = context.resolve(&derivation.from)?;
    let Some(object) = base.as_object_mut() else {
        return Err(Error::invalid_input(
            "the subject's from reference does not resolve to a claims object",
        ));
    };
    for (key, reference) in &derivation.merge {
        object.insert(key.clone(), context.resolve(reference)?);
    }
    Ok(base)
}

/// Fail the flow instance (best-effort persist: the refusal is the
/// answer either way — fail-closed beats perfect bookkeeping).
async fn fail(state: &FlowServiceState, flow_instance: &str, version: u64) {
    let Ok(Some(record)) = state.store.get(flow_instance).await else {
        return;
    };
    let mut instance = record.instance.clone();
    if instance.state.is_final() {
        return;
    }
    if instance.step(FlowEvent::StepFailed).is_err() {
        let _ = instance.step(FlowEvent::ErrorOccurred);
    }
    let _ = state
        .store
        .update(
            flow_instance,
            version,
            instance,
            None,
            Vec::new(),
            Vec::new(),
        )
        .await;
}

/// The registry the driver resolves `primitive:` names against (the
/// standard set; a deployment adds its own on the same trait).
pub fn standard_registry() -> BindRegistry {
    BindRegistry::standard()
}
