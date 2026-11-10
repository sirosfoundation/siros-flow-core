//! The flow service's HTTP surface (general: any loaded flow).
//!
//! - `POST /flows/{flow}/start` — start an instance of the named
//!   flow with the caller's inputs (the body is the inputs object);
//!   the reply is the armed presentation (request object +
//!   response_uri) — the QR / deep-link carrier.
//! - `POST /flow-response/{handle}` — the OID4VP `response_uri` (the
//!   wallet POSTs the `direct_post.jwt` JWE as the `response` form
//!   value); the reply carries the issuance offers (credential offer
//!   deep links) when the walk completes, or the next presentation.
//! - `GET /flows/{instance}` — the instance's status (state,
//!   position — never context values).
//! - `GET /healthz` — readiness: the loaded flow set + the issuer.
//!
//! Errors are the family shape: `{error, error_description}` with
//! stable codes; refusals name paths and steps, never values.

// The axum Response is a large Err-variant; the family's allow.
#![allow(clippy::result_large_err)]

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use siros_flow_core::Error;
use std::sync::Arc;

use crate::driver::{self, offers_of, WalkOutcome};
use crate::state::FlowServiceState;

pub type HandlerResult<T> = std::result::Result<T, Response>;

fn err(error: Error) -> Response {
    let status = match error.code {
        "illegal_transition" | "bind_mismatch" => StatusCode::BAD_REQUEST,
        "pdp_denied" | "pdp_unavailable" => StatusCode::FORBIDDEN,
        "configuration" => StatusCode::INTERNAL_SERVER_ERROR,
        "transport" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(json!({
            "error": error.code,
            "error_description": error.message,
        })),
    )
        .into_response()
}

/// The flow routes WITHOUT `/healthz` — for the embedded-issuer
/// merge, where the issuer's own `/healthz` serves the composite
/// origin (one app, one health).
pub fn routes(state: Arc<FlowServiceState>) -> axum::Router {
    axum::Router::new()
        .route("/flows/{flow}/start", axum::routing::post(start))
        .route(
            "/flow-response/{handle}",
            axum::routing::post(flow_response),
        )
        .route("/flows/{instance}", axum::routing::get(instance_status))
        .with_state(state)
}

/// The standalone surface: the flow routes + `/healthz`.
pub fn router(state: Arc<FlowServiceState>) -> axum::Router {
    axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/flows/{flow}/start", axum::routing::post(start))
        .route(
            "/flow-response/{handle}",
            axum::routing::post(flow_response),
        )
        .route("/flows/{instance}", axum::routing::get(instance_status))
        .with_state(state)
}

/// Readiness: the loaded flow set + the issuer backend.
async fn healthz(State(state): State<Arc<FlowServiceState>>) -> Response {
    let flows: Vec<&str> = state.definitions.keys().map(String::as_str).collect();
    let issuer = state.issuer.reachable().await;
    Json(json!({
        "status": "ok",
        "definitions_dir": state.definitions_dir,
        "flows": flows,
        "issuer_reachable": issuer,
    }))
    .into_response()
}

/// `POST /flows/{flow}/start` — body: the flow's inputs object.
async fn start(
    State(state): State<Arc<FlowServiceState>>,
    Path(flow): Path<String>,
    Json(inputs): Json<Value>,
) -> HandlerResult<Json<Value>> {
    let definition = state
        .definitions
        .get(&flow)
        .ok_or_else(|| {
            err(Error::invalid_input(format!(
                "no flow {flow:?} is loaded (healthz lists the set)"
            )))
        })?
        .clone();
    if !inputs.is_object() {
        return Err(err(Error::invalid_input(
            "the flow start body is the inputs object",
        )));
    }
    let awaiting = driver::start_flow(&state, &definition, inputs, 600)
        .await
        .map_err(err)?;
    Ok(Json(json!({
        "flow": flow,
        "instance": awaiting.flow_instance,
        "authorization_request": awaiting.jar,
        "response_uri": awaiting.response_uri,
        // The carrier this step rides (§7): "deeplink" → open a URI /
        // QR; "dc_api" → hand the request object to
        // navigator.credentials.get and POST the returned `data` to
        // the response_uri.
        "carrier": awaiting.carrier,
    })))
}

/// `POST /flow-response/{handle}` — the OID4VP response_uri. The
/// wallet POSTs `response=<direct_post.jwt JWE>` (form-encoded).
async fn flow_response(
    State(state): State<Arc<FlowServiceState>>,
    Path(handle): Path<String>,
    body: String,
) -> HandlerResult<Json<Value>> {
    // One value out of an application/x-www-form-urlencoded body (the
    // OID4VP direct_post.jwt shape — the same parse Mode B performs).
    let jwe = form_value(&body, "response")
        .ok_or_else(|| err(Error::invalid_input("response is required")))?;
    // Claim the arm single-use FIRST (peek-then-take would race).
    let record = state
        .store
        .take_by_handle(&handle)
        .await
        .map_err(err)?
        .ok_or_else(|| err(Error::invalid_input("no pending flow step for this handle")))?;
    let flow_name = record
        .instance
        .flow
        .split('_')
        .next()
        .unwrap_or_default()
        .to_owned();
    let definition = state
        .definitions
        .get(&flow_name)
        .ok_or_else(|| {
            err(Error::configuration(format!(
                "the instance's flow {flow_name:?} is no longer loaded"
            )))
        })?
        .clone();
    match driver::resume_flow(&state, &definition, &record, &jwe)
        .await
        .map_err(err)?
    {
        WalkOutcome::Parked(awaiting) => Ok(Json(json!({
            "instance": awaiting.flow_instance,
            "next": "presentation",
            "authorization_request": awaiting.jar,
            "response_uri": awaiting.response_uri,
            "carrier": awaiting.carrier,
        }))),
        WalkOutcome::Completed { flow_instance, .. } => {
            let offers = offers_of(&state, &flow_instance).await.map_err(err)?;
            Ok(Json(json!({
                "instance": flow_instance,
                "next": "complete",
                "credential_offers": offers,
                // The primary offer's deep link, for the same-device
                // wallet handoff (the issuance the walk produced).
                "wallet_redirect": offers
                    .first()
                    .and_then(|offer| offer["deep_link"].as_str())
                    .unwrap_or_default(),
            })))
        }
    }
}

/// The instance status: lifecycle + position — the clear split only
/// (never context values, §10).
async fn instance_status(
    State(state): State<Arc<FlowServiceState>>,
    Path(instance): Path<String>,
) -> HandlerResult<Json<Value>> {
    let record = state
        .store
        .get(&instance)
        .await
        .map_err(err)?
        .ok_or_else(|| {
            err(Error::invalid_input(format!(
                "no such flow instance {instance:?}"
            )))
        })?;
    let steps: Vec<Value> = record
        .instance
        .position
        .steps
        .iter()
        .map(|(id, step_state)| json!({ "id": id, "state": step_state.label() }))
        .collect();
    Ok(Json(json!({
        "instance": instance,
        "flow": record.instance.flow,
        "state": record.instance.state.label(),
        "definition_digest": record.instance.definition_digest,
        "cursor": record.instance.position.cursor,
        "steps": steps,
        "created_at_unix": record.instance.created_at_unix,
        "expires_at_unix": record.instance.expires_at_unix,
    })))
}

fn form_value(body: &str, name: &str) -> Option<String> {
    for (key, value) in form_urlencoded::parse(body.as_bytes()) {
        if key == name {
            return Some(value.into_owned());
        }
    }
    None
}
