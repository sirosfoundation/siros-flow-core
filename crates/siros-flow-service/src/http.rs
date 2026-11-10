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
/// The flow routes (the ONE route table — the embedded-merge surface
/// and the standalone surface must not diverge; the gdc deployment
/// runs the merged one, and a route added to only one constructor is
/// a route the deployment 404s).
pub fn routes(state: Arc<FlowServiceState>) -> axum::Router {
    axum::Router::new()
        .route("/flows/{flow}/start", axum::routing::post(start))
        .route(
            "/flow-response/{handle}",
            axum::routing::post(flow_response),
        )
        // The armed request object, served for the request-by-reference
        // wallets (§6.1: a deep link / QR carries a request_uri; a
        // real wallet fetches the JAR from it — only a custom driver
        // consumes the request by value).
        .route(
            "/request-object/{handle}",
            axum::routing::get(request_object),
        )
        .route("/flows/{instance}", axum::routing::get(instance_status))
        // §6.6's delivery for the embedding frontend: a typed SSE
        // stream of the recorded notification events (the WMP
        // carrier at P-bw4 is the instance audience's delivery).
        .route(
            "/flows/{instance}/events",
            axum::routing::get(instance_events),
        )
        .with_state(state)
        // The wallet-facing routes are cross-origin by design: the
        // wallet frontend fetches the request object and POSTs the
        // response from ITS origin to this service (the same CORS
        // discipline vc's verifier serves). Preflight answered for
        // insurance (the wallet's client sends simple requests today,
        // a future header must not silently break the fetch).
        .layer(axum::middleware::from_fn(wallet_cors))
}

/// The standalone surface: the flow routes + `/healthz` (the
/// embedded-merge case serves its own composite `/healthz`).
pub fn router(state: Arc<FlowServiceState>) -> axum::Router {
    routes(state.clone()).route("/healthz", axum::routing::get(healthz).with_state(state))
}

/// CORS for the two wallet-facing routes (request-object GET,
/// flow-response POST) + the OPTIONS preflight; every other route
/// passes through untouched.
async fn wallet_cors(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_wallet_facing = request.uri().path().starts_with("/request-object/")
        || request.uri().path().starts_with("/flow-response/");
    if !is_wallet_facing {
        return next.run(request).await;
    }
    if request.method() == axum::http::Method::OPTIONS {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::NO_CONTENT)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "GET, POST, OPTIONS")
            .header(
                "access-control-allow-headers",
                "Content-Type, Accept, Authorization",
            )
            .body(axum::body::Body::empty())
            .unwrap();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("access-control-allow-origin", "*".parse().unwrap());
    response
}

/// `GET /request-object/{handle}` — the armed step's public request
/// object (peek, not claim: a wallet may fetch it repeatedly; the
/// single-use claim is the response POST's `take_by_handle`).
async fn request_object(
    State(state): State<Arc<FlowServiceState>>,
    Path(handle): Path<String>,
) -> axum::response::Response {
    let Ok(Some(jar)) = state.store.peek_request_object(&handle).await else {
        return err(Error::invalid_input(
            "no pending request object for this handle",
        ))
        .into_response();
    };
    let mut response = (
        [
            ("content-type", "application/oauth-authz-req+jwt"),
            ("cache-control", "no-store"),
        ],
        jar,
    )
        .into_response();
    response
        .headers_mut()
        .insert("access-control-allow-origin", "*".parse().unwrap());
    response
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
        // The request-by-reference shapes a real wallet consumes: the
        // JAR served at request_uri, and the deep link
        // (openid4vp://?client_id=…&request_uri=…) a QR / link
        // carries (§6.1).
        "request_uri": awaiting.request_uri,
        "deep_link": awaiting.deep_link,
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
            "request_uri": awaiting.request_uri,
            "deep_link": awaiting.deep_link,
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
/// `GET /flows/{instance}/events` — the typed SSE stream of the
/// recorded notification events (§6.6): the embedding frontend's
/// audience. Streams the recorded events from `Last-Event-ID` (the
/// event index) onward, polls the store until the instance reaches a
/// final state, then closes. The instance id is the capability (the
/// same discipline as the status read).
async fn instance_events(
    State(state): State<Arc<FlowServiceState>>,
    Path(instance): Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // Resume support (SSE's Last-Event-ID = the last delivered index).
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .map(|v| v + 1)
        .unwrap_or(0);

    // The stream: poll the store, emit events past the cursor, close
    // on a final state. Built over ANY FlowStore (the trait unchanged
    // — the poll lives in the handler, not the store).
    let state_for_stream = state.clone();
    let stream = futures_util::stream::unfold(
        (state_for_stream, instance, last_event_id),
        |(state, instance, mut cursor)| async move {
            loop {
                let Ok(Some(record)) = state.store.get(&instance).await else {
                    // Gone (expired + swept): the stream ends.
                    return None;
                };
                if record.events.len() > cursor {
                    let event = &record.events[cursor];
                    let frame = format!(
                        "event: {}\nid: {}\ndata: {}\n\n",
                        event.event,
                        cursor,
                        serde_json::json!({
                            "event": event.event,
                            "message": event.message,
                            "step": event.step_id,
                            "at_unix": event.at_unix,
                        })
                    );
                    cursor += 1;
                    let bytes = axum::body::Bytes::from(frame);
                    return Some((
                        Ok::<_, std::convert::Infallible>(bytes),
                        (state, instance, cursor),
                    ));
                }
                if record.instance.state.is_final() {
                    // Final state + every event delivered: close.
                    return None;
                }
                // Wait for the next poll tick.
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
        },
    );

    let mut response = axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-store")
        .body(axum::body::Body::from_stream(stream))
        .expect("the SSE response builds");
    response
        .headers_mut()
        .insert("access-control-allow-origin", "*".parse().unwrap());
    response
}

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
    // §6.6: the recorded notification events — kinds and
    // definition-authored text, never values (§10.1/§10.2).
    let events: Vec<Value> = record
        .events
        .iter()
        .map(|event| {
            json!({
                "event": event.event,
                "message": event.message,
                "step": event.step_id,
                "at_unix": event.at_unix,
            })
        })
        .collect();
    Ok(Json(json!({
        "instance": instance,
        "flow": record.instance.flow,
        "state": record.instance.state.label(),
        "definition_digest": record.instance.definition_digest,
        "cursor": record.instance.position.cursor,
        "steps": steps,
        "events": events,
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
