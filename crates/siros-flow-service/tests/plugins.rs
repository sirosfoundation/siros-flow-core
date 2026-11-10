//! The plugin surface (§6.7): the allowlist discipline and the two
//! reference plugins' behavior — the P-bw3 exit criteria.
//!
//! - "a flow definition referencing a plugin not in the allowlist is
//!   a startup refusal" — the load check, tested directly;
//! - "the step declares its inputs … checkable at load" (§6.5) — the
//!   fetch input-surface audit, tested directly;
//! - the reference token plugin performs the `verify_bearer_assertion`
//!   checks (issuer-core service/src/auth.rs — the RFC 7523
//!   discipline, generalized): signature, `iss`, `aud`, freshness
//!   windows — each refusal tested;
//! - the reference fetch provider is bounded and fail-closed.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use siros_flow_core::context::FlowContext;
use siros_flow_service::config::{FetchPluginCfg, TokenPluginCfg};
use siros_flow_service::plugins::{
    validate_definition, FetchPlugin, FetchRegistry, HttpJsonPlugin, IdTokenPlugin, TokenPlugin,
    TokenRegistry,
};

fn now() -> i64 {
    siros_issuer_service::status::now_unix()
}

fn sign_jwt(key: &jose_rs::jwk::Jwk, claims: &Value) -> String {
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.kid = key.kid.clone();
    let payload = serde_json::to_vec(claims).unwrap();
    jose_rs::jws::compact::sign_with_jwk(key, &payload, &header).expect("jwt signs")
}

/// A token-plugin config pointing at the given public JWK file.
fn idp_config(key_path: &str) -> TokenPluginCfg {
    TokenPluginCfg {
        name: "test-idp".to_owned(),
        key_path: Some(key_path.to_owned()),
        jwks_uri: None,
        issuer: "https://idp.example.org".to_owned(),
        audience: "https://flow.example.org".to_owned(),
        leeway_seconds: 60,
    }
}

fn write_public_jwk(key: &jose_rs::jwk::Jwk) -> String {
    // Unique per call: the tests run concurrently in one process and a
    // shared name races (one truncates while another reads).
    static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "idp-public-{}-{}.jwk",
        std::process::id(),
        WRITES.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::write(&path, serde_json::to_string(&key.to_public_jwk()).unwrap()).unwrap();
    path.display().to_string()
}

/// A minimal definition (the loader's own front door), one step of
/// the asked kind.
fn definition_with(step_yaml: &str) -> siros_flow_core::language::FlowDefinition {
    siros_flow_core::language::FlowDefinition::from_yaml(&format!(
        "flow: plugin-check\nlanguage_version: 1\nsteps:\n{step_yaml}"
    ))
    .unwrap()
}

fn idp_key() -> jose_rs::jwk::Jwk {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
    jwk.alg = Some("ES256".to_owned());
    jwk
}

// ─── The allowlist discipline (§6.7, at load) ──────────────────────────────

#[test]
fn a_definition_referencing_an_unallowlisted_plugin_refuses_at_load() {
    let (tokens, fetches) = (TokenRegistry::new(), FetchRegistry::new());
    let definition = definition_with(
        "  - token:\n      id: t\n      plugin: not-configured\n      params: {}\n",
    );
    let error = validate_definition(&definition, &tokens, &fetches).unwrap_err();
    assert_eq!(error.code, "plugin_unknown");
    assert!(
        error.message.contains("not-configured"),
        "the refusal names the plugin: {error}"
    );

    let definition = definition_with("  - fetch:\n      id: f\n      plugin: not-configured\n");
    let error = validate_definition(&definition, &tokens, &fetches).unwrap_err();
    assert_eq!(error.code, "plugin_unknown");
}

#[test]
fn a_fetch_step_declaring_outside_the_providers_surface_refuses_at_load() {
    // §6.5's PII-flow audit: the provider's input surface is CONFIG
    // (what the reviewed provider may receive), and a definition
    // routing anything else to it refuses at load — never silently
    // sends.
    let fetches = FetchRegistry::new().with(Box::new(StubFetch {
        name: "hr-api".to_owned(),
        surface: vec!["family_name".to_owned()],
    }));
    let bad = definition_with(
        "  - fetch:\n      id: f\n      plugin: hr-api\n      inputs:\n        national_id: {input: secret, path: []}\n",
    );
    let error = validate_definition(&bad, &TokenRegistry::new(), &fetches).unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    assert!(
        error.message.contains("national_id")
            && error.message.contains("surface")
            && error.message.contains("hr-api"),
        "the refusal names the input, the provider and the surface: {error}"
    );

    // Inside the surface: passes.
    let good = definition_with(
        "  - fetch:\n      id: f\n      plugin: hr-api\n      inputs:\n        family_name: {input: name, path: []}\n",
    );
    validate_definition(&good, &TokenRegistry::new(), &fetches).unwrap();
}

// ─── The reference token plugin (the verify_bearer_assertion discipline) ──

#[tokio::test]
async fn the_reference_token_plugin_verifies_signature_iss_aud_and_freshness() {
    let key = idp_key();
    let plugin = IdTokenPlugin::from_config(&idp_config(&write_public_jwk(&key))).unwrap();
    let mut context = FlowContext::default();

    let claims = json!({
        "iss": "https://idp.example.org",
        "aud": "https://flow.example.org",
        "sub": "user-42",
        "iat": now() - 10,
        "exp": now() + 300,
        "given_name": "Anna",
        "employee_id": "emp-7",
        "department": "Signet",
    });
    context
        .inputs
        .insert("idp_assertion".to_owned(), json!(sign_jwt(&key, &claims)));
    let params = json!({ "token": { "input": "idp_assertion", "path": [] } });
    plugin.validate_params(&params).unwrap();
    let verified = plugin.verify(&context, &params).await.unwrap();
    assert_eq!(verified["given_name"], "Anna");
    assert_eq!(verified["employee_id"], "emp-7");

    // `aud` may be an array (an ID token legitimately lists audiences).
    let claims = json!({
        "iss": "https://idp.example.org",
        "aud": ["https://other.example.org", "https://flow.example.org"],
        "iat": now() - 10,
        "exp": now() + 300,
    });
    context
        .inputs
        .insert("idp_assertion".to_owned(), json!(sign_jwt(&key, &claims)));
    assert!(plugin.verify(&context, &params).await.unwrap()["aud"].is_array());
}

/// Sign the claims with the given key and verify them — the error out.
async fn try_verify(
    plugin: &IdTokenPlugin,
    params: &serde_json::Value,
    claims: Value,
    key: &jose_rs::jwk::Jwk,
) -> siros_flow_core::Error {
    let mut context = FlowContext::default();
    context
        .inputs
        .insert("idp_assertion".to_owned(), json!(sign_jwt(key, &claims)));
    plugin.verify(&context, params).await.unwrap_err()
}

#[tokio::test]
async fn the_reference_token_plugin_refuses_every_discipline_violation() {
    let key = idp_key();
    let plugin = IdTokenPlugin::from_config(&idp_config(&write_public_jwk(&key))).unwrap();
    let params = json!({ "token": { "input": "idp_assertion", "path": [] } });

    // The wrong signer: the signature must not verify.
    let other_key = idp_key();
    let error = try_verify(
        &plugin,
        &params,
        json!({"iss": "https://idp.example.org", "aud": "https://flow.example.org",
               "iat": now() - 10, "exp": now() + 300}),
        &other_key,
    )
    .await;
    assert!(
        error.message.to_lowercase().contains("signature")
            || error.message.to_lowercase().contains("verify"),
        "the wrong signer: {error}"
    );

    // The wrong iss / aud.
    let error = try_verify(
        &plugin,
        &params,
        json!({"iss": "https://someone-else.example.org", "aud": "https://flow.example.org",
               "iat": now() - 10, "exp": now() + 300}),
        &key,
    )
    .await;
    assert!(error.message.contains("iss"), "{error}");
    let error = try_verify(
        &plugin,
        &params,
        json!({"iss": "https://idp.example.org", "aud": "https://not-us.example.org",
               "iat": now() - 10, "exp": now() + 300}),
        &key,
    )
    .await;
    assert!(error.message.contains("aud"), "{error}");

    // Freshness: expired, in the future, missing exp.
    let error = try_verify(
        &plugin,
        &params,
        json!({"iss": "https://idp.example.org", "aud": "https://flow.example.org",
               "iat": now() - 10_000, "exp": now() - 5_000}),
        &key,
    )
    .await;
    assert!(error.message.contains("expired"), "{error}");
    let error = try_verify(
        &plugin,
        &params,
        json!({"iss": "https://idp.example.org", "aud": "https://flow.example.org",
               "iat": now() + 10_000, "exp": now() + 20_000}),
        &key,
    )
    .await;
    assert!(error.message.contains("future"), "{error}");
    let error = try_verify(
        &plugin,
        &params,
        json!({"iss": "https://idp.example.org", "aud": "https://flow.example.org",
               "iat": now() - 10}),
        &key,
    )
    .await;
    assert!(error.message.contains("exp"), "{error}");

    // Not a compact JWT at all.
    let mut context = FlowContext::default();
    context
        .inputs
        .insert("idp_assertion".to_owned(), json!("not-a-jwt"));
    let error = plugin.verify(&context, &params).await.unwrap_err();
    assert!(error.message.contains("compact"), "{error}");

    // Malformed params refuse at LOAD (the validate_params discipline):
    // a path on the token input, or no token ref at all.
    let bad_path = json!({ "token": { "input": "x", "path": ["deep"] } });
    assert!(plugin.validate_params(&bad_path).is_err());
    assert!(plugin.validate_params(&json!({})).is_err());
}

// ─── The reference fetch provider ─────────────────────────────────────────

struct StubFetch {
    name: String,
    surface: Vec<String>,
}

#[async_trait::async_trait]
impl FetchPlugin for StubFetch {
    fn name(&self) -> &str {
        &self.name
    }
    fn input_surface(&self) -> Vec<String> {
        self.surface.clone()
    }
    async fn fetch(&self, _inputs: BTreeMap<String, Value>) -> siros_flow_core::Result<Value> {
        Ok(json!({ "ok": true }))
    }
}

async fn spawn_echo_api() -> (String, axum::Router) {
    let app = axum::Router::new().route(
        "/record",
        axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
            axum::Json(json!({
                "employee_id": "emp-7",
                "department": "Signet",
                "saw": body,
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, axum::Router::new())
}

fn http_json_cfg(url: &str, inputs: &[&str], max_response_bytes: usize) -> FetchPluginCfg {
    FetchPluginCfg {
        name: "hr-api".to_owned(),
        url: url.to_owned(),
        timeout_ms: 5_000,
        max_response_bytes,
        inputs: inputs.iter().map(|s| s.to_string()).collect(),
    }
}

#[tokio::test]
async fn the_reference_fetch_provider_sends_exactly_the_declared_inputs_bounded() {
    let (url, _keep) = spawn_echo_api().await;
    let plugin = HttpJsonPlugin::from_config(&http_json_cfg(
        &format!("{url}/record"),
        &["family_name"],
        65_536,
    ))
    .unwrap();
    assert_eq!(plugin.input_surface(), vec!["family_name".to_owned()]);

    let mut inputs = BTreeMap::new();
    inputs.insert("family_name".to_owned(), json!("Andahl"));
    let fetched = plugin.fetch(inputs).await.unwrap();
    assert_eq!(fetched["employee_id"], "emp-7");
    // Exactly the declared inputs were sent (the echo proves it).
    assert_eq!(fetched["saw"]["family_name"], "Andahl");
    assert!(
        fetched["saw"].as_object().unwrap().len() == 1,
        "nothing else left the context: {:?}",
        fetched["saw"]
    );

    // Fail-closed: a dead endpoint is an error, never a silent
    // continue (§6.5).
    let plugin =
        HttpJsonPlugin::from_config(&http_json_cfg("http://127.0.0.1:9/nowhere", &[], 65_536))
            .unwrap();
    assert!(plugin.fetch(BTreeMap::new()).await.is_err());
}

#[tokio::test]
async fn the_reference_fetch_provider_enforces_the_response_budget() {
    let app = axum::Router::new().route(
        "/big",
        axum::routing::post(|| async move { "x".repeat(10_000) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let plugin = HttpJsonPlugin::from_config(&FetchPluginCfg {
        name: "big-api".to_owned(),
        url: format!("http://{addr}/big"),
        timeout_ms: 5_000,
        max_response_bytes: 128,
        inputs: vec![],
    })
    .unwrap();
    let error = plugin.fetch(BTreeMap::new()).await.unwrap_err();
    assert!(
        error.message.contains("budget"),
        "the size budget refuses: {error}"
    );
}

// ─── The discovery key source (the only honest wiring for an
//     ephemeral-key IdP — the mini-oidc mints a fresh key per boot) ─────────

/// A stub JWKS server whose key can ROTATE mid-test (the redeployed
/// IdP): the served set lives behind a lock the test swaps.
async fn spawn_jwks() -> (
    String,
    std::sync::Arc<std::sync::RwLock<Vec<jose_rs::jwk::Jwk>>>,
) {
    let served: std::sync::Arc<std::sync::RwLock<Vec<jose_rs::jwk::Jwk>>> = Default::default();
    let app = {
        let served = served.clone();
        axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let served = served.clone();
                async move {
                    let keys = served.read().map(|k| k.clone()).unwrap_or_default();
                    let jwks: Vec<serde_json::Value> = keys
                        .iter()
                        .map(|k| serde_json::to_value(k.to_public_jwk()).unwrap())
                        .collect();
                    axum::Json(serde_json::json!({ "keys": jwks }))
                }
            }),
        )
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/jwks"), served)
}

fn discovery_config(jwks_uri: &str) -> TokenPluginCfg {
    TokenPluginCfg {
        name: "test-idp".to_owned(),
        key_path: None,
        jwks_uri: Some(jwks_uri.to_owned()),
        issuer: "https://idp.example.org".to_owned(),
        audience: "https://flow.example.org".to_owned(),
        leeway_seconds: 60,
    }
}

fn claims_ok() -> Value {
    json!({
        "iss": "https://idp.example.org",
        "aud": "https://flow.example.org",
        "sub": "user-42",
        "iat": now() - 10,
        "exp": now() + 300,
        "employee_id": "emp-7",
    })
}

#[tokio::test]
async fn the_discovery_source_verifies_and_picks_up_rotation() {
    let (jwks_uri, served) = spawn_jwks().await;
    let key = idp_key();
    *served.write().unwrap() = vec![key.clone()];
    let plugin = IdTokenPlugin::from_config(&discovery_config(&jwks_uri)).unwrap();
    let params = json!({ "token": { "input": "idp_assertion", "path": [] } });

    // The discovered key verifies the assertion.
    let mut context = FlowContext::default();
    context.inputs.insert(
        "idp_assertion".to_owned(),
        json!(sign_jwt(&key, &claims_ok())),
    );
    let verified = plugin.verify(&context, &params).await.unwrap();
    assert_eq!(verified["employee_id"], "emp-7");

    // Rotation — the IdP redeployed and minted a fresh key. The
    // CACHED key keeps verifying until its TTL (honest caching, not
    // a bug: the set was fetched minutes ago).
    let rotated = idp_key();
    *served.write().unwrap() = vec![rotated.clone()];
    let still_ok = plugin.verify(&context, &params).await;
    assert!(
        still_ok.is_ok(),
        "the cached key keeps verifying: {still_ok:?}"
    );

    // A second plugin instance (a process restart — its cache starts
    // cold) fetches the ROTATED set: the old key's assertion refuses
    // (its kid is gone from the set), the new key's assertion verifies.
    let plugin2 = IdTokenPlugin::from_config(&discovery_config(&jwks_uri)).unwrap();
    let error = plugin2.verify(&context, &params).await.unwrap_err();
    assert!(
        error.message.to_lowercase().contains("signature")
            || error.message.to_lowercase().contains("verify")
            || error.message.to_lowercase().contains("kid"),
        "the rotated-out key refuses: {error}"
    );
    context.inputs.insert(
        "idp_assertion".to_owned(),
        json!(sign_jwt(&rotated, &claims_ok())),
    );
    let verified = plugin2.verify(&context, &params).await.unwrap();
    assert_eq!(verified["employee_id"], "emp-7");
}

#[tokio::test]
async fn the_key_source_config_refuses_ambiguity() {
    // Both sources named: ambiguous — refuse.
    let both = TokenPluginCfg {
        name: "x".to_owned(),
        key_path: Some("/dev/null".to_owned()),
        jwks_uri: Some("https://idp.example.org/jwks".to_owned()),
        issuer: String::new(),
        audience: String::new(),
        leeway_seconds: 60,
    };
    let error = IdTokenPlugin::from_config(&both).unwrap_err();
    assert!(
        error.message.contains("exactly one"),
        "the ambiguity refuses: {error}"
    );
    // Neither: refuse.
    let neither = TokenPluginCfg {
        key_path: None,
        jwks_uri: None,
        ..both
    };
    let error = IdTokenPlugin::from_config(&neither).unwrap_err();
    assert!(error.message.contains("exactly one"), "{error}");
}

#[test]
fn every_shipped_flow_validates_against_the_shipped_plugin_names() {
    // The load gate app::build runs for the whole shipped set: a
    // definition referencing a plugin outside the registry refuses at
    // startup — this is the same check with the shipped names wired.
    use siros_flow_service::plugins::validate_definition;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../flows");
    let key = idp_key();
    // The SHIPPED name ("idp") — the deployments' wiring contract.
    let shipped_idp = TokenPluginCfg {
        name: "idp".to_owned(),
        key_path: Some(write_public_jwk(&key)),
        jwks_uri: None,
        issuer: "https://idp.example.org".to_owned(),
        audience: "https://flow.example.org".to_owned(),
        leeway_seconds: 60,
    };
    let registry =
        TokenRegistry::new().with(Box::new(IdTokenPlugin::from_config(&shipped_idp).unwrap()));
    let fetches = FetchRegistry::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yaml") {
            let definition = siros_flow_core::language::FlowDefinition::from_yaml(
                &std::fs::read_to_string(&path).unwrap(),
            )
            .unwrap();
            validate_definition(&definition, &registry, &fetches)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }
}
