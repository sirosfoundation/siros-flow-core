//! §2.1 flow 4 end-to-end (P-bw3's target): **token-sourced
//! attestation — integrator-asserted identity + PID presentation**
//! (§6.4: the integrator that runs the SAML SP asserts its user;
//! flow-core parses no XML, it consumes the asserting party's JWT).
//!
//! The flow, definition-driven over the new step kinds:
//!
//! 1. `token` — the enterprise IdP's JWT arrives as a flow input; the
//!    reference plugin verifies signature/`iss`/`aud`/freshness (the
//!    `verify_bearer_assertion` discipline) and its claims land in
//!    the context under the step id.
//! 2. `presentation` — the PID, over the deep-link carrier.
//! 3. `bind` — claim-equals: the token's asserted given_name equals
//!    the PID's presented one. The names comparison, exact as a
//!    comparison, probabilistic as identity evidence — the flow says
//!    so by naming claim-equals (§8.2). Its LEFT side is a DERIVED
//!    ref (the token step's claims), exercising the §5.5 addressing.
//! 4. `issuance` — the staff attestation over the PID's identity
//!    claims merged with the token's employee_id/department; the
//!    catalog's claim building filters to the schema's paths.
//!
//! The companion test proves `fetch` (§6.5): the employee record is
//! FETCHED (the reference http-json provider, exactly the declared
//! inputs sent) and feeds the same subject derivation — the two
//! sourced-context step kinds are interchangeable in the merge.
//!
//! The negative proves the token-sourced side of the bind is honest:
//! a token asserting someone else refuses the walk at the names
//! comparison.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use url::Url;

use siros_flow_core::bind::BindRegistry;
use siros_flow_service::state::FlowServiceState;
use siros_flow_service::store::MemoryFlowStore;
use siros_flow_service::IssuerCoreClient;

const ISSUER_BASE: &str = "http://127.0.0.1:8080";

// ─── The service shapes (the family's e2e pattern) ─────────────────────────

struct PermitPdp;

#[async_trait::async_trait]
impl siros_issuer_service::pdp::TrustPdp for PermitPdp {
    async fn permit(
        &self,
        _query: &siros_issuer_core::trust::IssuanceTrustQuery,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }
    async fn permit_presentation(
        &self,
        _query: &siros_verifier_core::trust::TrustQuery,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }
    async fn permit_wallet_provider(
        &self,
        _query: &siros_issuer_core::trust::WalletProviderTrustQuery,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }
}

struct RecordingAllocator {
    list_url: Url,
    next_index: AtomicU64,
}

#[async_trait::async_trait]
impl siros_issuer_service::status::StatusAllocator for RecordingAllocator {
    async fn allocate(
        &self,
        _exp: Option<String>,
    ) -> siros_issuer_core::Result<siros_issuer_core::status_client::StatusRef> {
        Ok(siros_issuer_core::status_client::StatusRef {
            list_url: self.list_url.clone(),
            index: self.next_index.fetch_add(1, Ordering::SeqCst),
        })
    }
    async fn update(
        &self,
        _list_url: &Url,
        _index: u64,
        _status: siros_issuer_core::status_client::Status,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }
}

fn test_signer(kid: &str) -> (siros_issuer_core::signer::JwkSigner, jose_rs::jwk::Jwk) {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
    jwk.alg = Some("ES256".to_owned());
    jwk.kid = Some(kid.to_owned());
    let signer = siros_issuer_core::signer::JwkSigner::new(jwk.clone()).expect("signer");
    (signer, jwk)
}

fn signer_cert_chain(private: &jose_rs::jwk::Jwk) -> Vec<Vec<u8>> {
    let d = private.d.as_deref().expect("private scalar");
    let bytes = siros_issuer_core::sdjwt_issue::b64u_decode(d).expect("d is base64url");
    let key = p256::ecdsa::SigningKey::from_slice(&bytes).expect("signing key");
    use p256::pkcs8::EncodePrivateKey;
    let pkcs8 = key.to_pkcs8_der().unwrap();
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let params = rcgen::CertificateParams::new(vec!["flow.example.org".to_string()]).unwrap();
    vec![params.self_signed(&kp).unwrap().der().to_vec()]
}

fn issuer_config() -> siros_issuer_service::config::Config {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .display()
        .to_string();
    siros_issuer_service::config::Config::from_toml_str(&format!(
        r#"
[issuer]
url = "http://127.0.0.1:8080"

[catalog]
static_dir = "{dir}/ts11"
refresh_seconds = 0
"#
    ))
    .unwrap()
}

const FLOW_INTEGRATOR_ID: &str = "https://flow.example.org/";

const CLIENT_PRIVATE_JWK: &str = r#"{"kty":"EC","x":"MpY3glbcq9njtQLM1hCREOrfQqPgOKyGOl7xkMwHsSI","y":"ZDT-zr7lt2R12MaFbXuapq4eXS5hprKjegb5yq3UlXE","crv":"P-256","d":"gaknst5YK3n03zh8vvDXA4HydaNQfzYtnC0CiMHADmI","kid":"test-client-key-1","alg":"ES256","use":"sig"}"#;

fn flow_integrator_registry(
    public: &jose_rs::jwk::Jwk,
) -> siros_issuer_service::client_auth::ClientRegistry {
    let mut clients = HashMap::new();
    clients.insert(
        FLOW_INTEGRATOR_ID.to_owned(),
        siros_issuer_service::client_auth::ClientRegistration {
            jwks: vec![serde_json::to_value(public.to_public_jwk()).unwrap()],
            redirect_uris: vec![],
            allow_any_redirect_uri: false,
            scope: None,
        },
    );
    clients.insert(
        "suite-wallet".to_owned(),
        siros_issuer_service::client_auth::ClientRegistration {
            jwks: vec![serde_json::json!({
                "kty": "EC",
                "x": "MpY3glbcq9njtQLM1hCREOrfQqPgOKyGOl7xkMwHsSI",
                "y": "ZDT-zr7lt2R12MaFbXuapq4eXS5hprKjegb5yq3UlXE",
                "crv": "P-256",
                "kid": "test-client-key-1",
                "alg": "ES256",
                "use": "sig",
            })],
            redirect_uris: vec!["http://localhost:3000/cb".to_owned()],
            allow_any_redirect_uri: false,
            scope: Some("pid".to_owned()),
        },
    );
    siros_issuer_service::client_auth::ClientRegistry { clients }
}

async fn spawn_issuer(
    integrator_public: &jose_rs::jwk::Jwk,
) -> (String, siros_issuer_core::signer::JwkSigner) {
    let config = issuer_config();
    let (signer, private) = test_signer("test-issuer-key");
    let catalog_source =
        siros_issuer_service::fetch::CatalogSource::from_config(&config.catalog).unwrap();
    let catalog = futures_util::FutureExt::now_or_never(async {
        siros_issuer_service::fetch::load_catalog(&catalog_source).await
    })
    .unwrap()
    .unwrap();
    let (events_tx, _) = tokio::sync::broadcast::channel(64);
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/test-list").unwrap(),
        next_index: AtomicU64::new(3),
    });
    let state = siros_issuer_service::api::AppState {
        catalog: Arc::new(std::sync::RwLock::new(Arc::new(catalog))),
        issuer_base: Url::parse(ISSUER_BASE).unwrap(),
        authorization_servers: vec![],
        refresh: Arc::new(siros_issuer_service::api::RefreshStatus::default()),
        sessions: Arc::new(siros_issuer_service::store::MemoryStore::new()),
        dpop: Arc::new(siros_issuer_service::dpop::DpopValidator::new(60)),
        last_public_nonce: Arc::new(Mutex::new(String::new())),
        login_url: None,
        clients: Arc::new(flow_integrator_registry(integrator_public)),
        scopes: HashMap::new(),
        endpoint_paths: siros_issuer_core::oid4vci::EndpointPaths::default(),
        deferred_interval_seconds: 5,
        auxiliary_data_plans: std::collections::BTreeMap::new(),
        request_encryption_key: None,
        cert_chain_der: signer_cert_chain(&private),
        attestation: Arc::new(siros_issuer_service::client_auth::WildcardRulesPolicy::new(
            Vec::new(),
        )),
        wallet_attestation: None,
        pre_auth_binding: None,
        signer: Arc::new(signer.clone()),
        vault: Arc::new(siros_issuer_service::vault::Vault::new().unwrap()),
        pdp: Arc::new(PermitPdp),
        allocator,
        events_tx,
        credential_validity_seconds: 3600,
        access_token_ttl_seconds: 300,
        c_nonce_ttl_seconds: 300,
        rulebooks: HashMap::new(),
        zk_seeds: Default::default(),
        rate_counters: siros_issuer_service::rate_limit::WalletRateCounters::from_config(
            &config.rate_limit,
        ),
        rate_limit: config.rate_limit.clone(),
        circuit_manifest: None,
    };
    let app = siros_issuer_service::api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        format!("http://{addr}"),
        siros_issuer_core::signer::JwkSigner::new(private).unwrap(),
    )
}

/// The whole deployment shape: the definitions dir carries the flow-4
/// definition (+ the fetch variant), the plugin registries are built
/// from config exactly as app::build does, and the definitions pass
/// the same load gate (bind vocabulary + plugin allowlist + the
/// fetch input-surface audit).
async fn spawn_flow(
    definitions_dir: &str,
    issuer_base_url: &str,
    integrator_key: jose_rs::jwk::Jwk,
    idp_public_key_path: &str,
    hr_api_url: &str,
) -> String {
    let definitions = FlowServiceState::load_definitions(definitions_dir).unwrap();

    // The plugin allowlist, from config (§6.7) — app::build's shape.
    let token_registry = siros_flow_service::plugins::TokenRegistry::new().with(Box::new(
        siros_flow_service::plugins::IdTokenPlugin::from_config(
            &siros_flow_service::config::TokenPluginCfg {
                name: "test-idp".to_owned(),
                key_path: Some(idp_public_key_path.to_owned()),
                jwks_uri: None,
                issuer: "https://idp.example.org".to_owned(),
                audience: "https://flow.example.org".to_owned(),
                leeway_seconds: 60,
            },
        )
        .unwrap(),
    ));
    let fetch_registry = siros_flow_service::plugins::FetchRegistry::new().with(Box::new(
        siros_flow_service::plugins::HttpJsonPlugin::from_config(
            &siros_flow_service::config::FetchPluginCfg {
                name: "hr-api".to_owned(),
                url: hr_api_url.to_owned(),
                timeout_ms: 5_000,
                max_response_bytes: 65_536,
                inputs: vec!["family_name".to_owned()],
            },
        )
        .unwrap(),
    ));
    // The load gate the deployment runs at startup — the definitions
    // under test must pass it.
    let bind_registry = BindRegistry::standard();
    for definition in definitions.values() {
        siros_flow_core::bind::validate_definition(definition, &bind_registry).unwrap();
        siros_flow_service::plugins::validate_definition(
            definition,
            &token_registry,
            &fetch_registry,
        )
        .unwrap();
    }

    let (signer, private) = test_signer("test-flow-key");
    let _ = signer;
    let client = IssuerCoreClient::new(
        Url::parse(issuer_base_url).unwrap(),
        siros_issuer_core::oid4vci::issuer_identifier(&Url::parse(ISSUER_BASE).unwrap()).to_owned(),
        FLOW_INTEGRATOR_ID.to_owned(),
        {
            static SPAWNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = SPAWNS.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir()
                .join(format!("flow-integrator-{}-{n}.jwk", std::process::id()));
            std::fs::write(&path, serde_json::to_string(&integrator_key).unwrap()).unwrap();
            path.display().to_string()
        }
        .as_str(),
    )
    .unwrap();
    let state = Arc::new(FlowServiceState {
        definitions,
        definitions_dir: definitions_dir.to_owned(),
        store: Arc::new(MemoryFlowStore::new()),
        vault: siros_issuer_service::vault::Vault::new().unwrap(),
        signer: {
            let (verifier_signer, _) = test_signer("test-flow-verifier-key");
            Arc::new(verifier_signer)
        },
        cert_chain_der: signer_cert_chain(&private),
        pdp: Arc::new(PermitPdp),
        issuer: Arc::new(client),
        public_url: Url::parse(ISSUER_BASE).unwrap(),
        presentation_ttl_seconds: 300,
        default_carrier: siros_flow_core::language::Carrier::Deeplink,
        retention_after_final_seconds: 3_600,
        bind_registry,
        token_registry,
        fetch_registry,
    });
    let app = siros_flow_service::http::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

// ─── The wallet-side helpers ────────────────────────────────────────────────

fn sign_jwt(key: &jose_rs::jwk::Jwk, typ: &str, claims: &Value, embed_jwk: bool) -> String {
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some(typ.to_owned());
    header.kid = key.kid.clone();
    if embed_jwk {
        header.jwk = Some(serde_json::to_value(key.to_public_jwk()).unwrap());
    }
    let payload = serde_json::to_vec(claims).unwrap();
    let mut opts = jose_rs::jws::compact::SignOptions::new();
    if embed_jwk {
        opts = opts.with_key_reference_headers(true);
    }
    jose_rs::jws::compact::sign_with_jwk_options(key, &payload, &header, &opts).expect("jwt signs")
}

fn now_unix() -> i64 {
    siros_issuer_service::status::now_unix()
}

/// The enterprise IdP's assertion (an ES256 JWT; the plugin's
/// configured key verifies it).
fn idp_assertion(key: &jose_rs::jwk::Jwk, given_name: &str) -> String {
    sign_jwt(
        key,
        "jwt",
        &json!({
            "iss": "https://idp.example.org",
            "aud": "https://flow.example.org",
            "sub": "user-42",
            "iat": now_unix() - 10,
            "exp": now_unix() + 600,
            "given_name": given_name,
            "employee_id": "emp-7",
            "department": "Signet",
        }),
        false,
    )
}

/// The definitions dir: flow 4 (+ the fetch variant).
fn write_definitions() -> std::path::PathBuf {
    // Unique per call: the tests run concurrently in one process and a
    // shared dir races (one writes while another loads).
    static DIRS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "flow4-flows-{}-{}",
        std::process::id(),
        DIRS.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("token-sourced-attestation.yaml"),
        r#"
# §2.1 flow 4: token-sourced attestation — integrator-asserted
# identity + PID presentation (§6.4: the integrator that runs the
# SAML SP asserts its user; the flow consumes the asserting party's
# JWT as a flow input — flow-core parses no XML).
flow: token-sourced-attestation
language_version: 1
description: >
  The enterprise IdP's assertion plus the employee's PID, bound by
  the names comparison (probabilistic, §8.2), issue a staff
  attestation over both.
steps:
  - token:
      id: consume-idp-assertion
      plugin: test-idp
      params:
        token: { input: idp_assertion, path: [] }
  - presentation:
      id: present-pid
      request:
        - id: pid
          format: dc+sd-jwt
          meta: { vct_values: ["urn:eudi:pid:1"] }
          claims:
            - { path: [given_name] }
            - { path: [family_name] }
      require: [pid]
  - bind:
      # The names comparison: exact as a comparison, probabilistic as
      # identity evidence — the flow says so by naming claim-equals
      # (§8.2). The left side is the TOKEN's asserted claim (a
      # derived ref, §5.5); the right the PID's presented one.
      id: pid-is-the-asserted-user
      primitive: claim-equals
      params:
        left: { step: consume-idp-assertion, path: [given_name] }
        right: { step: present-pid, credential: pid, path: [given_name] }
      on_mismatch: fail
  - issuance:
      id: issue-staff-attestation
      credential: "urn:ewb:staff:1"
      subject:
        from: { step: present-pid, credential: pid, path: [] }
        merge:
          employee_id: { step: consume-idp-assertion, path: [employee_id] }
          department: { step: consume-idp-assertion, path: [department] }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("fetched-record-attestation.yaml"),
        r#"
# The fetch variant (§6.5): the employee record is FETCHED (exactly
# the declared inputs sent — the PID's family_name) and feeds the
# same subject derivation. The sourced-context step kinds are
# interchangeable in the merge.
flow: fetched-record-attestation
language_version: 1
steps:
  - presentation:
      id: present-pid
      request:
        - id: pid
          format: dc+sd-jwt
          meta: { vct_values: ["urn:eudi:pid:1"] }
          claims:
            - { path: [given_name] }
            - { path: [family_name] }
      require: [pid]
  - fetch:
      id: employee-record
      plugin: hr-api
      inputs:
        family_name: { step: present-pid, credential: pid, path: [family_name] }
  - issuance:
      id: issue-staff-attestation
      credential: "urn:ewb:staff:1"
      subject:
        from: { step: present-pid, credential: pid, path: [] }
        merge:
          employee_id: { step: employee-record, path: [employee_id] }
          department: { step: employee-record, path: [department] }
"#,
    )
    .unwrap();
    dir
}

/// The HR API the fetch step calls (the reference provider's target).
async fn spawn_hr_api() -> String {
    let app = axum::Router::new().route(
        "/employee",
        axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
            // The record for whoever's family_name arrived — and
            // nothing else was sent (the surface discipline).
            let family_name = body["family_name"].as_str().unwrap_or_default();
            axum::Json(json!({
                "employee_id": format!("emp-{family_name}"),
                "department": "Signet",
                "saw": body,
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/employee")
}

/// Present a PID (given_name/family_name disclosed) and return the
/// walk's reply. The whole wallet leg of the e2e.
async fn present_pid(
    client: &reqwest::Client,
    flow_url: &str,
    flow: &str,
    start_body: Value,
    given_name: &str,
    family_name: &str,
) -> (String, Value) {
    let response = client
        .post(format!("{flow_url}/flows/{flow}/start"))
        .json(&start_body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    let start: Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| panic!("the start reply (HTTP {status}): {text}"));
    let instance = start["instance"].as_str().unwrap().to_owned();
    let jar = start["authorization_request"]
        .as_str()
        .unwrap_or_else(|| panic!("the armed request: {start}"))
        .to_owned();
    let payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let nonce = payload["nonce"].as_str().unwrap().to_owned();
    let state = payload["state"].as_str().unwrap().to_owned();
    let client_id = payload["client_id"].as_str().unwrap().to_owned();
    let response_uri = payload["response_uri"]
        .as_str()
        .unwrap()
        .replace(ISSUER_BASE, flow_url.trim_end_matches('/'));
    let enc_pub: jose_rs::jwk::Jwk =
        serde_json::from_value(payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let enc_kid = enc_pub.kid.clone().unwrap();

    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, IssueSpec, KbSpec, Seg};
    let (issuer_cert, issuer_key) = testutil::self_signed_ec("pid-issuer.example", "ES256");
    let holder = testutil::ec_jwk("ES256", "holder");
    let now = now_unix();
    let mut spec = IssueSpec::new(json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "given_name": given_name,
        "family_name": family_name,
        "birthdate": "1985-05-05",
    }));
    spec.holder_pub = Some(testutil::public_of(&holder));
    spec.x5c_der = vec![issuer_cert];
    spec.conceal = vec![
        vec![Seg::Key("given_name")],
        vec![Seg::Key("family_name")],
        vec![Seg::Key("birthdate")],
    ];
    let issued = testutil::issue(&issuer_key, &spec).unwrap();
    let presentation = testutil::present(
        &issued,
        &[0, 1, 2],
        Some(KbSpec {
            holder: &holder,
            aud: &client_id,
            nonce: &nonce,
            iat: now,
        }),
        HashAlg::Sha256,
    )
    .unwrap();

    let body = serde_json::to_vec(&json!({
        "vp_token": { "pid": [presentation] },
        "state": state,
    }))
    .unwrap();
    let jwe = siros_issuer_core::response::encrypt_response(
        &enc_pub,
        &body,
        Some(&enc_kid),
        jose_rs::algorithm::JweEncryption::A128GCM,
    )
    .unwrap();
    let response = client
        .post(&response_uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("response={}", urlencoding::encode(&jwe)))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    let reply: Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| panic!("the walk reply (HTTP {status}): {text}"));
    (instance, reply)
}

/// Redeem the offer the walk produced: the staff attestation, verified.
async fn redeem_staff_attestation(
    client: &reqwest::Client,
    issuer_url: &str,
    issuer_signer: &siros_issuer_core::signer::JwkSigner,
    reply: &Value,
) -> siros_verifier_core::sdjwt::CryptoVerified {
    let offer = &reply["credential_offers"][0];
    assert_eq!(offer["credential"], "urn:ewb:staff:1", "{reply}");
    let offer_uri = offer["offer_uri"]
        .as_str()
        .unwrap()
        .replace(ISSUER_BASE, issuer_url.trim_end_matches('/'));
    let offer: Value = client
        .get(&offer_uri)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .expect("the pre-authorized grant");
    let client_key: jose_rs::jwk::Jwk =
        serde_json::from_str(CLIENT_PRIVATE_JWK).expect("the test client key");
    let client_assertion = sign_jwt(
        &client_key,
        "jwt",
        &json!({
            "iss": "suite-wallet",
            "sub": "suite-wallet",
            "aud": siros_issuer_core::oid4vci::issuer_identifier(&Url::parse(ISSUER_BASE).unwrap()),
            "iat": now_unix(),
            "exp": now_unix() + 300,
        }),
        true,
    );
    let token: Value = client
        .post(format!("{issuer_url}/token"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_owned(),
            ),
            ("pre_authorized_code", code.to_owned()),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
            ),
            ("client_assertion", client_assertion),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(token["access_token"].is_string(), "the token: {token}");
    let c_nonce = token["c_nonce"].as_str().unwrap().to_owned();

    let wallet_key = {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
        jwk.alg = Some("ES256".to_owned());
        jwk
    };
    let proof = sign_jwt(
        &wallet_key,
        "openid4vci-proof+jwt",
        &json!({
            "iss": "wallet",
            "aud": siros_issuer_core::oid4vci::issuer_identifier(&Url::parse(ISSUER_BASE).unwrap()),
            "nonce": c_nonce,
            "iat": now_unix(),
        }),
        true,
    );
    let credential: Value = client
        .post(format!("{issuer_url}/credential"))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .json(&json!({
            "credential_configuration_id": "urn:ewb:staff:1",
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let attestation = credential["credentials"][0]["credential"]
        .as_str()
        .expect("the staff attestation");

    use siros_verifier_core::sdjwt::{HolderBinding, StaticKey, VerifyParams};
    siros_verifier_core::sdjwt::verify(
        attestation,
        &StaticKey(
            siros_issuer_core::signer::Signer::public_jwk(issuer_signer)
                .expect("the issuer's public key"),
        ),
        &VerifyParams::new(now_unix(), HolderBinding::NotRequired),
    )
    .expect("the staff attestation verifies")
}

// ─── Flow 4 ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn flow4_the_idp_assertion_plus_pid_issue_the_staff_attestation() {
    // The enterprise IdP (the asserting party): its key is wired into
    // the plugin by config — the flow references the plugin by name.
    let idp_key = {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
        jwk.alg = Some("ES256".to_owned());
        jwk
    };
    let idp_public_path = {
        let path = std::env::temp_dir().join(format!("idp-public-{}.jwk", std::process::id()));
        std::fs::write(
            &path,
            serde_json::to_string(&idp_key.to_public_jwk()).unwrap(),
        )
        .unwrap();
        path.display().to_string()
    };

    let (integrator_signer, integrator_private) = test_signer("flow-integrator-key");
    let _ = integrator_signer;
    let (issuer_url, issuer_signer) = spawn_issuer(&integrator_private.to_public_jwk()).await;
    let definitions = write_definitions();
    let hr_url = spawn_hr_api().await;
    let flow_url = spawn_flow(
        definitions.to_str().unwrap(),
        &issuer_url,
        integrator_private,
        &idp_public_path,
        &hr_url,
    )
    .await;
    let client = reqwest::Client::new();

    let (instance, reply) = present_pid(
        &client,
        &flow_url,
        "token-sourced-attestation",
        json!({ "idp_assertion": idp_assertion(&idp_key, "Anna") }),
        "Anna",
        "Andahl",
    )
    .await;
    assert_eq!(reply["next"], "complete", "the walk completed: {reply}");

    // The oracle: the attestation's claims are the MERGED subject —
    // the PID's identity + the TOKEN's employee facts.
    let verified = redeem_staff_attestation(&client, &issuer_url, &issuer_signer, &reply).await;
    assert_eq!(verified.vct, "urn:ewb:staff:1");
    assert_eq!(verified.claims["given_name"], "Anna");
    assert_eq!(verified.claims["family_name"], "Andahl");
    assert_eq!(verified.claims["employee_id"], "emp-7");
    assert_eq!(verified.claims["department"], "Signet");
    // The catalog's claim building filtered to the schema: the PID's
    // birthdate never leaks.
    assert!(verified.claims.get("birthdate").is_none());

    let status: Value = client
        .get(format!("{flow_url}/flows/{instance}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["state"], "completed");
}

#[tokio::test]
async fn flow4_a_token_asserting_someone_else_refuses_at_the_bind() {
    let idp_key = {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
        jwk.alg = Some("ES256".to_owned());
        jwk
    };
    let idp_public_path = {
        let path =
            std::env::temp_dir().join(format!("idp-public-negative-{}.jwk", std::process::id()));
        std::fs::write(
            &path,
            serde_json::to_string(&idp_key.to_public_jwk()).unwrap(),
        )
        .unwrap();
        path.display().to_string()
    };
    let (integrator_signer, integrator_private) = test_signer("flow-integrator-key");
    let _ = integrator_signer;
    let (issuer_url, _issuer_signer) = spawn_issuer(&integrator_private.to_public_jwk()).await;
    let definitions = write_definitions();
    let hr_url = spawn_hr_api().await;
    let flow_url = spawn_flow(
        definitions.to_str().unwrap(),
        &issuer_url,
        integrator_private,
        &idp_public_path,
        &hr_url,
    )
    .await;
    let client = reqwest::Client::new();

    // The IdP asserts Birgitta; the wallet presents Anna's PID: the
    // names comparison refuses — the token-sourced side of the bind
    // gates like any other (fail-closed; the message names the
    // comparison, never values).
    let (_, reply) = present_pid(
        &client,
        &flow_url,
        "token-sourced-attestation",
        json!({ "idp_assertion": idp_assertion(&idp_key, "Birgitta") }),
        "Anna",
        "Andahl",
    )
    .await;
    assert_eq!(reply["error"], "bind_mismatch", "the refusal: {reply}");
    assert_ne!(reply["next"], "complete");
}

// ─── The fetch variant ────────────────────────────────────────────────────

#[tokio::test]
async fn a_fetch_step_feeds_the_subject_derivation_over_the_declared_inputs() {
    let (integrator_signer, integrator_private) = test_signer("flow-integrator-key");
    let _ = integrator_signer;
    let (issuer_url, issuer_signer) = spawn_issuer(&integrator_private.to_public_jwk()).await;
    let definitions = write_definitions();
    let hr_url = spawn_hr_api().await;
    let flow_url = spawn_flow(
        definitions.to_str().unwrap(),
        &issuer_url,
        integrator_private,
        // No token plugin configured for this deployment shape — the
        // fetch flow references none (the registries are per-step
        // concerns; an unused one may be empty).
        {
            let path =
                std::env::temp_dir().join(format!("idp-public-unused-{}.jwk", std::process::id()));
            let key = jose_rs::jwk::generate_ec("P-256").unwrap();
            std::fs::write(&path, serde_json::to_string(&key.to_public_jwk()).unwrap()).unwrap();
            path.display().to_string()
        }
        .as_str(),
        &hr_url,
    )
    .await;
    let client = reqwest::Client::new();

    let (instance, reply) = present_pid(
        &client,
        &flow_url,
        "fetched-record-attestation",
        json!({}),
        "Anna",
        "Andahl",
    )
    .await;
    assert_eq!(reply["next"], "complete", "the walk completed: {reply}");

    // The fetched record (the HR API saw exactly family_name — the
    // surface discipline) feeds the subject: employee_id is derived
    // FROM what was sent, proving the inputs reached the provider.
    let verified = redeem_staff_attestation(&client, &issuer_url, &issuer_signer, &reply).await;
    assert_eq!(verified.vct, "urn:ewb:staff:1");
    assert_eq!(
        verified.claims["employee_id"], "emp-Andahl",
        "the fetched record: {:?}",
        verified.claims
    );
    assert_eq!(verified.claims["department"], "Signet");
    assert_eq!(verified.claims["given_name"], "Anna");

    let status: Value = client
        .get(format!("{flow_url}/flows/{instance}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["state"], "completed");
}
