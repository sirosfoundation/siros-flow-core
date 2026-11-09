//! The PID→EHIC end-to-end (P-bw1's exit criterion, the MVP flow):
//! the `ehic-pid-presentation` DEFINITION drives the whole journey —
//! no flow-specific code, the driver walks the definition.
//!
//! The path, each hop a protocol surface a vc-compatible wallet
//! already speaks:
//!
//! 1. `POST /flows/ehic-pid-presentation/start` → the signed OID4VP
//!    request object (verifier-core `create_request`, the Mode B
//!    shape) + the response_uri.
//! 2. The wallet presents a PID (issued by a test PID issuer,
//!    x5c-carried — the verifier resolves and verifies it; trust is
//!    the PDP's) to the response_uri (`direct_post.jwt`).
//! 3. The driver adopts the verified claims and runs the `issuance`
//!    step: the issuer backend API (the integrator surface,
//!    RFC 7523-authenticated — the same API a portal drives) creates
//!    the EHIC session; the reply carries the credential offer.
//! 4. The wallet redeems the offer at the issuer's own OID4VCI
//!    surface (offer → token → credential) — the flow never fronts
//!    issuance.
//! 5. The EHIC verifies in verifier-core with the issuer's key, its
//!    claims the PID's (the definition's declarative subject).
//!
//! Sources of truth: the OID4VP request/response shapes (verifier-core,
//! the OIDF-conformance-proven Mode B path), the OID4VCI offer/token/
//! credential traffic (issuer-core, the OIDF-conformance-proven
//! pre-authorized path), and the definition itself (flows/).

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

// ─── Test PDPs (both boundaries permit; refusals are unit-tested) ───────────

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

// ─── The recording allocator (status indices) ──────────────────────────────

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

// ─── Spawn helpers ─────────────────────────────────────────────────────────

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

/// The integrator identity the flow service presents to the issuer
/// backend (registered in the issuer's client registry).
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
    // The suite-shaped wallet client (the issuer's token endpoint demands
    // client auth on every grant — the §12.2-resolved surface).
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
) -> (
    String,
    siros_issuer_core::signer::JwkSigner,
    Arc<RecordingAllocator>,
) {
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
        allocator: allocator.clone(),
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
        allocator,
    )
}

async fn spawn_flow(
    definitions_dir: &str,
    issuer_base_url: &str,
    issuer_public_identifier: String,
    integrator_key: jose_rs::jwk::Jwk,
) -> String {
    let definitions = FlowServiceState::load_definitions(definitions_dir).unwrap();
    let (signer, private) = test_signer("test-flow-key");
    let _ = signer;
    let client = IssuerCoreClient::new(
        Url::parse(issuer_base_url).unwrap(),
        issuer_public_identifier,
        FLOW_INTEGRATOR_ID.to_owned(),
        // The integrator key rides a temp file (the client reads the
        // path; the test writes the JWK it also registered).
        {
            let path =
                std::env::temp_dir().join(format!("flow-integrator-{}.jwk", std::process::id()));
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
            // The verifier-role signer: signs request objects.
            let (verifier_signer, _) = test_signer("test-flow-verifier-key");
            Arc::new(verifier_signer)
        },
        cert_chain_der: signer_cert_chain(&private),
        pdp: Arc::new(PermitPdp),
        issuer: Arc::new(client),
        public_url: Url::parse("http://127.0.0.1:8080").unwrap(),
        presentation_ttl_seconds: 300,
        retention_after_final_seconds: 3_600,
        bind_registry: BindRegistry::standard(),
    });
    let app = siros_flow_service::http::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

// ─── Wallet-side helpers (the vc-compatible shapes) ─────────────────────────

fn ec_key() -> jose_rs::jwk::Jwk {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
    jwk.alg = Some("ES256".to_owned());
    jwk
}

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

fn proof_jwt(holder: &jose_rs::jwk::Jwk, issuer_base: &Url, nonce: &str) -> String {
    sign_jwt(
        holder,
        "openid4vci-proof+jwt",
        &json!({
            "iss": "wallet",
            "aud": siros_issuer_core::oid4vci::issuer_identifier(issuer_base),
            "nonce": nonce,
            "iat": now_unix(),
        }),
        true,
    )
}

// ─── The flow ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_pid_to_ehic_flow_runs_definition_driven_end_to_end() {
    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, IssueSpec, KbSpec, Seg};

    // The issuer and the flow service, side by side (the deployment
    // shape: the flow drives the issuer's backend API).
    let (integrator_signer, integrator_private) = test_signer("flow-integrator-key");
    let _ = integrator_signer;
    let (issuer_url, issuer_signer, allocator) =
        spawn_issuer(&integrator_private.to_public_jwk()).await;
    let definitions_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../flows")
        .display()
        .to_string();
    let issuer_identifier =
        siros_issuer_core::oid4vci::issuer_identifier(&Url::parse(ISSUER_BASE).unwrap()).to_owned();
    let flow_url = spawn_flow(
        &definitions_dir,
        &issuer_url,
        issuer_identifier.clone(),
        integrator_private,
    )
    .await;

    let client = reqwest::Client::new();

    // 1. Start the flow (the definition does the rest).
    let start_response = client
        .post(format!("{flow_url}/flows/ehic-pid-presentation/start"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let start_status = start_response.status();
    let start_text = start_response.text().await.unwrap();
    let start: Value = serde_json::from_str(&start_text)
        .unwrap_or_else(|_| panic!("the start reply (HTTP {start_status}): {start_text}"));
    let jar = start["authorization_request"]
        .as_str()
        .unwrap_or_else(|| panic!("the start reply carries no request object: {start_text}"))
        .to_owned();
    let instance = start["instance"].as_str().unwrap().to_owned();
    assert!(instance.starts_with("ehic-pid-presentation_"));

    // 2. The wallet reads the request object: nonce, state, client_id,
    //    the ephemeral encryption key, the response_uri (rewritten to
    //    the spawned flow service's real port).
    let jar_payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    // vct_values matches ANY listed type (the registry's PID
    // generations + the classic v1) — the fixture lists them.
    let vct_values = jar_payload["dcql_query"]["credentials"][0]["meta"]["vct_values"]
        .as_array()
        .expect("the PID query lists its vct_values");
    assert!(vct_values.iter().any(|v| v == "urn:eudi:pid:arf-1.8:1"));
    let oid4vp_nonce = jar_payload["nonce"].as_str().unwrap().to_owned();
    let oid4vp_state = jar_payload["state"].as_str().unwrap().to_owned();
    let oid4vp_client_id = jar_payload["client_id"].as_str().unwrap().to_owned();
    let response_uri = jar_payload["response_uri"]
        .as_str()
        .unwrap()
        .replace(ISSUER_BASE, flow_url.trim_end_matches('/'));
    let enc_pub: jose_rs::jwk::Jwk =
        serde_json::from_value(jar_payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let enc_kid = enc_pub.kid.clone().unwrap();

    // 3. The wallet holds a PID issued by another issuer (x5c-carried;
    //    trust is the PDP's — the same PID shape the Mode B e2e uses).
    let (pid_issuer_cert, pid_issuer_key) = testutil::self_signed_ec("pid-issuer.example", "ES256");
    let holder = testutil::ec_jwk("ES256", "holder");
    let now = now_unix();
    let mut spec = IssueSpec::new(json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "given_name": "Presented",
        "family_name": "Subject",
        "birth_date": "1999-12-31",
    }));
    spec.holder_pub = Some(testutil::public_of(&holder));
    spec.x5c_der = vec![pid_issuer_cert];
    spec.conceal = vec![
        vec![Seg::Key("given_name")],
        vec![Seg::Key("family_name")],
        vec![Seg::Key("birth_date")],
    ];
    let issued_pid = testutil::issue(&pid_issuer_key, &spec).unwrap();
    let presentation = testutil::present(
        &issued_pid,
        &[0, 1, 2],
        Some(KbSpec {
            holder: &holder,
            aud: &oid4vp_client_id,
            nonce: &oid4vp_nonce,
            iat: now,
        }),
        HashAlg::Sha256,
    )
    .unwrap();

    // 4. direct_post.jwt: vp_token + state, JWE-encrypted to the
    //    request's ephemeral key, POSTed to the response_uri.
    let body = serde_json::to_vec(&json!({
        "vp_token": { "pid": [presentation] },
        "state": oid4vp_state,
    }))
    .unwrap();
    let jwe = siros_issuer_core::response::encrypt_response(
        &enc_pub,
        &body,
        Some(&enc_kid),
        jose_rs::algorithm::JweEncryption::A128GCM,
    )
    .unwrap();
    let reply: Value = client
        .post(&response_uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("response={}", urlencoding::encode(&jwe)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reply["next"], "complete", "the walk completed: {reply}");
    let offer = &reply["credential_offers"][0];
    assert_eq!(offer["credential"], "urn:eudi:ehic:1");
    // The offer URI points at the issuer's configured base — rewritten
    // to the spawned issuer's port for the wallet leg.
    let offer_uri = offer["offer_uri"]
        .as_str()
        .unwrap()
        .replace(ISSUER_BASE, issuer_url.trim_end_matches('/'));
    let deep_link = offer["deep_link"]
        .as_str()
        .unwrap()
        .replace(ISSUER_BASE, issuer_url.trim_end_matches('/'));

    // 5. The wallet fetches the offer (the offer URI is the bearer) and
    //    redeems the pre-authorized grant at the issuer's own surface.
    let offer_path = offer_uri.trim_start_matches(&issuer_url).to_owned();
    let offer_response = client
        .get(format!("{issuer_url}{offer_path}"))
        .send()
        .await
        .unwrap();
    let offer_status = offer_response.status();
    let offer_text = offer_response.text().await.unwrap();
    let offer: Value = serde_json::from_str(&offer_text)
        .unwrap_or_else(|_| panic!("the offer (HTTP {offer_status}): {offer_text}"));
    let code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .unwrap_or_else(|| panic!("the pre-authorized grant, offer: {offer}"));

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
    let token_response = client
        .post(format!("{issuer_url}/token"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_owned(),
            ),
            ("pre-authorized_code", code.to_owned()),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
            ),
            ("client_assertion", client_assertion),
        ])
        .send()
        .await
        .unwrap();
    let token_status = token_response.status();
    let token_text = token_response.text().await.unwrap();
    let token: Value = serde_json::from_str(&token_text)
        .unwrap_or_else(|_| panic!("the token (HTTP {token_status}): {token_text}"));
    assert!(
        token["access_token"].is_string(),
        "the token answered: {token}"
    );
    let c_nonce = token["c_nonce"].as_str().unwrap().to_owned();

    // 6. Proof + credential: the EHIC, its subject the PID's verified
    //    claims (the definition's declarative derivation).
    let wallet_key = ec_key();
    let proof = proof_jwt(&wallet_key, &Url::parse(ISSUER_BASE).unwrap(), &c_nonce);
    let credential: Value = client
        .post(format!("{issuer_url}/credential"))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .json(&json!({
            "credential_configuration_id": "urn:eudi:ehic:1",
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ehic = credential["credentials"][0]["credential"]
        .as_str()
        .expect("the EHIC");

    // 7. The oracle: the EHIC verifies in verifier-core with the
    //    issuer's key, and its claims are the PID's.
    use siros_verifier_core::sdjwt::{HolderBinding, StaticKey, VerifyParams};
    let verified = siros_verifier_core::sdjwt::verify(
        ehic,
        &StaticKey(
            siros_issuer_core::signer::Signer::public_jwk(&issuer_signer)
                .expect("the issuer's public key"),
        ),
        &VerifyParams::new(now_unix(), HolderBinding::NotRequired),
    )
    .expect("the EHIC verifies in verifier-core");
    assert_eq!(verified.vct, "urn:eudi:ehic:1");
    assert_eq!(verified.claims["given_name"], "Presented");
    assert_eq!(verified.claims["family_name"], "Subject");
    assert_eq!(verified.claims["birth_date"], "1999-12-31");

    // The flow instance is completed; a status read shows the
    // definition's digest (the PDP-evidence identity).
    let status: Value = client
        .get(format!("{flow_url}/flows/{instance}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["state"], "completed");
    assert!(
        status["definition_digest"]
            .as_str()
            .is_some_and(|digest| !digest.is_empty()),
        "the digest rides the instance"
    );
    // The status is clear-data only: no claim values (§10).
    let raw = status.to_string();
    assert!(!raw.contains("Presented"), "no subject data in status");

    // The allocator recorded the EHIC's status index (a real index,
    // not the flow's bookkeeping).
    assert_eq!(allocator.next_index.load(Ordering::SeqCst), 4);

    // The deep link carries the same offer (the same-device carrier).
    assert!(
        deep_link.starts_with("openid-credential-offer://?credential_offer_uri="),
        "{deep_link}"
    );
}
