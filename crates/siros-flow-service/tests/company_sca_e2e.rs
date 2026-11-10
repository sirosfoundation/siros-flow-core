//! The company-bound SCA end-to-end (P-bw2's exit criterion, design
//! §2.1 flow 1): **one transaction, two credential queries** — the
//! `company-sca` DEFINITION drives the whole journey, the wallet
//! presents a PID and a PoA together, the names-comparison binds
//! (labelled probabilistic, §14 Q11 resolved), and the SCA issues
//! over the PID's claims merged with the company from the PoA.
//!
//! The path:
//!
//! 1. `POST /flows/company-sca/start` (the caller's two rules from
//!    the same session record ride flow INPUTS) → the signed OID4VP
//!    request whose DCQL carries BOTH credential queries.
//! 2. The wallet holds a PID (id, given_name, family_name) and a PoA
//!    (attorney_full_name, company_statutory_full_name), issued by
//!    two different test issuers — and presents BOTH in one
//!    `vp_token` map, one `direct_post.jwt` POST.
//! 3. verifier-core verifies each; the driver adopts both results
//!    and runs the two `rule-match` binds: the PoA's attorney is the
//!    caller's attorney, the PID's subject is the caller's subject —
//!    both rules from the same session record, so agreeing is the
//!    caller's names-comparison (honest label: probabilistic, §8.2).
//! 4. The SCA issues over the merged subject (the PID's identity
//!    claims + the PoA's company); the wallet redeems the offer and
//!    the SCA verifies with exactly those claims.
//!
//! The negative is the same flow with the WRONG attorney: the
//! names-comparison refuses (fail-closed) and the instance dies
//! `failed` — binding is math that gates, never a logged observation.
//!
//! Sources of truth: the multi-credential DCQL/response shapes
//! (verifier-core `process_response` — every query id answered, no
//! unrequested ids), vc's `IdentityMatch` (rule-match via the
//! issuer-core port), the OID4VCI offer/token/credential traffic
//! (issuer-core's conformance-proven pre-authorized path).

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

// ─── The service shapes (the ehic e2e's, reused) ───────────────────────────

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
        {
            // Unique per spawn: tests in this binary run concurrently
            // and each writes its own file (a shared name races —
            // one truncates while another reads).
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
        public_url: Url::parse("http://127.0.0.1:8080").unwrap(),
        presentation_ttl_seconds: 300,
        default_carrier: siros_flow_core::language::Carrier::Deeplink,
        retention_after_final_seconds: 3_600,
        bind_registry: BindRegistry::standard(),
        token_registry: siros_flow_service::plugins::TokenRegistry::new(),
        fetch_registry: siros_flow_service::plugins::FetchRegistry::new(),
    });
    let app = siros_flow_service::http::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

// ─── Wallet-side helpers ────────────────────────────────────────────────────

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

// ─── The flow ───────────────────────────────────────────────────────────────

/// The caller's two rules, from ONE session record: the session
/// knows the representative is "Anna Andahl" — the PoA must name her
/// as attorney, the PID must be hers. Both rules arriving from the
/// same record is the names-comparison; the definition names
/// rule-match, so the flow states its evidence is probabilistic
/// (§8.2).
fn start_body(attorney: &str) -> Value {
    json!({
        "attorney_rule": { "claims": { "attorney_full_name": { "equals": attorney } } },
        "subject_rule": { "claims": {
            "given_name": { "equals": "Anna" },
            "family_name": { "equals": "Andahl" }
        }}
    })
}

#[tokio::test]
async fn one_transaction_two_credentials_the_company_sca_end_to_end() {
    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, IssueSpec, KbSpec, Seg};

    let (integrator_signer, integrator_private) = test_signer("flow-integrator-key");
    let _ = integrator_signer;
    let (issuer_url, issuer_signer) = spawn_issuer(&integrator_private.to_public_jwk()).await;
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

    // 1. Start the flow — the caller's rules ride the inputs.
    let start_response = client
        .post(format!("{flow_url}/flows/company-sca/start"))
        .json(&start_body("Anna Andahl"))
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
    assert!(instance.starts_with("company-sca_"));

    // 2. The wallet reads the request: ONE DCQL carrying BOTH
    //    credential queries — the multi-query transaction.
    let jar_payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let queries = jar_payload["dcql_query"]["credentials"]
        .as_array()
        .expect("the DCQL credential queries");
    assert_eq!(
        queries.len(),
        2,
        "one transaction, two queries: {queries:?}"
    );
    let ids: Vec<&str> = queries.iter().map(|q| q["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"pid") && ids.contains(&"poa"), "{ids:?}");
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

    // 3. The wallet holds TWO credentials from DIFFERENT issuers —
    //    the PID (id, given_name, family_name) and the WE BUILD PoA
    //    naming its attorney — and presents BOTH.
    let (pid_issuer_cert, pid_issuer_key) = testutil::self_signed_ec("pid-issuer.example", "ES256");
    let (poa_issuer_cert, poa_issuer_key) = testutil::self_signed_ec("poa-issuer.example", "ES256");
    let holder = testutil::ec_jwk("ES256", "holder");
    let now = now_unix();

    let mut pid_spec = IssueSpec::new(json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "id": "pid-7f3e",
        "given_name": "Anna",
        "family_name": "Andahl",
        "birthdate": "1985-05-05",
    }));
    pid_spec.holder_pub = Some(testutil::public_of(&holder));
    pid_spec.x5c_der = vec![pid_issuer_cert];
    pid_spec.conceal = vec![
        vec![Seg::Key("id")],
        vec![Seg::Key("given_name")],
        vec![Seg::Key("family_name")],
        vec![Seg::Key("birthdate")],
    ];
    let issued_pid = testutil::issue(&pid_issuer_key, &pid_spec).unwrap();

    let mut poa_spec = IssueSpec::new(json!({
        "iss": "https://poa-issuer.example",
        "vct": "urn:ewb:poa:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "attorney_full_name": "Anna Andahl",
        "company_statutory_full_name": "Example AB (publ)",
        "scope_of_representation": "sign applications",
    }));
    poa_spec.holder_pub = Some(testutil::public_of(&holder));
    poa_spec.x5c_der = vec![poa_issuer_cert];
    poa_spec.conceal = vec![
        vec![Seg::Key("attorney_full_name")],
        vec![Seg::Key("company_statutory_full_name")],
        vec![Seg::Key("scope_of_representation")],
    ];
    let issued_poa = testutil::issue(&poa_issuer_key, &poa_spec).unwrap();

    // One wallet, one key-binding audience, both presentations.
    let kb = |issued: &testutil::Issued, select: &[usize]| {
        testutil::present(
            issued,
            select,
            Some(KbSpec {
                holder: &holder,
                aud: &oid4vp_client_id,
                nonce: &oid4vp_nonce,
                iat: now,
            }),
            HashAlg::Sha256,
        )
        .unwrap()
    };
    let pid_presentation = kb(&issued_pid, &[0, 1, 2, 3]);
    let poa_presentation = kb(&issued_poa, &[0, 1, 2]);

    // 4. direct_post.jwt: ONE POST carrying BOTH credentials —
    //    vp_token keyed by query id.
    let body = serde_json::to_vec(&json!({
        "vp_token": { "pid": [pid_presentation], "poa": [poa_presentation] },
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
    let reply_response = client
        .post(&response_uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("response={}", urlencoding::encode(&jwe)))
        .send()
        .await
        .unwrap();
    let reply_status = reply_response.status();
    let reply_text = reply_response.text().await.unwrap();
    let reply: Value = serde_json::from_str(&reply_text)
        .unwrap_or_else(|_| panic!("the flow reply (HTTP {reply_status}): {reply_text}"));
    assert_eq!(reply["next"], "complete", "the walk completed: {reply}");
    let offer = &reply["credential_offers"][0];
    assert_eq!(offer["credential"], "urn:ewb:sca:1");
    let offer_uri = offer["offer_uri"]
        .as_str()
        .unwrap()
        .replace(ISSUER_BASE, issuer_url.trim_end_matches('/'));

    // 5. The wallet redeems the SCA offer at the issuer's own
    //    OID4VCI surface (offer → token with client auth → proof →
    //    the credential).
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

    let wallet_key = ec_key();
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
            "credential_configuration_id": "urn:ewb:sca:1",
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sca = credential["credentials"][0]["credential"]
        .as_str()
        .expect("the SCA");

    // 6. The oracle: the SCA verifies and its claims are the MERGED
    //    subject — the PID's identity claims + the company from the
    //    PoA (the definition's declarative subject).
    use siros_verifier_core::sdjwt::{HolderBinding, StaticKey, VerifyParams};
    let verified = siros_verifier_core::sdjwt::verify(
        sca,
        &StaticKey(
            siros_issuer_core::signer::Signer::public_jwk(&issuer_signer)
                .expect("the issuer's public key"),
        ),
        &VerifyParams::new(now_unix(), HolderBinding::NotRequired),
    )
    .expect("the SCA verifies in verifier-core");
    assert_eq!(verified.vct, "urn:ewb:sca:1");
    assert_eq!(verified.claims["given_name"], "Anna");
    assert_eq!(verified.claims["family_name"], "Andahl");
    assert_eq!(
        verified.claims["company"], "Example AB (publ)",
        "the SCA's claims: {:?}",
        verified.claims
    );
    // The catalog's claim building filtered to the SCA schema's
    // paths: the PID's id/birthdate never leak into the SCA.
    assert!(
        verified.claims.get("id").is_none() && verified.claims.get("birthdate").is_none(),
        "the schema filter holds: {:?}",
        verified.claims
    );

    // The instance is completed.
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
async fn the_wrong_attorney_refuses_the_flow_fail_closed() {
    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, IssueSpec, KbSpec, Seg};

    let (integrator_signer, integrator_private) = test_signer("flow-integrator-key");
    let _ = integrator_signer;
    let (issuer_url, _issuer_signer) = spawn_issuer(&integrator_private.to_public_jwk()).await;
    let definitions_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../flows")
        .display()
        .to_string();
    let issuer_identifier =
        siros_issuer_core::oid4vci::issuer_identifier(&Url::parse(ISSUER_BASE).unwrap()).to_owned();
    let flow_url = spawn_flow(
        &definitions_dir,
        &issuer_url,
        issuer_identifier,
        integrator_private,
    )
    .await;

    let client = reqwest::Client::new();

    // The session's record names ANOTHER attorney than the PoA does:
    // the names-comparison refuses — binding is a gate, never a
    // logged observation (§8.2 determinism: no best-effort).
    let start_response = client
        .post(format!("{flow_url}/flows/company-sca/start"))
        .json(&start_body("Birgitta Birgersson"))
        .send()
        .await
        .unwrap();
    let start_text = start_response.text().await.unwrap();
    let start: Value = serde_json::from_str(&start_text).unwrap();
    let jar = start["authorization_request"].as_str().unwrap().to_owned();
    let jar_payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
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

    // The same wallet: the PoA still names Anna Andahl as attorney.
    let (pid_issuer_cert, pid_issuer_key) = testutil::self_signed_ec("pid-issuer.example", "ES256");
    let (poa_issuer_cert, poa_issuer_key) = testutil::self_signed_ec("poa-issuer.example", "ES256");
    let holder = testutil::ec_jwk("ES256", "holder");
    let now = now_unix();
    let mut pid_spec = IssueSpec::new(json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "id": "pid-7f3e",
        "given_name": "Anna",
        "family_name": "Andahl",
        "birthdate": "1985-05-05",
    }));
    pid_spec.holder_pub = Some(testutil::public_of(&holder));
    pid_spec.x5c_der = vec![pid_issuer_cert];
    pid_spec.conceal = vec![
        vec![Seg::Key("id")],
        vec![Seg::Key("given_name")],
        vec![Seg::Key("family_name")],
        vec![Seg::Key("birthdate")],
    ];
    let issued_pid = testutil::issue(&pid_issuer_key, &pid_spec).unwrap();
    let mut poa_spec = IssueSpec::new(json!({
        "iss": "https://poa-issuer.example",
        "vct": "urn:ewb:poa:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "attorney_full_name": "Anna Andahl",
        "company_statutory_full_name": "Example AB (publ)",
        "scope_of_representation": "sign applications",
    }));
    poa_spec.holder_pub = Some(testutil::public_of(&holder));
    poa_spec.x5c_der = vec![poa_issuer_cert];
    poa_spec.conceal = vec![
        vec![Seg::Key("attorney_full_name")],
        vec![Seg::Key("company_statutory_full_name")],
        vec![Seg::Key("scope_of_representation")],
    ];
    let issued_poa = testutil::issue(&poa_issuer_key, &poa_spec).unwrap();

    let kb = |issued: &testutil::Issued, select: &[usize]| {
        testutil::present(
            issued,
            select,
            Some(KbSpec {
                holder: &holder,
                aud: &oid4vp_client_id,
                nonce: &oid4vp_nonce,
                iat: now,
            }),
            HashAlg::Sha256,
        )
        .unwrap()
    };
    let body = serde_json::to_vec(&json!({
        "vp_token": {
            "pid": [kb(&issued_pid, &[0, 1, 2, 3])],
            "poa": [kb(&issued_poa, &[0, 1, 2])]
        },
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
    let reply_response = client
        .post(&response_uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("response={}", urlencoding::encode(&jwe)))
        .send()
        .await
        .unwrap();
    let reply_status = reply_response.status();
    let reply_text = reply_response.text().await.unwrap();
    let reply: Value = serde_json::from_str(&reply_text)
        .unwrap_or_else(|_| panic!("the flow reply (HTTP {reply_status}): {reply_text}"));

    // Fail-closed: the mismatch refuses the walk — the code is
    // stable and the message names the rule's paths, never values.
    assert_eq!(reply["error"], "bind_mismatch", "the refusal: {reply}");
    let message = reply["error_description"]
        .as_str()
        .or(reply["message"].as_str())
        .unwrap_or_default();
    assert!(
        message.contains("attorney_full_name"),
        "the refusal names the rule's path: {message}"
    );
    assert!(
        !message.contains("Anna") && !message.contains("Birgitta"),
        "never values: {message}"
    );
    assert_ne!(reply["next"], "complete");

    // The instance is dead — failed, not completed; no SCA was issued.
    let instance = reply["instance"].as_str().unwrap_or_default().to_owned();
    let instance = if instance.is_empty() {
        start["instance"].as_str().unwrap().to_owned()
    } else {
        instance
    };
    let status: Value = client
        .get(format!("{flow_url}/flows/{instance}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["state"], "failed", "the flow died: {status}");
}
