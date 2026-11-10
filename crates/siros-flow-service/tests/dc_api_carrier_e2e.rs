//! The DC API carrier (§7, the P-bw2 row's remainder): a
//! `presentation` step naming `carrier: dc_api` arms the W3C Digital
//! Credentials API shape — verifier-core's `create_dc_api_request`,
//! whose holder-binding audience is the calling page's ORIGIN (the
//! DC API handover `origin:<origin>`, `OpenID4VPDCAPIHandover`), not
//! the redirect flow's `client_id`.
//!
//! What changes with the carrier (and nothing else — §7: "the step's
//! semantics do not change with the carrier"):
//!
//! - the reply envelope marks `carrier: "dc_api"` so a front-end hands
//!   the request object to `navigator.credentials.get({digital:
//!   {requests: [{protocol: "openid4vp", data: <request>}]}})` instead
//!   of opening a URI (vc's `digital-credentials.js` / `dc-api.js`,
//!   the ported front-end shape);
//! - the request's `response_mode` is `dc_api.jwt`;
//! - the wallet binds its key-binding proof to the ORIGIN.
//!
//! The response path is OID4VP's own: the `data` the wallet returned
//! POSTs to the `response_uri` — the same `direct_post`-style body,
//! the same sealed-session unseal and `process_response`.
//!
//! The negative proves the origin binding is real: a wallet binding
//! to the redirect flow's audience (`client_id`) is refused — a DC API
//! response cannot be replayed into a redirect context and vice
//! versa.
//!
//! Sources of truth: verifier-core `create_dc_api_request` (the
//! response mode + origin discipline, the independent-vector handover
//! test), vc's front-end (the `credentials.get` envelope shape).

use std::sync::Arc;

use serde_json::{json, Value};

use siros_flow_core::bind::BindRegistry;
use siros_flow_service::state::FlowServiceState;
use siros_flow_service::store::MemoryFlowStore;
use siros_flow_service::IssuerCoreClient;

const ISSUER_BASE: &str = "http://127.0.0.1:8080";

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

/// Spawn the flow service over a test-local definitions dir (the
/// shipped `flows/` stays the reviewed business set; the carrier is
/// vocabulary, exercised here by its own definition).
async fn spawn_flow(definitions_dir: &str) -> String {
    let definitions = FlowServiceState::load_definitions(definitions_dir).unwrap();
    let (signer, private) = test_signer("test-flow-key");
    let _ = signer;
    let client = IssuerCoreClient::new(
        url::Url::parse("http://127.0.0.1:9").unwrap(),
        "http://127.0.0.1:9".to_owned(),
        "https://flow.example.org/".to_owned(),
        {
            let path =
                std::env::temp_dir().join(format!("dc-api-integrator-{}.jwk", std::process::id()));
            let key = jose_rs::jwk::generate_ec("P-256").unwrap();
            std::fs::write(&path, serde_json::to_string(&key).unwrap()).unwrap();
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
        public_url: url::Url::parse(ISSUER_BASE).unwrap(),
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

/// A definitions dir carrying exactly the DC API smoke flow.
fn write_definitions() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("dc-api-flows-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dc-api-smoke.yaml"),
        r#"
# The carrier's own acceptance flow: a presentation whose carrier the
# STEP names (§7) — not the deployment default — over the fixture PID.
flow: dc-api-smoke
language_version: 1
description: >
  The DC API carrier smoke: one PID presentation, the request handed
  to navigator.credentials.get, the response POSTed back to the
  response_uri.
steps:
  - presentation:
      id: present-pid
      carrier: dc_api
      request:
        - id: pid
          format: dc+sd-jwt
          meta: { vct_values: ["urn:eudi:pid:1"] }
          claims:
            - { path: [given_name] }
            - { path: [family_name] }
      require: [pid]
"#,
    )
    .unwrap();
    dir
}

fn now_unix() -> i64 {
    siros_issuer_service::status::now_unix()
}

/// Read the request object + envelope facts a front-end consumes.
async fn start_and_read(
    client: &reqwest::Client,
    flow_url: &str,
) -> (Value, String, String, String) {
    let response = client
        .post(format!("{flow_url}/flows/dc-api-smoke/start"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    let start: Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| panic!("the start reply (HTTP {status}): {text}"));
    assert_eq!(
        start["carrier"], "dc_api",
        "the envelope marks the carrier: {start}"
    );
    let jar = start["authorization_request"].as_str().unwrap().to_owned();
    let instance = start["instance"].as_str().unwrap().to_owned();
    let payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        payload["response_mode"], "dc_api.jwt",
        "the DC API response mode: {payload}"
    );
    let response_uri = start["response_uri"]
        .as_str()
        .unwrap()
        .replace(ISSUER_BASE, flow_url.trim_end_matches('/'));
    (start, jar, instance, response_uri)
}

#[tokio::test]
async fn the_dc_api_carrier_binds_the_response_to_the_origin() {
    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, IssueSpec, KbSpec, Seg};

    let definitions = write_definitions();
    let flow_url = spawn_flow(definitions.to_str().unwrap()).await;
    let client = reqwest::Client::new();

    // The walk: start once, read everything the front-end consumes.
    let (_, jar, instance, response_uri) = start_and_read(&client, &flow_url).await;
    let payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let oid4vp_nonce = payload["nonce"].as_str().unwrap().to_owned();
    let oid4vp_state = payload["state"].as_str().unwrap().to_owned();
    let enc_pub: jose_rs::jwk::Jwk =
        serde_json::from_value(payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let enc_kid = enc_pub.kid.clone().unwrap();

    // The wallet: a PID, key-bound to the ORIGIN (the DC API
    // handover — not the redirect flow's client_id).
    let (issuer_cert, issuer_key) = testutil::self_signed_ec("pid-issuer.example", "ES256");
    let holder = testutil::ec_jwk("ES256", "holder");
    let now = now_unix();
    let mut spec = IssueSpec::new(json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "given_name": "Origin",
        "family_name": "Bound",
    }));
    spec.holder_pub = Some(testutil::public_of(&holder));
    spec.x5c_der = vec![issuer_cert];
    spec.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    let issued = testutil::issue(&issuer_key, &spec).unwrap();
    let audience = format!("origin:{ISSUER_BASE}");
    let presentation = testutil::present(
        &issued,
        &[0, 1],
        Some(KbSpec {
            holder: &holder,
            aud: &audience,
            nonce: &oid4vp_nonce,
            iat: now,
        }),
        HashAlg::Sha256,
    )
    .unwrap();

    // The DigitalCredential's data POSTs back (the front-end relay —
    // the same direct_post-style body).
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
async fn the_redirect_audience_is_refused_over_the_dc_api_carrier() {
    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, IssueSpec, KbSpec, Seg};

    let definitions = write_definitions();
    let flow_url = spawn_flow(definitions.to_str().unwrap()).await;
    let client = reqwest::Client::new();

    let (start, _, _, response_uri) = start_and_read(&client, &flow_url).await;
    let jar = start["authorization_request"].as_str().unwrap().to_owned();
    let payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let oid4vp_nonce = payload["nonce"].as_str().unwrap().to_owned();
    let oid4vp_state = payload["state"].as_str().unwrap().to_owned();
    // The redirect flow's audience: the client_id (x509_hash scheme).
    let redirect_audience = payload["client_id"].as_str().unwrap().to_owned();
    let enc_pub: jose_rs::jwk::Jwk =
        serde_json::from_value(payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let enc_kid = enc_pub.kid.clone().unwrap();

    let (issuer_cert, issuer_key) = testutil::self_signed_ec("pid-issuer.example", "ES256");
    let holder = testutil::ec_jwk("ES256", "holder");
    let now = now_unix();
    let mut spec = IssueSpec::new(json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "given_name": "Wrong",
        "family_name": "Audience",
    }));
    spec.holder_pub = Some(testutil::public_of(&holder));
    spec.x5c_der = vec![issuer_cert];
    spec.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    let issued = testutil::issue(&issuer_key, &spec).unwrap();
    let presentation = testutil::present(
        &issued,
        &[0, 1],
        Some(KbSpec {
            holder: &holder,
            aud: &redirect_audience,
            nonce: &oid4vp_nonce,
            iat: now,
        }),
        HashAlg::Sha256,
    )
    .unwrap();

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
        .unwrap_or_else(|_| panic!("the refusal (HTTP {reply_status}): {reply_text}"));
    assert_ne!(
        reply["next"], "complete",
        "the wrong audience refused: {reply}"
    );
    assert!(
        reply_text.to_lowercase().contains("aud"),
        "the refusal names the audience check: {reply_text}"
    );
}
