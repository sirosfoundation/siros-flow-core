//! The embedded-issuer e2e (the gdc deployment's shape): ONE process,
//! ONE port — the flow service embeds a complete issuer and stands as
//! an additional trusted issuer AND verifier. The same journey as
//! ehic_e2e (start → present PID → offer → token → credential →
//! verifier-core oracle), but every surface — the flow API, the
//! issuer backend, and the issuer's own OID4VCI wallet surface
//! (/.well-known, offer, token, credential, /jwks) — answers on one
//! origin, exactly as the Fly deployment serves it.

use std::sync::atomic::Ordering;

use serde_json::{json, Value};
use siros_flow_service::app::build;
use siros_flow_service::config::Config;

// NOTE: no PDP double here — the test drives the REAL AuthZEN client
// path against an in-test evaluation endpoint (the same wire gdc's
// go-trust speaks), so the deployment's trust path is what runs.

fn key_file(tag: &str) -> (String, jose_rs::jwk::Jwk) {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
    jwk.alg = Some("ES256".to_owned());
    jwk.kid = Some(format!("{tag}-key"));
    let path = std::env::temp_dir().join(format!("flow-{tag}-{}.jwk", std::process::id()));
    std::fs::write(&path, serde_json::to_string(&jwk).unwrap()).unwrap();
    (path.display().to_string(), jwk)
}

fn cert_chain(private: &jose_rs::jwk::Jwk, host: &str) -> String {
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
    // SAN DNS = the host (the additional-verifier identity; CN is not
    // what trust rides on).
    let params = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
    let chain = params.self_signed(&kp).unwrap();
    let path = std::env::temp_dir().join(format!("flow-chain-{}.pem", std::process::id()));
    std::fs::write(&path, chain.pem()).unwrap();
    path.display().to_string()
}

#[tokio::test]
async fn one_service_one_port_the_whole_journey() {
    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, IssueSpec, KbSpec, Seg};

    // The keys: the verifier role's (request objects, x5c with the
    // service host) and the embedded issuer's (credentials — a
    // SEPARATE identity, the siros-verifier rule).
    let (verifier_key_path, verifier_key) = key_file("verifier");
    let (issuer_key_path, issuer_key) = key_file("issuer-signing");
    let (integrator_key_path, _integrator_key) = key_file("integrator");
    let chain_path = cert_chain(&verifier_key, "flow.local");

    let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .display()
        .to_string();
    let flows = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../flows")
        .display()
        .to_string();

    // A permit-everything AuthZEN evaluation endpoint (the same wire
    // go-trust speaks: POST the query, answer the decision). The gdc
    // deployment points at the REAL go-trust; the test drives the
    // client's protocol path, not a bypassed PDP.
    let pdp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pdp_addr = pdp_listener.local_addr().unwrap();
    let pdp_url = format!("http://{pdp_addr}/evaluation");
    tokio::spawn(async move {
        let pdp = axum::Router::new().route(
            "/evaluation",
            axum::routing::post(|| async { axum::Json(serde_json::json!({"decision": "Permit"})) }),
        );
        axum::serve(pdp_listener, pdp).await.unwrap();
    });

    // A status-service stub (the siros-status-service wire: POST
    // /token, POST /allocate, PATCH /status/{id}/{n} — the conformance
    // fixture's shape, fail-open AS; local-test only).
    let status_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let status_addr = status_listener.local_addr().unwrap();
    let status_base = format!("http://{status_addr}");
    let status_next = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
    let status_base_for_handler = status_base.clone();
    tokio::spawn(async move {
        let next = status_next.clone();
        let list_base = status_base_for_handler.clone();
        let app = axum::Router::new()
            .route(
                "/token",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({
                        "access_token": "stub-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }))
                }),
            )
            .route(
                "/allocate",
                axum::routing::post(move || {
                    let next = next.clone();
                    let list_base = list_base.clone();
                    async move {
                        let index = next.fetch_add(1, Ordering::SeqCst);
                        axum::Json(serde_json::json!({
                            "list_url": format!("{list_base}/lists/stub"),
                            "index": index,
                            "exp": serde_json::Value::Null,
                        }))
                    }
                }),
            )
            .route(
                "/status/{id}/{index}",
                axum::routing::patch(|| async { axum::http::StatusCode::NO_CONTENT }),
            );
        axum::serve(status_listener, app).await.unwrap();
    });

    // Bind FIRST: the service's public_url must be the real address
    // (the one-URL rule — the response_uri and the issuer's
    // credential_issuer both derive from it).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");

    let config = Config::from_toml_str(&format!(
        r#"
pdp = "{pdp_url}"

[service]
public_url = "{base}"

[definitions]
dir = "{flows}"

[signing]
jwk_path = "{verifier_key_path}"
cert_chain_path = "{chain_path}"

[issuer]
status_mode = "service"
integrator_id = "https://flow.local/integrator"
integrator_key_path = "{integrator_key_path}"

# The embedded issuer: a complete siros-issuer-service config — the
# additional trusted issuer's own identity.
[embedded.issuer]
url = "{base}"

[embedded.catalog]
static_dir = "{testdata}/ts11"
refresh_seconds = 0

[embedded.signing]
jwk_path = "{issuer_key_path}"

[embedded.status_service]
as_url = "{status_base}"
ingestion_url = "{status_base}"

[embedded.issuance]
credential_validity_seconds = 3600

# The wallet client the e2e drives (the §12.2-resolved token surface).
[embedded.authorization.clients.suite-wallet]
jwks = [{{ kty = "EC", x = "MpY3glbcq9njtQLM1hCREOrfQqPgOKyGOl7xkMwHsSI", y = "ZDT-zr7lt2R12MaFbXuapq4eXS5hprKjegb5yq3UlXE", crv = "P-256", kid = "test-client-key-1", alg = "ES256", use = "sig" }}]
allow_any_redirect_uri = false
"#
    ))
    .unwrap();

    let app = build(&config).await.unwrap();
    assert_eq!(app.embedded_issuer.as_deref(), Some(base.as_str()));
    tokio::spawn(async move {
        axum::serve(listener, app.router).await.unwrap();
    });

    let client = reqwest::Client::new();

    // The issuer's OID4VCI well-known answers on the same origin (the
    // wallet discovers the additional issuer here).
    let metadata: Value = client
        .get(format!("{base}/.well-known/openid-credential-issuer"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["credential_issuer"], base);
    assert!(
        metadata["credential_configurations_supported"]
            .as_object()
            .is_some_and(|c| c.contains_key("urn:eudi:ehic:1")),
        "the embedded issuer advertises the EHIC: {metadata}"
    );

    // The whole PID→EHIC journey, every hop on this one origin.
    let start: Value = client
        .post(format!("{base}/flows/ehic-pid-presentation/start"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jar = start["authorization_request"]
        .as_str()
        .expect("the request object")
        .to_owned();
    // The response_uri resolves to THIS origin (one port).
    assert!(
        start["response_uri"].as_str().unwrap().starts_with(&base),
        "{}",
        start["response_uri"]
    );

    // The verifier role's x5c rides the request object's JOSE HEADER
    // (the additional-trusted-verifier identity — the wallet/PDP trust
    // the request-signing leaf by this chain).
    let jar_header: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(
        jar_header["x5c"]
            .as_array()
            .is_some_and(|chain| !chain.is_empty()),
        "the request object's header carries the verifier's x5c: {jar_header}"
    );
    let jar_payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let oid4vp_nonce = jar_payload["nonce"].as_str().unwrap().to_owned();
    let oid4vp_state = jar_payload["state"].as_str().unwrap().to_owned();
    let oid4vp_client_id = jar_payload["client_id"].as_str().unwrap().to_owned();
    let response_uri = jar_payload["response_uri"].as_str().unwrap().to_owned();
    let enc_pub: jose_rs::jwk::Jwk =
        serde_json::from_value(jar_payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let enc_kid = enc_pub.kid.clone().unwrap();

    // The wallet's PID (an x5c-carried third-party PID, as ever).
    let (pid_issuer_cert, pid_issuer_key) = testutil::self_signed_ec("pid-issuer.example", "ES256");
    let holder = testutil::ec_jwk("ES256", "holder");
    let now = siros_issuer_service::status::now_unix();
    let mut spec = IssueSpec::new(json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "given_name": "Embedded",
        "family_name": "Flow",
        "birth_date": "2000-01-01",
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
        .unwrap_or_else(|_| panic!("the flow reply (HTTP {reply_status}): {reply_text}"));
    assert_eq!(reply["next"], "complete", "the flow reply: {reply}");

    // The offer — on the same origin; redeem at the same origin.
    let offer = &reply["credential_offers"][0];
    assert_eq!(offer["credential"], "urn:eudi:ehic:1");
    let offer_uri = offer["offer_uri"].as_str().unwrap().to_owned();
    assert!(offer_uri.starts_with(&base), "{offer_uri}");

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
        .unwrap()
        .to_owned();

    // The token hop needs client auth (the embedded issuer enforces
    // the §12.2-resolved surface like any other): the test wallet's
    // assertion — registered via the embedded config's client
    // registry? NO: the e2e drives the wallet WITHOUT a registered
    // client by registering the suite-shaped client in the embedded
    // config. Simplest: add it to the config above.
    let token: Value = client
        .post(format!("{base}/token"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_owned(),
            ),
            ("pre-authorized_code", code),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
            ),
            ("client_assertion", wallet_assertion(&base)),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(token["access_token"].is_string(), "the token: {token}");
    let c_nonce = token["c_nonce"].as_str().unwrap().to_owned();

    // Proof + credential: the EHIC, on the same origin.
    let wallet_key = {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".to_owned());
        jwk
    };
    let proof = {
        let mut header = jose_rs::JoseHeader::new("ES256");
        header.typ = Some("openid4vci-proof+jwt".to_owned());
        header.jwk = Some(serde_json::to_value(wallet_key.to_public_jwk()).unwrap());
        let payload = serde_json::to_vec(&json!({
            "iss": "wallet",
            "aud": base,
            "nonce": c_nonce,
            "iat": siros_issuer_service::status::now_unix(),
        }))
        .unwrap();
        let opts = jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true);
        jose_rs::jws::compact::sign_with_jwk_options(&wallet_key, &payload, &header, &opts).unwrap()
    };
    let credential_response = client
        .post(format!("{base}/credential"))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .json(&json!({
            "credential_configuration_id": "urn:eudi:ehic:1",
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap();
    let credential_status = credential_response.status();
    let credential_text = credential_response.text().await.unwrap();
    let credential: Value = serde_json::from_str(&credential_text)
        .unwrap_or_else(|_| panic!("the credential (HTTP {credential_status}): {credential_text}"));
    let ehic = credential["credentials"][0]["credential"]
        .as_str()
        .unwrap_or_else(|| panic!("the EHIC, the credential reply: {credential}"));

    // The oracle: the EHIC verifies with the EMBEDDED issuer's key and
    // carries the PID's claims.
    use siros_verifier_core::sdjwt::{HolderBinding, StaticKey, VerifyParams};
    let verified = siros_verifier_core::sdjwt::verify(
        ehic,
        &StaticKey(issuer_key.to_public_jwk()),
        &VerifyParams::new(
            siros_issuer_service::status::now_unix(),
            HolderBinding::NotRequired,
        ),
    )
    .expect("the EHIC verifies");
    assert_eq!(verified.vct, "urn:eudi:ehic:1");
    assert_eq!(verified.claims["given_name"], "Embedded");
    assert_eq!(verified.claims["family_name"], "Flow");
}

/// The suite-shaped wallet's client assertion (the embedded config
/// registers the suite wallet client in its client registry).
fn wallet_assertion(base: &str) -> String {
    const CLIENT_PRIVATE_JWK: &str = r#"{"kty":"EC","x":"MpY3glbcq9njtQLM1hCREOrfQqPgOKyGOl7xkMwHsSI","y":"ZDT-zr7lt2R12MaFbXuapq4eXS5hprKjegb5yq3UlXE","crv":"P-256","d":"gaknst5YK3n03zh8vvDXA4HydaNQfzYtnC0CiMHADmI","kid":"test-client-key-1","alg":"ES256","use":"sig"}"#;
    let key: jose_rs::jwk::Jwk = serde_json::from_str(CLIENT_PRIVATE_JWK).unwrap();
    let now = siros_issuer_service::status::now_unix();
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some("jwt".to_owned());
    header.kid = key.kid.clone();
    header.jwk = Some(serde_json::to_value(key.to_public_jwk()).unwrap());
    let payload = serde_json::to_vec(&json!({
        "iss": "suite-wallet",
        "sub": "suite-wallet",
        "aud": base,
        "iat": now,
        "exp": now + 300,
    }))
    .unwrap();
    let opts = jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true);
    jose_rs::jws::compact::sign_with_jwk_options(&key, &payload, &header, &opts).unwrap()
}

/// The LOCAL status mode (the embedded default, gdc's path): the
/// in-process list — issuance works without any deployed status
/// service, the credential carries the local list URL, and the list
/// serves as a Status List Token signed by the embedded issuer.
#[tokio::test]
async fn the_local_status_list_serves_the_credentials_it_backs() {
    let (verifier_key_path, verifier_key) = key_file("local-verifier");
    let (issuer_key_path, issuer_key) = key_file("local-issuer-signing");
    let (integrator_key_path, _integrator_key) = key_file("local-integrator");

    let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .display()
        .to_string();
    let flows = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../flows")
        .display()
        .to_string();

    // The verifier role's x5c (verifier-core derives the x509_hash
    // client_id from the leaf — the chain is REQUIRED, local mode or
    // not).
    let chain_path = cert_chain(&verifier_key, "flow.local");

    let pdp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pdp_addr = pdp_listener.local_addr().unwrap();
    let pdp_url = format!("http://{pdp_addr}/evaluation");
    tokio::spawn(async move {
        let pdp = axum::Router::new().route(
            "/evaluation",
            axum::routing::post(|| async { axum::Json(serde_json::json!({"decision": "Permit"})) }),
        );
        axum::serve(pdp_listener, pdp).await.unwrap();
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");

    let config = Config::from_toml_str(&format!(
        r#"
pdp = "{pdp_url}"

[service]
public_url = "{base}"

[definitions]
dir = "{flows}"

[signing]
jwk_path = "{verifier_key_path}"
cert_chain_path = "{chain_path}"

[issuer]
integrator_id = "https://flow.local/integrator"
integrator_key_path = "{integrator_key_path}"

[embedded.issuer]
url = "{base}"

[embedded.catalog]
static_dir = "{testdata}/ts11"
refresh_seconds = 0

[embedded.signing]
jwk_path = "{issuer_key_path}"

[embedded.issuance]
credential_validity_seconds = 3600

[embedded.authorization.clients.suite-wallet]
jwks = [{{ kty = "EC", x = "MpY3glbcq9njtQLM1hCREOrfQqPgOKyGOl7xkMwHsSI", y = "ZDT-zr7lt2R12MaFbXuapq4eXS5hprKjegb5yq3UlXE", crv = "P-256", kid = "test-client-key-1", alg = "ES256", use = "sig" }}]
allow_any_redirect_uri = false
"#
    ))
    .unwrap();

    let app = build(&config).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.router).await.unwrap();
    });

    let client = reqwest::Client::new();

    // The wallet redeems the EHIC offer (the local list backs it).
    let start_response = client
        .post(format!("{base}/flows/ehic-pid-presentation/start"))
        .json(&serde_json::json!({}))
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
    let jar_payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let response_uri = jar_payload["response_uri"].as_str().unwrap().to_owned();
    let enc_pub: jose_rs::jwk::Jwk =
        serde_json::from_value(jar_payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let enc_kid = enc_pub.kid.clone().unwrap();

    // A PID (verifier-core testutil): the PDP permit-everything decides
    // trust either way — the local status mode is what this test runs.
    let (pid_cert, pid_issuer_key) =
        siros_verifier_core::testutil::self_signed_ec("pid-issuer.example", "ES256");
    let holder = siros_verifier_core::testutil::ec_jwk("ES256", "holder");
    let now = siros_issuer_service::status::now_unix();
    let mut spec = siros_verifier_core::testutil::IssueSpec::new(serde_json::json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "given_name": "Local",
        "family_name": "List",
        "birth_date": "2000-01-01",
    }));
    spec.holder_pub = Some(siros_verifier_core::testutil::public_of(&holder));
    spec.x5c_der = vec![pid_cert];
    spec.conceal = vec![
        vec![siros_verifier_core::testutil::Seg::Key("given_name")],
        vec![siros_verifier_core::testutil::Seg::Key("family_name")],
        vec![siros_verifier_core::testutil::Seg::Key("birth_date")],
    ];
    let issued_pid = siros_verifier_core::testutil::issue(&pid_issuer_key, &spec).unwrap();
    let presentation = siros_verifier_core::testutil::present(
        &issued_pid,
        &[0, 1, 2],
        Some(siros_verifier_core::testutil::KbSpec {
            holder: &holder,
            aud: jar_payload["client_id"].as_str().unwrap(),
            nonce: jar_payload["nonce"].as_str().unwrap(),
            iat: now,
        }),
        siros_verifier_core::sdjwt::HashAlg::Sha256,
    )
    .unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "vp_token": { "pid": [presentation] },
        "state": jar_payload["state"].as_str().unwrap(),
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
    assert_eq!(reply["next"], "complete", "the local-mode flow: {reply}");
    let offer = &reply["credential_offers"][0];
    let offer_uri = offer["offer_uri"].as_str().unwrap().to_owned();
    assert!(offer_uri.starts_with(&base));

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
        .unwrap()
        .to_owned();
    let token: Value = client
        .post(format!("{base}/token"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_owned(),
            ),
            ("pre_authorized_code", code),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
            ),
            ("client_assertion", wallet_assertion(&base)),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(token["access_token"].is_string());
    let c_nonce = token["c_nonce"].as_str().unwrap().to_owned();

    let wallet_key = {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".to_owned());
        jwk
    };
    let proof = {
        let mut header = jose_rs::JoseHeader::new("ES256");
        header.typ = Some("openid4vci-proof+jwt".to_owned());
        header.jwk = Some(serde_json::to_value(wallet_key.to_public_jwk()).unwrap());
        let payload = serde_json::to_vec(&serde_json::json!({
            "iss": "wallet",
            "aud": base,
            "nonce": c_nonce,
            "iat": siros_issuer_service::status::now_unix(),
        }))
        .unwrap();
        let opts = jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true);
        jose_rs::jws::compact::sign_with_jwk_options(&wallet_key, &payload, &header, &opts).unwrap()
    };
    let credential: Value = client
        .post(format!("{base}/credential"))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .json(&serde_json::json!({
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
        .unwrap_or_else(|| panic!("the EHIC, the reply: {credential}"))
        .to_owned();

    // The oracle: the EHIC verifies, and the credential CARRIES the
    // local list URL (its status_list.uri resolves on this app).
    use siros_verifier_core::sdjwt::{HolderBinding, StaticKey, VerifyParams};
    let verified = siros_verifier_core::sdjwt::verify(
        &ehic,
        &StaticKey(issuer_key.to_public_jwk()),
        &VerifyParams::new(
            siros_issuer_service::status::now_unix(),
            HolderBinding::NotRequired,
        ),
    )
    .expect("the EHIC verifies");
    assert_eq!(verified.vct, "urn:eudi:ehic:1");
    // The local list serves the token the status_list URI points at.
    let status_uri = verified
        .status
        .as_ref()
        .map(|status| status.uri.clone())
        .expect("the EHIC carries a status list URI");
    let list_path = status_uri.trim_start_matches(&base).to_owned();
    let list: reqwest::Response = client
        .get(format!("{base}{list_path}"))
        .send()
        .await
        .unwrap();
    assert!(
        list.status().is_success(),
        "the local list serves: {status_uri}"
    );
}
