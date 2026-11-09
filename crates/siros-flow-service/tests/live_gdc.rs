//! The LIVE gdc round trip (run explicitly: `cargo test --test live_gdc --
//! --ignored` with `LIVE_GDC_URL`): the whole journey against the DEPLOYED
//! flow service, every trust decision made by gdc's REAL go-trust.
//!
//! 1. Start the `ehic-pid-presentation` flow → the signed OID4VP request.
//! 2. Issue a REAL PID from the flow service's own EMBEDDED issuer (the
//!    additional trusted issuer: backend session → pre-authorized offer →
//!    token (client auth) → credential, the holder key binding it).
//! 3. Present that PID to the flow's response_uri (`direct_post.jwt`) —
//!    verifier-core verifies, gdc's go-trust DECIDES (the issuer identity
//!    is whitelisted in environments/gdc.yaml — trust added, never
//!    disabled).
//! 4. The walk completes: the embedded issuer issues the EHIC over the
//!    PID's claims (the definition's declarative subject) → redeem the
//!    offer → the EHIC verifies with the PID's claims.
//!
//! Local test only (the suite-shaped dev wallet client + the fixture
//! integrator identity); the deployment under test is real.

use serde_json::{json, Value};
use url::Url;

const DEFAULT_URL: &str = "https://sirosid-gdc-flow-core.fly.dev";

/// The suite-shaped dev wallet client's private key (the conformance
/// fixtures' published test key — LOCAL TEST ONLY).
const DEV_WALLET_PRIVATE_JWK: &str = r#"{"kty":"EC","x":"MpY3glbcq9njtQLM1hCREOrfQqPgOKyGOl7xkMwHsSI","y":"ZDT-zr7lt2R12MaFbXuapq4eXS5hprKjegb5yq3UlXE","crv":"P-256","d":"gaknst5YK3n03zh8vvDXA4HydaNQfzYtnC0CiMHADmI","kid":"test-client-key-1","alg":"ES256","use":"sig"}"#;

fn base() -> Url {
    Url::parse(&std::env::var("LIVE_GDC_URL").unwrap_or_else(|_| DEFAULT_URL.to_owned())).unwrap()
}

fn now() -> i64 {
    siros_issuer_service::status::now_unix()
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

fn ec_key() -> jose_rs::jwk::Jwk {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".to_owned());
    jwk
}

/// The RFC 7523 client assertion (the dev wallet, registered in the
/// deployment's embedded client registry).
fn client_assertion(base: &Url) -> String {
    let key: jose_rs::jwk::Jwk = serde_json::from_str(DEV_WALLET_PRIVATE_JWK).unwrap();
    sign_jwt(
        &key,
        "jwt",
        &json!({
            "iss": "suite-wallet",
            "sub": "suite-wallet",
            "aud": base.as_str(),
            "iat": now(),
            "exp": now() + 300,
        }),
        true,
    )
}

async fn post_form(client: &reqwest::Client, url: String, pairs: &[(&str, String)]) -> Value {
    let response = client.post(url).form(pairs).send().await.unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("HTTP {status}: {text}"))
}

async fn post_json(
    client: &reqwest::Client,
    url: String,
    bearer: Option<&str>,
    body: Value,
) -> Value {
    let mut request = client.post(url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let response = request.json(&body).send().await.unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("HTTP {status}: {text}"))
}

/// Redeem a pre-authorized offer at the embedded issuer's own OID4VCI
/// surface: token (client auth) → proof → the credential.
async fn redeem_pre_authorized(
    client: &reqwest::Client,
    base: &Url,
    offer_uri: &str,
    credential_id: &str,
    holder: &jose_rs::jwk::Jwk,
) -> String {
    let offer: Value = client
        .get(offer_uri)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .expect("the pre-authorized grant")
        .to_owned();
    let token = post_form(
        client,
        format!("{base}/token"),
        &[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_owned(),
            ),
            ("pre_authorized_code", code),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
            ),
            ("client_assertion", client_assertion(base)),
        ],
    )
    .await;
    let access_token = token["access_token"]
        .as_str()
        .expect("the access token")
        .to_owned();
    let c_nonce = token["c_nonce"].as_str().expect("the c_nonce").to_owned();
    let proof = sign_jwt(
        holder,
        "openid4vci-proof+jwt",
        &json!({
            "iss": "wallet",
            "aud": base.as_str(),
            "nonce": c_nonce,
            "iat": now(),
        }),
        true,
    );
    let credential = post_json(
        client,
        format!("{base}/credential"),
        Some(&access_token),
        json!({
            "credential_configuration_id": credential_id,
            "proof": { "proof_type": "jwt", "jwt": proof },
        }),
    )
    .await;
    credential["credentials"][0]["credential"]
        .as_str()
        .expect("the credential")
        .to_owned()
}

#[tokio::test]
#[ignore = "the live gdc deployment (LIVE_GDC_URL)"]
async fn the_live_gdc_round_trip() {
    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, Issued, KbSpec};

    let base = base();
    let client = reqwest::Client::new();

    // ── 1. Start the flow ────────────────────────────────────────────────
    let start = post_json(
        &client,
        format!("{base}/flows/ehic-pid-presentation/start"),
        None,
        json!({}),
    )
    .await;
    let jar = start["authorization_request"]
        .as_str()
        .expect("the request object")
        .to_owned();
    let jar_header: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    let jar_payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let response_uri = jar_payload["response_uri"].as_str().unwrap().to_owned();
    let oid4vp_client_id = jar_payload["client_id"].as_str().unwrap().to_owned();
    let oid4vp_nonce = jar_payload["nonce"].as_str().unwrap().to_owned();
    let oid4vp_state = jar_payload["state"].as_str().unwrap().to_owned();
    let enc_pub: jose_rs::jwk::Jwk =
        serde_json::from_value(jar_payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let enc_kid = enc_pub.kid.clone().unwrap();
    assert!(
        jar_header["x5c"].as_array().is_some_and(|c| !c.is_empty()),
        "the verifier's x5c rides the request"
    );

    // ── 2. Issue a REAL PID from the embedded issuer ─────────────────────
    let pid_vct = "urn:eudi:pid:arf-1.8:1";
    let holder = ec_key();

    // The backend session (the integrator surface — the dev wallet client
    // is registered too; the assertion's aud is the issuer identifier).
    let integrator_assertion = sign_jwt(
        &serde_json::from_str::<jose_rs::jwk::Jwk>(DEV_WALLET_PRIVATE_JWK).unwrap(),
        "jwt",
        &json!({
            "iss": "suite-wallet",
            "sub": "suite-wallet",
            "aud": base.as_str(),
            "iat": now(),
            "exp": now() + 300,
        }),
        true,
    );
    let create = post_json(
        &client,
        format!("{base}/api/v1/issuance/sessions"),
        Some(&format!("Bearer {integrator_assertion}")),
        json!({
            "credential": pid_vct,
            "subject": {
                "given_name": "Live",
                "family_name": "Roundtrip",
                "birth_date": "1990-01-01"
            },
            "ttl_seconds": 600,
        }),
    )
    .await;
    let pid_offer_uri = create["offer_uri"]
        .as_str()
        .expect("the offer uri")
        .to_owned();

    let pid = redeem_pre_authorized(&client, &base, &pid_offer_uri, pid_vct, &holder).await;
    assert!(pid.contains('~'), "an SD-JWT with disclosures: {pid}");

    // ── 3. Present the PID to the flow ────────────────────────────────────
    // The wallet discloses every claim the DCQL asked for.
    let mut parts = pid.splitn(2, '~');
    let pid_jwt = parts.next().unwrap().to_owned();
    let disclosures: Vec<String> = pid
        .split('~')
        .skip(1)
        .filter(|d| !d.is_empty() && !d.starts_with("urn:"))
        .map(str::to_owned)
        .collect();
    // The KB-JWT is the last ~-part when it carries a key binding (the
    // issuer-core SD-JWT ends with the KB-JWT segment: jwt~d...~kb).
    let issued = Issued {
        jwt: pid_jwt,
        disclosures,
    };
    let presentation = testutil::present(
        &issued,
        &(0..issued.disclosures.len()).collect::<Vec<_>>(),
        Some(KbSpec {
            holder: &holder,
            aud: &oid4vp_client_id,
            nonce: &oid4vp_nonce,
            iat: now(),
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
    assert_eq!(
        reply["next"], "complete",
        "the live flow completed: {reply}"
    );

    // ── 4. Redeem the EHIC the walk issued ──────────────────────────────
    let offer = &reply["credential_offers"][0];
    assert_eq!(offer["credential"], "urn:eudi:ehic:1");
    let offer_uri = offer["offer_uri"].as_str().unwrap().to_owned();
    let wallet_key = ec_key();
    let ehic =
        redeem_pre_authorized(&client, &base, &offer_uri, "urn:eudi:ehic:1", &wallet_key).await;

    // The oracle: the EHIC's claims are the PID's (the declarative subject).
    use siros_verifier_core::sdjwt::{HolderBinding, StaticKey, VerifyParams};
    let verified = siros_verifier_core::sdjwt::verify(
        &ehic,
        &StaticKey(issuer_core::public_key_of_the_embedded_issuer(&client, &base).await),
        &VerifyParams::new(now(), HolderBinding::NotRequired),
    )
    .expect("the EHIC verifies");
    assert_eq!(verified.vct, "urn:eudi:ehic:1");
    assert_eq!(verified.claims["given_name"], "Live");
    assert_eq!(verified.claims["family_name"], "Roundtrip");
}

/// Fetch the embedded issuer's public JWK from its own JWKS (the verifier
/// role publishes /jwks on the same origin).
mod issuer_core {
    pub async fn public_key_of_the_embedded_issuer(
        client: &reqwest::Client,
        base: &url::Url,
    ) -> jose_rs::jwk::Jwk {
        let jwks: serde_json::Value = client
            .get(format!("{base}/jwks"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let key = &jwks["keys"][0];
        serde_json::from_value(key.clone()).expect("the issuer's public key")
    }
}
