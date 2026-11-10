//! The `presentation` primitive (design §6.1): build the OID4VP
//! request from the definition's DCQL credential queries, verify the
//! response — verifier-core in-process, never re-implemented — and
//! hand the presented credentials' claims and holder keys to the
//! context.
//!
//! Ported from siros-issuer-core's `presentation_auth.rs` (the Mode B
//! machinery — OIDF-conformance-proven and wallet-interop-proven
//! against the vc stack): the same `create_request` /
//! `process_response` library calls, the same request-object shape,
//! the same `direct_post.jwt` response path. A wallet that completes
//! a vc presentation completes a flow presentation.

use std::sync::Arc;

use serde_json::{json, Value};
use siros_flow_core::error::code;
use siros_flow_core::language::PresentationStep;
use siros_flow_core::{Error, Result};
use url::Url;

use siros_issuer_core::signer::Signer;
use siros_verifier_core::oid4vp::{self, RequestConfig};
use siros_verifier_core::sdjwt::X5cLeaf;

use crate::state::FlowServiceState;

/// An issuer-core error crossing the vault boundary.
fn vault_error(error: siros_issuer_core::Error) -> Error {
    Error::configuration(format!("the vault: {error}"))
}

/// The kryptering adapter over the family Signer — issuer-core Mode
/// B's adapter, verbatim (the verifier-core signing boundary).
pub struct KrypteringSignerAdapter {
    pub inner: Arc<dyn Signer>,
}

impl kryptering::Signer for KrypteringSignerAdapter {
    fn algorithm(&self) -> kryptering::SignatureAlgorithm {
        jose_rs::JwsAlgorithm::from_str("ES256")
            .expect("ES256 is a known JWS algorithm")
            .to_crypto()
            .expect("ES256 maps to a crypto algorithm")
    }

    fn sign(&self, data: &[u8]) -> kryptering::error::Result<Vec<u8>> {
        self.inner
            .sign_es256_raw(data)
            .map_err(|e| kryptering::error::Error::Crypto(format!("signing: {e}")))
    }
}

/// Derive the DCQL query from the definition's typed credential
/// queries (issuer-core's `derive_dcql` shape, restated over the
/// definition's vocabulary — the same wire DCQL, so the same wallets
/// answer).
pub fn derive_dcql(queries: &[siros_flow_core::language::CredentialQuery]) -> Result<Value> {
    let mut credentials = Vec::new();
    for query in queries {
        let claims: Vec<Value> = query
            .claims
            .iter()
            .map(|claim| json!({ "path": claim.path }))
            .collect();
        credentials.push(json!({
            "id": query.id,
            "format": query.format,
            "meta": query.meta,
            "claims": claims,
        }));
    }
    Ok(json!({ "credentials": credentials }))
}

/// The wallet's response, in the shape the armed request's mode
/// demanded (§6.1): the encrypted modes answer with a `response` JWE
/// form value; the plain direct_post mode answers with the clear
/// `vp_token` + `state` body. The modes never cross — the verifier
/// refuses a mismatched answer.
#[derive(Debug, Clone)]
pub enum PresentationResponse {
    /// The `response` form value: a JWE to the request's ephemeral
    /// key (the `direct_post.jwt` / `dc_api.jwt` modes).
    Jwe(String),
    /// The clear `vp_token` + `state` body (the plain `direct_post`
    /// mode).
    Plain(Vec<u8>),
}

/// One armed presentation step: what waits for the wallet.
pub struct ArmedPresentation {
    /// The signed request object (the JAR the wallet reads).
    pub jar: String,
    /// The `response_uri` the wallet POSTs to (this service's
    /// `/flow-response/{handle}`).
    pub response_uri: Url,
    /// The challenge handle (opaque, rides the response_uri path).
    pub handle: String,
    /// The carrier this step rides ("deeplink" | "dc_api") — the
    /// reply envelope carries it so a front-end knows which hand to
    /// play (open a URI vs `credentials.get`).
    pub carrier: &'static str,
    /// The verifier-core session, sealed for the flow record (it
    /// carries the ephemeral response-encryption key — sealed at
    /// rest, never in the clear).
    pub sealed_session: Vec<u8>,
}

/// Arm one presentation step: build and sign the request object, seal
/// the verifier-core session. Trust in the presented credential is
/// decided when the RESPONSE arrives (the PDP, fail-closed), never at
/// arm time.
pub fn arm_presentation(
    state: &FlowServiceState,
    flow_instance: &str,
    step: &PresentationStep,
) -> Result<ArmedPresentation> {
    let now = crate::status::now_unix();
    let dcql_query = derive_dcql(&step.request)?;
    let handle = format!("fr_{}", random_handle(24));
    let response_uri = state
        .public_url
        .join(&format!("flow-response/{handle}"))
        .map_err(|e| Error::configuration(format!("public_url: {e}")))?;

    let signer = KrypteringSignerAdapter {
        inner: state.signer.clone(),
    };
    let request_config = RequestConfig {
        response_uri: response_uri.as_str().to_owned(),
        dcql_query,
        ttl_secs: state.presentation_ttl_seconds,
        vp_formats_supported: None,
        client_id: None,
    };
    // The carrier decides how the request reaches the wallet (§7) and
    // the response mode how the answer comes back (§6.1): the
    // definition states both — the plain mode's confidentiality
    // tradeoff is visible in the reviewed file. The DC API carrier
    // arms only its .jwt profile (the browser-relayed response
    // shape); the plain mode refused at load for it, and this match
    // refuses it again should a deployment default cross them.
    let carrier_kind = step.carrier.unwrap_or(state.default_carrier);
    let mode = step.response_mode.unwrap_or_default();
    let (carrier, jar, oid4vp_session) = match (carrier_kind, mode) {
        (
            siros_flow_core::language::Carrier::Deeplink,
            siros_flow_core::language::ResponseMode::Jwt,
        ) => {
            let (jar, session) = oid4vp::create_request(
                &request_config,
                &signer,
                "ES256",
                &state.cert_chain_der,
                now,
            )
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("request: {e}")))?;
            ("deeplink", jar, session)
        }
        (
            siros_flow_core::language::Carrier::Deeplink,
            siros_flow_core::language::ResponseMode::Plain,
        ) => {
            // OID4VP's plain direct_post: the response form rides TLS
            // with no JWE layer (the definition's visible tradeoff).
            let (jar, session) = oid4vp::create_plain_request(
                &request_config,
                &signer,
                "ES256",
                &state.cert_chain_der,
                now,
            )
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("request: {e}")))?;
            ("deeplink", jar, session)
        }
        (siros_flow_core::language::Carrier::DcApi, _) => {
            // The DC API's holder-binding audience is the ORIGIN
            // of the page calling `credentials.get` — this
            // service's own public origin (the same origin that
            // serves the front-end and the response_uri).
            // create_dc_api_request validates the bare-origin
            // shape and sets the DC-API handover the wallet
            // signs into its key-binding proof.
            if mode == siros_flow_core::language::ResponseMode::Plain {
                return Err(Error::language_invalid(
                    "the plain direct_post mode arms only the deep-link carrier",
                ));
            }
            let origin = state.public_url.origin().ascii_serialization();
            let (jar, session) = oid4vp::create_dc_api_request(
                &request_config,
                &signer,
                "ES256",
                &state.cert_chain_der,
                now,
                &origin,
            )
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("request: {e}")))?;
            ("dc_api", jar, session)
        }
    };

    // Seal the verifier-core session for the flow record (the
    // ephemeral key inside; the flow vault owns it at rest).
    let sealed = state
        .vault
        .seal(
            flow_instance,
            &serde_json::to_value(&oid4vp_session).expect("the oid4vp session serializes"),
        )
        .map_err(vault_error)?;

    Ok(ArmedPresentation {
        jar,
        response_uri,
        handle,
        carrier,
        sealed_session: sealed,
    })
}

/// One verified credential, in the context's shape.
pub struct VerifiedCredentialOutcome {
    pub format: String,
    pub claims: Value,
    pub holder_key: Option<Value>,
    /// The trust query the PDP decides on (per credential, fail-
    /// closed before anything is adopted).
    pub trust_query: siros_verifier_core::trust::TrustQuery,
}

/// Verify an armed presentation's response (the `direct_post.jwt` JWE
/// the wallet POSTs) and collect each answered credential query's
/// claims + holder key. Cryptographic verification is verifier-core's;
/// **trust is the PDP's** — the caller runs `permit_presentation` per
/// result before adopting anything (§9).
pub fn verify_presentation(
    state: &FlowServiceState,
    flow_instance: &str,
    sealed_session: &[u8],
    response: &PresentationResponse,
) -> Result<Vec<(String, VerifiedCredentialOutcome)>> {
    let now = crate::status::now_unix();
    let session_value = state
        .vault
        .unseal(flow_instance, sealed_session)
        .map_err(vault_error)?;
    let oid4vp_session: siros_verifier_core::oid4vp::Session =
        serde_json::from_value(session_value)
            .map_err(|e| Error::configuration(format!("the sealed oid4vp session: {e}")))?;
    let results = match response {
        // The encrypted modes: the `response` JWE form value.
        PresentationResponse::Jwe(jwe) => {
            oid4vp::process_response(&oid4vp_session, jwe, now, &X5cLeaf)
        }
        // OID4VP's plain direct_post: the clear `vp_token` + state
        // body — the same checks, no JWE layer (§6.1's stated
        // tradeoff).
        PresentationResponse::Plain(body) => {
            oid4vp::process_response_plain(&oid4vp_session, body, now, &X5cLeaf)
        }
    }
    .map_err(|e| Error::new(code::INVALID_INPUT, format!("presentation: {e}")))?;

    let mut out = Vec::new();
    for result in &results {
        let claims = result
            .verified
            .claims()
            .map_err(|e| Error::new(code::INVALID_INPUT, format!("presented claims: {e}")))?;
        let (format, holder_key) = match &result.verified {
            siros_verifier_core::oid4vp::VerifiedCredential::SdJwt(verified) => (
                "dc+sd-jwt".to_owned(),
                verified
                    .holder_key
                    .as_ref()
                    .map(|jwk| serde_json::to_value(jwk).expect("the holder key serializes")),
            ),
            siros_verifier_core::oid4vp::VerifiedCredential::Mdoc(verified) => (
                "mso_mdoc".to_owned(),
                Some(device_key_jwk(&verified.device_key)),
            ),
        };
        out.push((
            result.credential_id.clone(),
            VerifiedCredentialOutcome {
                format,
                claims: Value::Object(claims),
                holder_key,
                // The verifier-side trust query: "issuer" both roles
                // (the presented credential's issuer is the issuer of
                // record; the mdoc role is its own).
                trust_query: result.verified.trust_query("issuer", "issuer"),
            },
        ));
    }
    Ok(out)
}

/// The mdoc device key as a JWK value (the `PublicKey<p256>` type
/// carries no Serialize — the SEC1 point maps to the EC JWK members).
fn device_key_jwk(key: &p256::PublicKey) -> Value {
    // elliptic-curve 0.14: `ToSec1Point::to_sec1_point` (the SEC1
    // affine point — the deprecated spelling is `to_encoded_point`).
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    let point = key.to_sec1_point(false);
    let bytes = point.as_bytes();
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": siros_issuer_core::sdjwt_issue::b64u(&bytes[1..33]),
        "y": siros_issuer_core::sdjwt_issue::b64u(&bytes[33..]),
    })
}

/// A URL-safe random handle (the family's `random_handle` shape).
pub(crate) fn random_handle(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("OS randomness");
    siros_issuer_core::sdjwt_issue::b64u(&buf)
}
