//! The `issuance` primitive's backend (design §6.3): the flow drives
//! an OpenID4VCI issuer's **backend session API** — the integrator
//! surface a portal uses. siros-issuer-core's §6.1 API is the v1
//! client (create-session → the credential offer); the vc platform's
//! prepare-issuance is the same trait — the interop point.
//!
//! The wallet redeems the offer against the issuer's own OID4VCI
//! surface (token / credential). The flow never fronts issuance and
//! never touches a private key of the issuer's.

use serde_json::Value;
use siros_flow_core::{Error, Result};
use url::Url;

/// What one issuance step produced: the offer the wallet redeems.
#[derive(Debug, Clone)]
pub struct IssuanceOutcome {
    /// The offer URI (the OID4VCI `credential_offer_uri`).
    pub offer_uri: String,
    /// The same-device deep link
    /// (`openid-credential-offer://?credential_offer_uri=…`).
    pub deep_link: String,
    /// The session id (observability: the issuer's own record).
    pub session_id: String,
}

/// One issuer backend. The flow's `issuance` step calls
/// `create_session` with the subject derived from the flow context;
/// everything else — the offer's grant shape, tx codes, TTL policy —
/// is the issuer's, configured on the issuer, not in the flow.
#[async_trait::async_trait]
pub trait IssuerClient: Send + Sync {
    async fn create_session(
        &self,
        credential: &str,
        subject: &Value,
        ttl_seconds: i64,
    ) -> Result<IssuanceOutcome>;
    /// A readiness ping (the service's healthz reports the issuer).
    async fn reachable(&self) -> bool;
}

/// The siros-issuer-core client: POST /api/v1/issuance/sessions with
/// an RFC 7523 bearer assertion (the integrator key; the issuer's
/// client registry carries the public key — the §12.2-resolved
/// surface, the same auth the conformance portal uses).
pub struct IssuerCoreClient {
    http: reqwest::Client,
    backend: Url,
    /// The assertion's `aud`: the issuer identifier.
    audience: String,
    /// The assertion's `iss`/`sub`: this service's integrator id.
    integrator_id: String,
    /// The integrator signing key (JWK with private material — the
    /// only private key this service holds; never the issuer's).
    key: jose_rs::jwk::Jwk,
}

impl IssuerCoreClient {
    pub fn new(
        backend: Url,
        audience: String,
        integrator_id: String,
        key_path: &str,
    ) -> Result<Self> {
        // The family's key shapes, one loader (PKCS#8 EC P-256 PEM
        // detected by the header, or JWK JSON).
        let key: jose_rs::jwk::Jwk = crate::keys::load_key_file(key_path)?;
        Ok(Self {
            http: reqwest::Client::new(),
            backend,
            audience,
            integrator_id,
            key,
        })
    }

    /// The RFC 7523 assertion (the issuer's `verify_bearer_assertion`
    /// verifies: iss/sub = the integrator id, aud = the issuer
    /// identifier, a fresh iat/exp window).
    fn assertion(&self) -> Result<String> {
        let now = siros_issuer_service::status::now_unix();
        let mut header = jose_rs::JoseHeader::new("ES256");
        header.typ = Some("jwt".to_owned());
        header.kid = self.key.kid.clone();
        // The issuer's bearer verification reads the JWK from the
        // assertion header (the RFC 7523 key-reference shape the
        // conformance portal uses).
        header.jwk = Some(
            serde_json::to_value(self.key.to_public_jwk()).expect("the public jwk serializes"),
        );
        let payload = serde_json::json!({
            "iss": self.integrator_id,
            "sub": self.integrator_id,
            "aud": self.audience,
            "iat": now,
            "exp": now + 300,
        });
        let mut opts = jose_rs::jws::compact::SignOptions::new();
        opts = opts.with_key_reference_headers(true);
        jose_rs::jws::compact::sign_with_jwk_options(
            &self.key,
            &serde_json::to_vec(&payload).expect("the assertion serializes"),
            &header,
            &opts,
        )
        .map_err(|e| Error::configuration(format!("signing the backend assertion: {e}")))
    }
}

#[async_trait::async_trait]
impl IssuerClient for IssuerCoreClient {
    async fn create_session(
        &self,
        credential: &str,
        subject: &Value,
        ttl_seconds: i64,
    ) -> Result<IssuanceOutcome> {
        let url = self
            .backend
            .join("api/v1/issuance/sessions")
            .map_err(|e| Error::configuration(format!("the backend url: {e}")))?;
        let assertion = self.assertion()?;
        let response = self
            .http
            .post(url.as_str())
            .header("Authorization", format!("Bearer {assertion}"))
            .json(&serde_json::json!({
                "credential": credential,
                "subject": subject,
                "ttl_seconds": ttl_seconds,
            }))
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    siros_flow_core::error::code::TRANSPORT,
                    format!("the issuer backend: {e}"),
                )
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::new(
                siros_flow_core::error::code::TRANSPORT,
                format!("the issuer backend answered {status}: {body}"),
            ));
        }
        let reply: Value = response.json().await.map_err(|e| {
            Error::new(
                siros_flow_core::error::code::TRANSPORT,
                format!("the issuer backend reply: {e}"),
            )
        })?;
        Ok(IssuanceOutcome {
            offer_uri: reply["offer_uri"]
                .as_str()
                .ok_or_else(|| {
                    Error::new(
                        siros_flow_core::error::code::TRANSPORT,
                        "the backend reply carries no offer_uri",
                    )
                })?
                .to_owned(),
            deep_link: reply["wallet_redirect"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            session_id: reply["session_id"].as_str().unwrap_or_default().to_owned(),
        })
    }

    async fn reachable(&self) -> bool {
        let Ok(url) = self.backend.join("healthz") else {
            return false;
        };
        self.http
            .get(url.as_str())
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }
}
