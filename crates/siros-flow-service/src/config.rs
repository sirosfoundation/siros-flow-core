//! The flow service configuration (TOML — deployment settings never
//! leak into the core). The service runs ONE deployment's flows: the
//! reviewed definitions directory, the issuer backend it drives, the
//! key that signs OID4VP request objects, and the PDP.

use siros_flow_core::Result;
use url::Url;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub service: ServiceCfg,
    #[serde(default)]
    pub definitions: DefinitionsCfg,
    #[serde(default)]
    pub signing: SigningCfg,
    #[serde(default)]
    pub issuer: IssuerCfg,
    #[serde(default)]
    pub pdp: Option<Url>,
    /// The presentation TTL: how long an armed OID4VP request may wait
    /// for its response (seconds). Default 300.
    #[serde(default = "default_presentation_ttl")]
    pub presentation_ttl_seconds: i64,
    /// Flow instance retention after expiry (the sweep, §10).
    #[serde(default = "default_retention")]
    pub retention_after_final_seconds: i64,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCfg {
    /// `host:port` to bind.
    pub bind: Option<String>,
    /// The externally visible base URL — the OID4VP `response_uri` and
    /// the flow status URLs are derived from it (the one-URL rule: it
    /// must resolve from the wallet AND from inside the deployment).
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionsCfg {
    /// The reviewed flow definitions directory (each `.yaml` loads and
    /// validates at startup; a definition that does not is a startup
    /// refusal — fail-closed like the circuit catalog).
    pub dir: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningCfg {
    /// The JWK that signs OID4VP request objects (the verifier role).
    /// Absent ⇒ an ephemeral dev key (restarts rotate it; development
    /// only — the same warning the issuer gives).
    pub jwk_path: Option<String>,
}

/// The issuer the `issuance` primitive drives: an OpenID4VCI issuer's
/// **backend session API** (the integrator surface — the same API a
/// portal drives; siros-issuer-core's §6.1, and the vc platform's
/// prepare-issuance shape). The wallet redeems the offer against the
/// issuer's own OID4VCI surface; the flow never fronts issuance.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerCfg {
    /// The issuer backend base URL (the internal API: create-session).
    pub backend_url: Option<String>,
    /// The issuer's public identifier — the RFC 7523 assertion's
    /// `aud` (issuer-core: the issuer identifier derived from its
    /// public URL; vc: its `iss`).
    pub audience: Option<String>,
    /// This service's integrator identity (the assertion's
    /// `iss`/`sub`).
    pub integrator_id: Option<String>,
    /// The integrator signing key (JWK file) for the backend
    /// assertion. The issuer's client registry carries the public
    /// key.
    pub integrator_key_path: Option<String>,
}

fn default_presentation_ttl() -> i64 {
    300
}

fn default_retention() -> i64 {
    3_600
}

impl Config {
    pub fn from_toml_str(text: &str) -> Result<Self> {
        toml::from_str(text)
            .map_err(|e| siros_flow_core::Error::configuration(format!("flow config: {e}")))
    }
}
