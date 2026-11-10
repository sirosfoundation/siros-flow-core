//! The flow service configuration (TOML — deployment settings never
//! leak into the core). The service runs ONE deployment's flows: the
//! reviewed definitions directory, the issuer backend it drives, the
//! key that signs OID4VP request objects, and the PDP.

use siros_flow_core::Result;
use url::Url;

#[derive(Debug, serde::Deserialize)]
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
    /// Present ⇒ the service embeds its own issuer (the additional
    /// trusted issuer); absent ⇒ the issuance steps drive an
    /// external issuer's backend.
    #[serde(default)]
    pub embedded: Option<EmbeddedIssuerCfg>,
    /// The deployment's plugin allowlist (§6.7): token-verification
    /// plugins and fetch providers, by name.
    #[serde(default)]
    pub plugins: PluginsCfg,
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

/// The deployment's plugin allowlist (§6.7).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PluginsCfg {
    /// `[[plugins.token]]`: one token-verification plugin per stanza
    /// (§6.4) — the name a definition's `token` step references.
    #[serde(default)]
    pub token: Vec<TokenPluginCfg>,
    /// `[[plugins.fetch]]`: one fetch provider per stanza (§6.5) —
    /// the name a definition's `fetch` step references, with the
    /// provider's input surface (the PII-flow audit).
    #[serde(default)]
    pub fetch: Vec<FetchPluginCfg>,
}

/// One `[[plugins.token]]` stanza (the reference plugin's config).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenPluginCfg {
    /// The name definitions reference (`plugin: <name>`).
    pub name: String,
    /// The asserting party's public key file — the family's shapes
    /// (PKCS#8 EC P-256 PEM or JWK JSON). Exactly one of `key_path`
    /// (a static, pinned key) or `jwks_uri` (discovery) is required:
    /// a key-pinned asserting party never rotates silently, and an
    /// ephemeral-key IdP (mini-oidc mints a fresh key every boot) can
    /// never be a static file.
    pub key_path: Option<String>,
    /// The asserting party's JWKS endpoint (OIDC discovery): the
    /// signing keys are fetched and cached (a TTL), selected by the
    /// assertion's `kid`.
    pub jwks_uri: Option<String>,
    /// The expected `iss`.
    pub issuer: String,
    /// The expected `aud`.
    pub audience: String,
    /// Clock-skew leeway on the freshness windows.
    #[serde(default = "default_leeway_seconds")]
    pub leeway_seconds: i64,
}

fn default_leeway_seconds() -> i64 {
    60
}

/// One `[[plugins.fetch]]` stanza (the reference provider's config).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchPluginCfg {
    /// The name definitions reference (`plugin: <name>`).
    pub name: String,
    /// The endpoint the declared inputs POST to.
    pub url: String,
    /// The request timeout.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// The response-size budget.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    /// The provider's INPUT SURFACE: the context input names it may
    /// be sent (§6.5 — a fetch step declaring anything else refuses
    /// at load). Empty = no subject data out.
    #[serde(default)]
    pub inputs: Vec<String>,
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn default_max_response_bytes() -> usize {
    65_536
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
    /// The carrier a wallet-facing step rides when the step does not
    /// name one (design §7): "deeplink" (the default) or "dc_api".
    /// An unknown name refuses configuration parsing (the closed
    /// vocabulary — WMP is a carrier of the same kind at P-bw4).
    pub default_carrier: Option<siros_flow_core::language::Carrier>,
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
    /// The family's key shape instead: a PKCS#8 EC P-256 PEM
    /// (fixtures/vc-pki/verifier-style, created by create-pki.sh) —
    /// loaded into the same JWK. Exactly one of jwk_path / pem_path.
    pub pem_path: Option<String>,
    /// The verifier role's certificate chain (PEM, leaf first): the
    /// request object's x5c. The wallet/PDP trust the request-signing
    /// leaf by this chain — the additional-trusted-verifier identity.
    pub cert_chain_path: Option<String>,
}

/// The issuer the `issuance` primitive drives: an OpenID4VCI issuer's
/// **backend session API** (the integrator surface — the same API a
/// portal drives; siros-issuer-core's §6.1, and the vc platform's
/// prepare-issuance shape). The wallet redeems the offer against the
/// issuer's own OID4VCI surface; the flow never fronts issuance.
/// `[issuer.embedded]` — the flow service embeds a complete
/// siros-issuer-service in-process: **its own `credential_issuer`
/// identity** (an additional trusted issuer), its own catalog,
/// signing keys, and OID4VCI wallet surface (offer / token /
/// credential / jwks), served on the same port as the flow API. The
/// section is a full siros-issuer-service config; the flow's
/// issuance steps drive it over its own backend API (the
/// integrator surface) with the flow's own identity — registered
/// into the embedded issuer's client registry automatically.
///
/// The deployment then registers the flow service's public URL as an
/// issuer (the PDP's trusted_issuers) and as a verifier (the
/// request-signing identity) — no trust disabled anywhere.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedIssuerCfg {
    /// A full siros-issuer-service configuration (its own TOML shape:
    /// [issuer], [catalog], [signing], [status_service], ...), nested
    /// under this section.
    #[serde(flatten)]
    pub issuer: siros_issuer_service::config::Config,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerCfg {
    /// The issuer backend base URL (the internal API: create-session).
    pub backend_url: Option<String>,
    /// The status list mode for the EMBEDDED issuer: `service`
    /// ([embedded.status_service] — a deployed siros-status-service,
    /// the production path) or `local` (an in-process status list
    /// served by this app at `GET /lists/{id}` — a dev/staging
    /// path: one shared list, random indices — the conformance
    /// fixtures' discipline). Default (`local` when embedded and no
    /// status_service given): the embedded issuer still needs a
    /// revocation handle — fail-closed means NO issuance without
    /// one, so the local list is the embedded default, labelled
    /// dev/staging.
    #[serde(default)]
    pub status_mode: Option<String>,
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
