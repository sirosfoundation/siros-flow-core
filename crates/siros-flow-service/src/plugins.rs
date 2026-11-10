//! The plugin surface (design §6.7): the deliberate
//! Turing-completeness escape hatch — **code stays code, config
//! stays config**. A plugin is reviewed, tested code, registered by
//! name from deployment config; a flow definition referencing a
//! plugin not in the allowlist refuses the definition at LOAD (the
//! same discipline as the bind primitives, §8.3).
//!
//! Two step kinds ride plugins (§6):
//!
//! - `token` (§6.4): a JWT-shaped token → its verified claims. The
//!   token arrives as a flow input (an OIDC ID token, an RFC 7523
//!   assertion; the integrator that runs a SAML SP asserts its user
//!   the way issuer-core Mode A allows — flow-core parses no XML).
//!   The plugin performs the checks `verify_bearer_assertion` /
//!   `verify_private_key_jwt` perform in issuer-core, generalized to
//!   the deployment's own asserting party: signature, `iss`, `aud`,
//!   freshness windows.
//! - `fetch` (§6.5): an external API → a context value, bounded by
//!   the provider's config, with the provider's **input surface**
//!   declared in config — so the PII flow of a definition is
//!   checkable at load from the definition and the allowlist alone.
//!
//! Trust is never a plugin's: a token plugin verifies *keys and
//! windows*, it does not decide policy (§9); the PDP decides.

use std::collections::BTreeMap;

use siros_flow_core::context::FlowContext;
use siros_flow_core::language::ContextRef;
use siros_flow_core::{Error, Result};

// ─── The traits ────────────────────────────────────────────────────────────

/// A token-verification plugin (§6.4). Pure verification over the
/// context and its configured key material — no I/O, no policy.
pub trait TokenPlugin: Send + Sync {
    /// The name the flow language references (`plugin: <name>`).
    fn name(&self) -> &str;
    /// Validate the step's parameters at LOAD (fail-closed: a
    /// definition naming malformed parameters never runs).
    fn validate_params(&self, params: &serde_json::Value) -> Result<()>;
    /// Verify the token the step's parameters name, from the flow
    /// context; the verified claims are the return value (the driver
    /// lands them in the context's derived values under the step id).
    fn verify(
        &self,
        context: &FlowContext,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value>;
}

/// A fetch provider plugin (§6.5). Bounded by construction (the
/// implementation owns its timeout and response-size budget, wired
/// from config) and DECLARING its input surface — the context input
/// names it may be sent.
#[async_trait::async_trait]
pub trait FetchPlugin: Send + Sync {
    /// The name the flow language references (`plugin: <name>`).
    fn name(&self) -> &str;
    /// The input names this provider may receive — its configured
    /// surface (config, never definition). A fetch step declaring an
    /// input outside this surface refuses the definition at load
    /// (§6.5's PII-flow audit).
    fn input_surface(&self) -> Vec<String>;
    /// Fetch: exactly the step's declared inputs (surface-checked at
    /// load, resolved by the driver at runtime). A failed fetch is
    /// an error — fail-closed, never silently continues (§6.5).
    async fn fetch(&self, inputs: BTreeMap<String, serde_json::Value>)
        -> Result<serde_json::Value>;
}

// ─── The registries (the BindRegistry shape) ───────────────────────────────

/// The deployment's allowlisted token plugins, by name.
#[derive(Default)]
pub struct TokenRegistry {
    plugins: Vec<Box<dyn TokenPlugin>>,
}

impl TokenRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, plugin: Box<dyn TokenPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }
    pub fn resolve(&self, name: &str) -> Result<&dyn TokenPlugin> {
        self.plugins
            .iter()
            .map(|plugin| plugin.as_ref())
            .find(|plugin| plugin.name() == name)
            .ok_or_else(|| {
                Error::new(
                    siros_flow_core::error::code::PLUGIN_UNKNOWN,
                    format!("token plugin {name:?} is not in the deployment's allowlist"),
                )
            })
    }
}

/// The deployment's allowlisted fetch providers, by name.
#[derive(Default)]
pub struct FetchRegistry {
    plugins: Vec<Box<dyn FetchPlugin>>,
}

impl FetchRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, plugin: Box<dyn FetchPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }
    pub fn resolve(&self, name: &str) -> Result<&dyn FetchPlugin> {
        self.plugins
            .iter()
            .map(|plugin| plugin.as_ref())
            .find(|plugin| plugin.name() == name)
            .ok_or_else(|| {
                Error::new(
                    siros_flow_core::error::code::PLUGIN_UNKNOWN,
                    format!("fetch provider {name:?} is not in the deployment's allowlist"),
                )
            })
    }
}

/// The §6.7 allowlist discipline + §6.5's PII-flow audit, at LOAD:
/// every token step's plugin resolves and its parameters pass the
/// plugin's own validation; every fetch step's plugin resolves and
/// every input it declares is in that provider's configured surface.
/// The service runs this for every definition at startup — a
/// definition referencing an unregistered plugin (or routing
/// undeclared subject data to a provider) refuses the deployment.
pub fn validate_definition(
    definition: &siros_flow_core::language::FlowDefinition,
    tokens: &TokenRegistry,
    fetches: &FetchRegistry,
) -> Result<()> {
    use siros_flow_core::language::Step;
    for step in &definition.steps {
        match step {
            Step::Token(token) => {
                let plugin = tokens.resolve(&token.plugin)?;
                plugin.validate_params(&token.params)?;
            }
            Step::Fetch(fetch) => {
                let plugin = fetches.resolve(&fetch.plugin)?;
                let surface = plugin.input_surface();
                for name in fetch.inputs.keys() {
                    if !surface.contains(name) {
                        return Err(Error::language_invalid(format!(
                            "fetch {:?}: input {:?} is not in provider {:?}'s configured \
                             surface {:?} — the PII flow of a definition is checkable at \
                             load (§6.5)",
                            fetch.id, name, fetch.plugin, surface
                        )));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ─── The reference token plugin: `id-token` ────────────────────────────────

/// The reference token plugin (§6.4): an ES256 JWT verified against
/// a configured public key, `iss`/`aud` pinned by config, `exp`/`iat`
/// freshness windows with leeway — the checks
/// `verify_bearer_assertion` performs in issuer-core (the RFC 7523
/// client-assertion discipline, service/src/auth.rs), generalized to
/// the deployment's own asserting party.
pub struct IdTokenPlugin {
    name: String,
    /// The asserting party's public key (config; the family's key
    /// file shapes).
    key: jose_rs::jwk::Jwk,
    /// The expected `iss`.
    issuer: String,
    /// The expected `aud` (a string, or an element of an array).
    audience: String,
    /// Clock-skew leeway on the freshness windows.
    leeway_seconds: i64,
}

impl IdTokenPlugin {
    /// Build from the deployment's `[[plugins.token]]` stanza.
    pub fn from_config(cfg: &crate::config::TokenPluginCfg) -> Result<Self> {
        let key = crate::keys::load_public_key_file(&cfg.key_path)?;
        Ok(Self {
            name: cfg.name.clone(),
            key,
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            leeway_seconds: cfg.leeway_seconds,
        })
    }
}

impl TokenPlugin for IdTokenPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn validate_params(&self, params: &serde_json::Value) -> Result<()> {
        // The step's parameters name the flow input carrying the
        // token — `{token: {input: <name>, path: []}}` (the token
        // arrives as a flow input, §6.4).
        let reference = token_reference(params)?;
        if reference.path.is_empty() {
            Ok(())
        } else {
            Err(Error::language_invalid(
                "the token input reference takes no path — the input is the compact JWT",
            ))
        }
    }

    fn verify(
        &self,
        context: &FlowContext,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let reference = token_reference(params)?;
        let token = context.resolve(&reference)?;
        let Some(token) = token.as_str() else {
            return Err(Error::new(
                siros_flow_core::error::code::INVALID_INPUT,
                "the token input is not a string (a compact JWT)",
            ));
        };
        // The compact-JWT shape (issuer-core auth.rs's discipline):
        // exactly three segments.
        let mut parts = token.split('.');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(_), Some(_), Some(_)) if parts.next().is_none() => {}
            _ => {
                return Err(Error::new(
                    siros_flow_core::error::code::INVALID_INPUT,
                    "the token is not a compact JWT",
                ))
            }
        }
        // Signature: ES256 against the configured key (the pinned
        // jwk.alg carries the algorithm-allowlist discipline).
        let payload = jose_rs::jws::compact::verify_with_jwk(&self.key, token)
            .map_err(|e| Error::new(siros_flow_core::error::code::INVALID_INPUT, e.to_string()))?;
        let claims: serde_json::Value = serde_json::from_slice(&payload).map_err(|e| {
            Error::new(
                siros_flow_core::error::code::INVALID_INPUT,
                format!("the token payload: {e}"),
            )
        })?;
        // `iss` pinned by config.
        if claims["iss"].as_str() != Some(self.issuer.as_str()) {
            return Err(Error::new(
                siros_flow_core::error::code::INVALID_INPUT,
                "the token's iss is not the configured issuer",
            ));
        }
        // `aud`: the configured audience, string or array element.
        let aud_ok = match &claims["aud"] {
            serde_json::Value::String(aud) => aud == &self.audience,
            serde_json::Value::Array(auds) => auds
                .iter()
                .any(|aud| aud.as_str() == Some(self.audience.as_str())),
            _ => false,
        };
        if !aud_ok {
            return Err(Error::new(
                siros_flow_core::error::code::INVALID_INPUT,
                "the token's aud is not the configured audience",
            ));
        }
        // Freshness windows with leeway (the issuer-core discipline).
        let now = crate::status::now_unix();
        let exp = claims["exp"].as_i64().ok_or_else(|| {
            Error::new(
                siros_flow_core::error::code::INVALID_INPUT,
                "the token has no exp",
            )
        })?;
        if now >= exp + self.leeway_seconds {
            return Err(Error::new(
                siros_flow_core::error::code::INVALID_INPUT,
                "the token is expired",
            ));
        }
        if let Some(iat) = claims["iat"].as_i64() {
            if iat > now + self.leeway_seconds {
                return Err(Error::new(
                    siros_flow_core::error::code::INVALID_INPUT,
                    "the token is issued in the future",
                ));
            }
        }
        if let Some(nbf) = claims["nbf"].as_i64() {
            if now + self.leeway_seconds < nbf {
                return Err(Error::new(
                    siros_flow_core::error::code::INVALID_INPUT,
                    "the token is not yet valid",
                ));
            }
        }
        Ok(claims)
    }
}

/// The `{token: {input: …}}` reference every step names — parsed at
/// both load and run (fail-closed on malformed shapes).
fn token_reference(params: &serde_json::Value) -> Result<ContextRef> {
    let reference = params.get("token").ok_or_else(|| {
        Error::language_invalid("the token step needs a token reference ({token: {input: …}})")
    })?;
    let reference: ContextRef = serde_json::from_value(reference.clone())
        .map_err(|e| Error::language_invalid(format!("the token reference: {e}")))?;
    if reference.input.is_none() {
        return Err(Error::language_invalid(
            "the token reference names a flow input (the token arrives as an input, §6.4)",
        ));
    }
    Ok(reference)
}

// ─── The reference fetch provider: `http-json` ─────────────────────────────

/// The reference fetch provider (§6.5): POSTs the step's declared
/// inputs as a JSON object to the configured URL, bounded by the
/// configured timeout and response-size budget; the JSON response
/// becomes the step's derived value.
pub struct HttpJsonPlugin {
    name: String,
    url: url::Url,
    timeout: std::time::Duration,
    max_response_bytes: usize,
    surface: Vec<String>,
    client: reqwest::Client,
}

impl HttpJsonPlugin {
    /// Build from the deployment's `[[plugins.fetch]]` stanza.
    pub fn from_config(cfg: &crate::config::FetchPluginCfg) -> Result<Self> {
        let url: url::Url = cfg
            .url
            .parse()
            .map_err(|e| Error::configuration(format!("plugins.fetch {}: url: {e}", cfg.name)))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::configuration(format!(
                "plugins.fetch {}: url must be HTTP(S)",
                cfg.name
            )));
        }
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| Error::configuration(format!("plugins.fetch {}: {e}", cfg.name)))?;
        Ok(Self {
            name: cfg.name.clone(),
            url,
            timeout: std::time::Duration::from_millis(cfg.timeout_ms),
            max_response_bytes: cfg.max_response_bytes,
            surface: cfg.inputs.clone(),
            client,
        })
    }
}

#[async_trait::async_trait]
impl FetchPlugin for HttpJsonPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn input_surface(&self) -> Vec<String> {
        self.surface.clone()
    }

    async fn fetch(
        &self,
        inputs: BTreeMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let response = self
            .client
            .post(self.url.clone())
            .timeout(self.timeout)
            .json(&inputs)
            .send()
            .await
            .map_err(|e| Error::new(siros_flow_core::error::code::TRANSPORT, e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::new(
                siros_flow_core::error::code::TRANSPORT,
                format!("the provider answered {status}"),
            ));
        }
        // The response-size budget: checked on arrival (the body is
        // already buffered by reqwest; the budget bounds the parse).
        let body = response
            .bytes()
            .await
            .map_err(|e| Error::new(siros_flow_core::error::code::TRANSPORT, e.to_string()))?;
        if body.len() > self.max_response_bytes {
            return Err(Error::new(
                siros_flow_core::error::code::TRANSPORT,
                format!(
                    "the provider's response is {} bytes over the configured budget",
                    body.len() - self.max_response_bytes
                ),
            ));
        }
        serde_json::from_slice(&body).map_err(|e| {
            Error::new(
                siros_flow_core::error::code::TRANSPORT,
                format!("the provider's response is not JSON: {e}"),
            )
        })
    }
}
