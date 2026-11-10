//! The flow language (design §5): definitions are YAML pipelines — a
//! linear sequence of steps from a closed vocabulary over a working
//! set, non-Turing-complete by construction. The schema is a JSON tree
//! (§5.3): YAML is the frontend, the parsed-and-validated definition
//! is the typed document, and the **content digest** of its canonical
//! JSON form is the definition's identity (stable across YAML
//! re-serialization; the PDP evidence carries it, §9).
//!
//! Fail-closed everywhere (the circuit-catalog load discipline): an
//! unknown step kind, an unknown primitive, an unknown version, a
//! two-key step, an empty id — each is a load refusal with a stable
//! code, never a best-effort interpretation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{code, Error, Result};

/// The one `language_version` this engine reads. Unknown versions are
/// refused at load (§14 Q7 resolved: semver the language, the version
/// rides every definition, the digest is the identity).
pub const LANGUAGE_VERSION: u32 = 1;

// ─── The typed definition ─────────────────────────────────────────────────

/// A validated flow definition. All maps are `BTreeMap` so the
/// canonical JSON (and thus the digest) is deterministic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowDefinition {
    /// The flow's name — the id flows are started by. Non-empty,
    /// `[a-z0-9-]` (it rides evidence and logs; a stable, boring token).
    pub flow: String,
    #[serde(default)]
    pub description: String,
    pub language_version: u32,
    pub steps: Vec<Step>,
}

/// One step. The YAML shape is a heterogeneous map keyed by the step
/// kind (`- presentation: …`); the loader rewrites each exactly-one-key
/// entry to a kind-tagged object (§5: a two-key step is ambiguous and
/// refused), which is what this enum deserializes from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    Presentation(PresentationStep),
    Bind(BindStep),
    Issuance(IssuanceStep),
    Store(StoreStep),
    /// A JWT-shaped token verified by a named plugin (§6.4).
    Token(TokenStep),
    /// An external API called through a named provider plugin (§6.5).
    Fetch(FetchStep),
    /// A typed event emitted to the flow's audiences (§6.6).
    Notify(NotifyStep),
    /// Early flow-stop (goFF/pyFF `end`). No parameters.
    End,
}

/// `presentation` (§6.1): one DCQL request, one or more credential
/// queries — one OID4VP transaction, so "presented together" is
/// cryptographic, not sequential.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationStep {
    /// The step's id — the name later steps reference it by. Non-empty;
    /// unique within the definition.
    pub id: String,
    /// The credential queries (DCQL shape; the vocabulary of §5.1).
    pub request: Vec<CredentialQuery>,
    /// Every query id that must answer (default: all).
    #[serde(default)]
    pub require: Vec<String>,
    /// The carrier this step rides (§7); absent = the deployment
    /// default (`service.default_carrier`). The step's semantics do
    /// not change with the carrier — only how the request reaches
    /// the wallet and how the response comes back.
    #[serde(default)]
    pub carrier: Option<Carrier>,
    /// The response mode the step arms (§6.1): how the wallet
    /// returns its response. Absent = `direct_post.jwt` (the
    /// default, the encrypted mode). `direct_post` is OID4VP's plain
    /// mode — the `vp_token` + `state` form rides TLS to the
    /// `response_uri` with NO JWE layer: a confidentiality tradeoff
    /// stated VISIBLY in the definition (the wallet stack deployed on
    /// gdc completes the plain mode today; the encrypted mode waits
    /// on its frontend's response-encryption branch).
    #[serde(default)]
    pub response_mode: Option<ResponseMode>,
}

/// The response mode a presentation step arms (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ResponseMode {
    /// OID4VP's plain `direct_post`: the response form in the clear
    /// (over TLS), no JWE layer. The visible, reviewed tradeoff.
    #[serde(rename = "direct_post")]
    Plain,
    /// The encrypted default: the response is a JWE to the request's
    /// ephemeral key (`direct_post.jwt`).
    #[default]
    #[serde(rename = "direct_post.jwt")]
    Jwt,
}

/// The carrier a wallet-facing step rides (design §7):
///
/// - `deeplink` — QR / deep link: the request object travels a URI
///   and the wallet POSTs the `direct_post.jwt` response to the
///   `response_uri`.
/// - `dc_api` — the W3C Digital Credentials API: the front-end hands
///   the request object to `navigator.credentials.get` and POSTs the
///   returned `data` back. The holder-binding audience is the
///   calling page's ORIGIN (the DC API handover — verifier-core's
///   `create_dc_api_request`), not the `client_id`.
///
/// WMP is a carrier of the same kind, at P-bw4; naming it today is a
/// load refusal (the closed vocabulary — `deeplink`/`dc_api` only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    Deeplink,
    DcApi,
}

/// One DCQL credential query. `meta` carries the format's matching
/// member (`vct_values` for dc+sd-jwt, `doctype_values` for mso_mdoc)
/// verbatim — flow-core does not re-shape DCQL (verifier-core owns it).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialQuery {
    pub id: String,
    /// `dc+sd-jwt` or `mso_mdoc`.
    pub format: String,
    pub meta: BTreeMap<String, serde_json::Value>,
    /// The claims paths requested (DCQL claims-path arrays, §5.4).
    #[serde(default)]
    pub claims: Vec<ClaimsRequest>,
}

/// A DCQL claims request: `{path: [...]}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimsRequest {
    pub path: Vec<String>,
}

/// `bind` (§8): one identity-binding check. The vocabulary rule
/// (owner, v0.3): **comparisons are plugin-only except where they are
/// 100% unequivocal** — `same-key` is the one built-in; everything
/// else is a named reference plugin, allowlisted exactly like a
/// deployment's own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindStep {
    pub id: String,
    /// The primitive name: `same-key` (built-in) or a plugin name
    /// (`claim-equals`, `rule-match`, …) resolved against the registry
    /// at load — unknown names refuse the definition.
    pub primitive: String,
    /// The primitive's parameters, validated by the primitive itself
    /// (typed refs, never dotted strings — §5.4: mdoc namespaces
    /// contain dots).
    #[serde(default)]
    pub params: serde_json::Value,
    /// `fail` (default): a mismatch ends the flow with the primitive's
    /// refusal code. `record`: write the verdict for a later `when:`
    /// — branching is visible, never implied.
    #[serde(default)]
    pub on_mismatch: OnMismatch,
    /// A `when:` matcher on this step: run only when a recorded bind
    /// verdict matches. The declarative branch point (§5.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<WhenMatcher>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnMismatch {
    #[default]
    Fail,
    Record,
}

/// The `when:` matcher — presence/equality over a recorded bind
/// verdict (§5.4's closed matcher vocabulary: no expressions).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhenMatcher {
    /// The bind step whose recorded verdict this tests.
    pub step: String,
    /// The verdict required for this step to run.
    pub matched: bool,
}

/// `issuance` (§6.3): create an issuance session over subject data
/// derived declaratively from the context — `from` (a presentation's
/// verified claims) plus a `merge` map. No computation, no plugins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceStep {
    pub id: String,
    /// The credential configuration id to issue (catalog-resolved by
    /// issuer-core at runtime).
    pub credential: String,
    pub subject: SubjectDerivation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectDerivation {
    /// The base subject: a presentation result's verified claims.
    pub from: ContextRef,
    /// Context refs merged over the base (claim path → source ref).
    /// Keys are claim paths into the subject document.
    #[serde(default)]
    pub merge: BTreeMap<String, ContextRef>,
}

/// A typed context reference (§5.4): never a dotted string. `input`
/// names a flow input; `step` + `credential` name a presentation
/// result; `path` is the claims-path array into it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    pub path: Vec<String>,
}

impl ContextRef {
    /// A human-stable rendering for evidence and refusals (names the
    /// reference, never a value).
    pub fn render(&self) -> String {
        let source = if let Some(input) = &self.input {
            format!("input:{input}")
        } else if let Some(step) = &self.step {
            match &self.credential {
                Some(credential) => format!("{step}.{credential}"),
                None => step.clone(),
            }
        } else {
            "context".to_owned()
        };
        format!("{source}#{}", self.path.join("/"))
    }
}

/// `store` (§6.6): write a derived value into the context under a
/// declared key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreStep {
    pub id: String,
    /// The value: a context ref (copy) or a literal. It lands in the
    /// context's derived values under the STEP ID (§5.5) — the one
    /// addressing discipline: later steps reference it as
    /// `{step: <id>, path: [...]}`.
    pub value: serde_json::Value,
}

/// One `token` step (§6.4): a JWT-shaped token — an OIDC ID token,
/// an RFC 7523 assertion, an enterprise IdP's JWT — verified by a
/// named plugin. The token arrives as a flow input (the integrator
/// that runs a SAML SP asserts its user the way issuer-core Mode A
/// allows; flow-core parses no XML); the plugin is the reviewed code
/// — signature, audience, freshness windows (the checks
/// `verify_private_key_jwt` performs in issuer-core, generalized) —
/// and the flow references it by name. Its verified claims land in
/// the context's derived values under the step id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenStep {
    pub id: String,
    /// The plugin's name — must be in the deployment's allowlist or
    /// the definition refuses to load (§6.7).
    pub plugin: String,
    /// The plugin's parameters (validated by the plugin at load —
    /// the bind vocabulary's `validate_params` discipline).
    #[serde(default)]
    pub params: serde_json::Value,
}

/// One `fetch` step (§6.5): an external API called through a
/// config-selected provider plugin. The step declares the context
/// inputs it MAY be sent; every declared name is checked against the
/// provider's configured input surface at LOAD (the PII-flow audit:
/// a definition routing undeclared subject data to a provider never
/// runs). The fetched value lands in the context's derived values
/// under the step id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchStep {
    pub id: String,
    /// The provider's name — must be in the deployment's allowlist
    /// or the definition refuses to load (§6.7).
    pub plugin: String,
    /// The inputs this step may send: input name → context ref. Every
    /// name must be in the provider's configured input surface (§6.5,
    /// checked at load); at runtime exactly these are resolved and
    /// sent, nothing else.
    #[serde(default)]
    pub inputs: BTreeMap<String, ContextRef>,
}

/// One `notify` step (§6.6): emit a typed event to the flow's
/// audiences — a carrier message (a WMP notification when the target
/// is an instance, at P-bw4) or a typed SSE event for the embedding
/// frontend ("one state machine, two audiences").
///
/// Events carry the KIND (a stable token the consumer switches on)
/// and an optional MESSAGE: a **definition-authored literal**. A
/// context reference here refuses at load — events are narration,
/// and context values never leave the process (§10.1) nor ride
/// event surfaces (§10.2's never-values discipline).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyStep {
    pub id: String,
    /// The event kind — a stable token (`[a-z0-9._-]`).
    pub event: String,
    /// A definition-authored message literal (optional).
    #[serde(default)]
    pub message: Option<String>,
}

// ─── Load + validate + digest ──────────────────────────────────────────────

impl FlowDefinition {
    /// Parse a definition from YAML. Fail-closed at every shape: the
    /// document must be a mapping, `steps` a sequence of exactly
    /// one-key mappings, every step kind known, every id a non-empty
    /// stable token, the version exactly `LANGUAGE_VERSION`.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let value: serde_json::Value = serde_yaml::from_str(text)
            .map_err(|e| Error::language_invalid(format!("the document is not YAML: {e}")))?;
        Self::from_value(value)
    }

    /// Parse from an already-loaded JSON tree (the schema is the JSON
    /// tree; YAML is one frontend — §5.3). The step entries arrive in
    /// the document's own shape (one key = one kind) and are rewritten
    /// to the kind-tagged form here.
    pub fn from_value(mut value: serde_json::Value) -> Result<Self> {
        rewrite::rewrite_steps(&mut value)?;
        let definition: FlowDefinition = serde_json::from_value(value).map_err(|e| {
            Error::language_invalid(format!("the document is not a flow definition: {e}"))
        })?;
        if definition.language_version != LANGUAGE_VERSION {
            return Err(Error::new(
                code::FLOW_LANGUAGE_VERSION,
                format!(
                    "language_version {} is not {} — the definition must be written for the engine's language",
                    definition.language_version, LANGUAGE_VERSION
                ),
            ));
        }
        definition.validate()?;
        Ok(definition)
    }

    /// The structural validation (fail-closed; every refusal names the
    /// step and the rule, never a value).
    pub fn validate(&self) -> Result<()> {
        validate_flow_id(&self.flow)?;
        let mut step_ids: Vec<&str> = Vec::new();
        for (index, step) in self.steps.iter().enumerate() {
            let id = match step {
                Step::Presentation(presentation) => {
                    validate_step_id(&presentation.id, index, "presentation")?;
                    validate_presentation(presentation)?;
                    presentation.id.as_str()
                }
                Step::Bind(bind) => {
                    validate_step_id(&bind.id, index, "bind")?;
                    if bind.primitive.trim().is_empty() {
                        return Err(Error::language_invalid(format!(
                            "step {index} (bind {:?}): a bind step must name a primitive",
                            bind.id
                        )));
                    }
                    if let Some(when) = &bind.when {
                        if when.step.trim().is_empty() {
                            return Err(Error::language_invalid(format!(
                                "step {index} (bind {:?}): a when: matcher names an empty step",
                                bind.id
                            )));
                        }
                    }
                    bind.id.as_str()
                }
                Step::Issuance(issuance) => {
                    validate_step_id(&issuance.id, index, "issuance")?;
                    validate_credential_id(&issuance.credential, index, &issuance.id)?;
                    validate_subject_derivation(&issuance.subject, index, &issuance.id)?;
                    issuance.id.as_str()
                }
                Step::Store(store) => {
                    validate_step_id(&store.id, index, "store")?;
                    store.id.as_str()
                }
                Step::Token(token) => {
                    validate_step_id(&token.id, index, "token")?;
                    if token.plugin.trim().is_empty() {
                        return Err(Error::language_invalid(format!(
                            "step {index} (token {:?}): an empty plugin name",
                            token.id
                        )));
                    }
                    token.id.as_str()
                }
                Step::Fetch(fetch) => {
                    validate_step_id(&fetch.id, index, "fetch")?;
                    if fetch.plugin.trim().is_empty() {
                        return Err(Error::language_invalid(format!(
                            "step {index} (fetch {:?}): an empty plugin name",
                            fetch.id
                        )));
                    }
                    fetch.id.as_str()
                }
                Step::Notify(notify) => {
                    validate_step_id(&notify.id, index, "notify")?;
                    if notify.event.trim().is_empty() {
                        return Err(Error::language_invalid(format!(
                            "step {index} (notify {:?}): an empty event kind",
                            notify.id
                        )));
                    }
                    if !notify.event.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
                    }) {
                        return Err(Error::language_invalid(format!(
                            "step {index} (notify {:?}): the event kind is a stable token ([a-z0-9._-])",
                            notify.id
                        )));
                    }
                    notify.id.as_str()
                }
                Step::End => "",
            };
            if !id.is_empty() {
                if step_ids.contains(&id) {
                    return Err(Error::language_invalid(format!(
                        "step {index}: duplicate step id {id:?} — step ids are the names (§5.4)"
                    )));
                }
                step_ids.push(id);
            }
        }
        // `when:` matchers reference recorded bind verdicts.
        let bind_ids: Vec<&str> = self
            .steps
            .iter()
            .filter_map(|step| match step {
                Step::Bind(bind) => Some(bind.id.as_str()),
                _ => None,
            })
            .collect();
        for step in &self.steps {
            if let Step::Bind(bind) = step {
                if let Some(when) = &bind.when {
                    if !bind_ids.contains(&when.step.as_str()) {
                        return Err(Error::language_invalid(format!(
                            "bind {:?}: when: references step {:?}, which is not a bind step",
                            bind.id, when.step
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// The definition's **content digest**: sha256 of the canonical
    /// JSON serialization of the normalized (typed) definition —
    /// stable across YAML formatting because the typed form is the
    /// input (BTreeMap ordering; §5.4, §9). This is the identity the
    /// PDP evidence pins.
    pub fn digest(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("the typed definition serializes");
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        let mut out = String::with_capacity(64);
        for byte in digest {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

fn validate_flow_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Error::language_invalid(format!(
            "the flow name {id:?} must be a non-empty [a-z0-9-] token — it rides evidence and logs"
        )));
    }
    Ok(())
}

fn validate_step_id(id: &str, index: usize, kind: &str) -> Result<()> {
    if id.trim().is_empty() {
        return Err(Error::language_invalid(format!(
            "step {index} ({kind}): an empty step id"
        )));
    }
    Ok(())
}

fn validate_presentation(presentation: &PresentationStep) -> Result<()> {
    if presentation.request.is_empty() {
        return Err(Error::language_invalid(format!(
            "presentation {:?}: a presentation step carries at least one credential query",
            presentation.id
        )));
    }
    let mut query_ids: Vec<&str> = Vec::new();
    for query in &presentation.request {
        if query.id.trim().is_empty() {
            return Err(Error::language_invalid(format!(
                "presentation {:?}: a credential query carries a non-empty id",
                presentation.id
            )));
        }
        if !matches!(query.format.as_str(), "dc+sd-jwt" | "mso_mdoc") {
            return Err(Error::language_invalid(format!(
                "presentation {:?}: query {:?} names format {:?} — the v1 vocabulary is dc+sd-jwt and mso_mdoc",
                presentation.id, query.id, query.format
            )));
        }
        if query.meta.is_empty() {
            return Err(Error::language_invalid(format!(
                "presentation {:?}: query {:?} carries no meta (vct_values / doctype_values)",
                presentation.id, query.id
            )));
        }
        if query_ids.contains(&query.id.as_str()) {
            return Err(Error::language_invalid(format!(
                "presentation {:?}: duplicate credential query id {:?}",
                presentation.id, query.id
            )));
        }
        query_ids.push(query.id.as_str());
    }
    if presentation.response_mode == Some(ResponseMode::Plain)
        && presentation.carrier == Some(Carrier::DcApi)
    {
        return Err(Error::language_invalid(format!(
            "presentation {:?}: the plain direct_post mode arms only the deep-link carrier \
             (the DC API's browser-relayed response is its .jwt profile)",
            presentation.id
        )));
    }
    for required in &presentation.require {
        if !query_ids.contains(&required.as_str()) {
            return Err(Error::language_invalid(format!(
                "presentation {:?}: require names query {:?}, which the request does not carry",
                presentation.id, required
            )));
        }
    }
    Ok(())
}

fn validate_credential_id(credential: &str, index: usize, id: &str) -> Result<()> {
    if credential.trim().is_empty() {
        return Err(Error::language_invalid(format!(
            "step {index} (issuance {id:?}): an empty credential id"
        )));
    }
    Ok(())
}

fn validate_subject_derivation(subject: &SubjectDerivation, index: usize, id: &str) -> Result<()> {
    validate_context_ref(&subject.from, index, id, "subject.from")?;
    for (key, source) in &subject.merge {
        if key.trim().is_empty() {
            return Err(Error::language_invalid(format!(
                "step {index} (issuance {id:?}): subject.merge carries an empty key"
            )));
        }
        validate_context_ref(source, index, id, "subject.merge")?;
    }
    Ok(())
}

fn validate_context_ref(
    reference: &ContextRef,
    index: usize,
    id: &str,
    where_: &str,
) -> Result<()> {
    let names_source = reference.input.is_some() || reference.step.is_some();
    if !names_source {
        return Err(Error::language_invalid(format!(
            "step {index} (issuance {id:?}): {where_} names neither an input nor a step — a context reference is typed, never a bare path (§5.4)"
        )));
    }
    if reference.input.is_some() && reference.step.is_some() {
        return Err(Error::language_invalid(format!(
            "step {index} (issuance {id:?}): {where_} names both an input and a step"
        )));
    }
    Ok(())
}

// The serde plumbing: YAML steps are heterogeneous one-key maps; the
// typed `Step` is a serde-tagged enum. The bridge is explicit (parse
// to a Value tree, rewrite each one-key entry to `{kind: …}` →
// `{"kind": …}`) so the fail-closed rules (exactly one key, known
// kind) are ours, not the serializer's.
pub(crate) mod rewrite {
    use super::*;

    /// Rewrite the raw YAML document's `steps` from one-key-per-entry
    /// maps to kind-tagged objects the typed enum deserializes from.
    /// Every ambiguity is a refusal.
    pub fn rewrite_steps(value: &mut serde_json::Value) -> Result<()> {
        let Some(steps) = value
            .as_object_mut()
            .and_then(|object| object.get_mut("steps"))
            .and_then(|steps| steps.as_array_mut())
        else {
            return Err(Error::language_invalid(
                "the document carries no steps array",
            ));
        };
        for (index, entry) in steps.iter_mut().enumerate() {
            // The one bare-scalar step: `end` (goFF shape). Any other
            // scalar step is meaningless and refused.
            if let Some(scalar) = entry.as_str() {
                if scalar == "end" {
                    *entry = serde_json::json!({"kind": "end"});
                    continue;
                }
                return Err(Error::language_invalid(format!(
                    "step {index} is the scalar {scalar:?} — the only bare step is `end`"
                )));
            }
            let Some(map) = entry.as_object_mut() else {
                return Err(Error::language_invalid(format!(
                    "step {index} is not a mapping"
                )));
            };
            if map.len() != 1 {
                return Err(Error::language_invalid(format!(
                    "step {index} carries {} keys — exactly one step kind per entry (§5)",
                    map.len()
                )));
            }
            let (kind, body) = map.iter_mut().next().expect("len checked");
            let kind = kind.clone();
            let body = body.take();
            let mut rewritten = serde_json::Map::new();
            rewritten.insert("kind".to_owned(), serde_json::Value::String(kind.clone()));
            if let serde_json::Value::Object(body) = body {
                for (key, value) in body {
                    rewritten.insert(key, value);
                }
            } else if !body.is_null() {
                return Err(Error::language_invalid(format!(
                    "step {index} ({kind}) carries a scalar body — the step's parameters are a mapping"
                )));
            }
            *entry = serde_json::Value::Object(rewritten);
        }
        Ok(())
    }
}
