//! The working set (design §5.5): the flow context — a typed document
//! the engine owns, threaded through the steps. The **clear/sealed
//! split** (§5.5, §10): everything subject-shaped (presentation
//! claims, holder keys, derived values, caller inputs) is sealed at
//! rest under a per-flow data key; what this type holds is the
//! unsealed, in-memory copy that exists for one step and never leaves
//! the process. The service's FlowStore persists the split form.

use std::collections::BTreeMap;

use crate::error::Result;
use crate::language::ContextRef;

/// The in-memory flow context (the unsealed working set) — the
/// serialized form is what the vault seals and the FlowStore stores.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FlowContext {
    /// The flow inputs (fixed at start): the initiating caller's
    /// parameters — session identity, bind rules (`rule-match`'s rule
    /// arrives here, never in the definition: only the caller knows
    /// what "the same user" means for its session, §8.2).
    pub inputs: BTreeMap<String, serde_json::Value>,
    /// Presentation results by step id: each entry carries the
    /// verified claims per credential id, and the holder keys per
    /// credential id (the `cnf`/`DeviceKey` the wallet proved).
    pub presentations: BTreeMap<String, PresentationResult>,
    /// Derived values written by steps (`store`, `token`, `fetch`).
    pub derived: BTreeMap<String, serde_json::Value>,
    /// Issuance refs created by `issuance` steps (session ids / offer
    /// URIs — handles, never subject data).
    pub issuance: BTreeMap<String, serde_json::Value>,
    /// Recorded bind verdicts by bind step id — verdict, primitive
    /// name, parameters; **never values** (§8.4).
    pub verdicts: BTreeMap<String, BindVerdict>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PresentationResult {
    /// credential query id → (format, verified claims object).
    pub credentials: BTreeMap<String, PresentedCredential>,
}

impl PresentationResult {
    pub fn credential(&self, id: &str) -> Option<&PresentedCredential> {
        self.credentials.get(id)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PresentedCredential {
    pub format: String,
    /// The verified claims (the verifier-core result's claims object).
    pub claims: serde_json::Value,
    /// The holder key the wallet proved (`cnf.jwk` / COSE key), as a
    /// JWK value.
    pub holder_key: Option<serde_json::Value>,
}

/// A recorded bind verdict (§8.4): matched, the primitive's name, its
/// parameters as written — never the values it compared.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BindVerdict {
    pub matched: bool,
    pub primitive: String,
    /// The primitive's parameters, as the definition wrote them
    /// (paths and names; the values they resolved against are not
    /// recorded).
    pub params: serde_json::Value,
}

impl FlowContext {
    /// Resolve a typed context reference (§5.4) to a value. Input
    /// refs read `inputs`; step refs read a presentation result's
    /// claims, walking the claims-path array with the credential's
    /// **format-aware** lookup (mdoc: literal namespace-qualified key
    /// first; SD-JWT: nested objects only — vc's `lookupClaimPath`,
    /// the same semantics issuer-core's IdentityMatch port carries).
    /// Unresolvable = refusal, never a skip (a primitive that cannot
    /// resolve declares it).
    pub fn resolve(&self, reference: &ContextRef) -> Result<serde_json::Value> {
        if let Some(input) = &reference.input {
            let Some(value) = self.inputs.get(input) else {
                return Err(crate::Error::context_unresolved(format!(
                    "the flow input {input:?} was not supplied at start"
                )));
            };
            return walk_path(value, &reference.path, &reference.render());
        }
        let Some(step) = &reference.step else {
            return Err(crate::Error::context_unresolved(format!(
                "{} names neither an input nor a step",
                reference.render()
            )));
        };
        // A presentation step: the ref may name the whole result, one
        // credential's claims, or a claim path within them.
        if let Some(result) = self.presentations.get(step) {
            let credential = match &reference.credential {
                Some(credential) => result.credential(credential).ok_or_else(|| {
                    crate::Error::context_unresolved(format!(
                        "step {step:?} presented no credential {credential:?}"
                    ))
                })?,
                None => return Ok(result_to_value(result, &reference.path)),
            };
            return lookup_claim_path(&credential.claims, &reference.path, &credential.format);
        }
        // A derived value (§5.5: the store/token/fetch step's output,
        // keyed by step id): the path walks the value. A credential
        // member on a derived ref is a definition error — derived
        // values are not presentations.
        if let Some(value) = self.derived.get(step) {
            if let Some(credential) = &reference.credential {
                return Err(crate::Error::context_unresolved(format!(
                    "{} names credential {credential:?}, but step {step:?} is a derived \
                     value, not a presentation",
                    reference.render()
                )));
            }
            return walk_path(value, &reference.path, &reference.render());
        }
        Err(crate::Error::context_unresolved(format!(
            "step {step:?} has neither a presentation result nor a derived value yet — \
             steps run in order (§5.2)"
        )))
    }
}

/// Format-aware claim lookup (vc `lookupClaimPath`, ported with the
/// issuer-core IdentityMatch port's semantics): mdoc tries the literal
/// namespace-qualified key first (a flat `org.iso.18013.5.1.…`
/// entry); SD-JWT walks nested objects only, so a flat dotted key
/// cannot satisfy a nested requirement. Paths are arrays, never
/// dotted strings (§5.4).
pub fn lookup_claim_path(
    claims: &serde_json::Value,
    path: &[String],
    format: &str,
) -> Result<serde_json::Value> {
    if path.is_empty() {
        return Ok(claims.clone());
    }
    if format == "mso_mdoc" {
        // The literal key: the path joined by dots as ONE key.
        let literal = path.join(".");
        if let Some(value) = claims.get(&literal) {
            return Ok(value.clone());
        }
    }
    let mut cursor = claims;
    for segment in path {
        cursor = cursor.get(segment).ok_or_else(|| {
            crate::Error::context_unresolved(format!(
                "the claims path {} does not resolve",
                path.join("/")
            ))
        })?;
    }
    Ok(cursor.clone())
}

/// Walk an input value's path (nested object segments; no format
/// rules — inputs are the caller's own shape).
fn walk_path(
    value: &serde_json::Value,
    path: &[String],
    rendered: &str,
) -> Result<serde_json::Value> {
    let mut cursor = value;
    for segment in path {
        cursor = cursor.get(segment).ok_or_else(|| {
            crate::Error::context_unresolved(format!("the path {rendered} does not resolve"))
        })?;
    }
    Ok(cursor.clone())
}

/// A whole presentation result as a value (credential ids as keys).
fn result_to_value(result: &PresentationResult, path: &[String]) -> serde_json::Value {
    if path.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = result
            .credentials
            .iter()
            .map(|(id, credential)| (id.clone(), credential.claims.clone()))
            .collect();
        return serde_json::Value::Object(map);
    }
    serde_json::Value::Null
}
