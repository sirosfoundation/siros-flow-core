//! Identity binding (design §8): the generic concept — *does this
//! presented credential describe the same subject as this session (or
//! this other credential)?* — assembled from **bind primitives**.
//!
//! The vocabulary rule (owner, v0.3): **comparisons are plugin-only
//! except where they are 100% unequivocal.** `same-key` is the one
//! built-in (key identity: same key or not, thumbprint to thumbprint,
//! no interpretation, no identity inference riding on a value).
//! Everything that compares *values* is a **reference plugin** —
//! shipped, reviewed, allowlisted code on the same trait a
//! deployment's own plugin would use, nothing engine-privileged.
//!
//! A primitive is pure math over the context. It never decides trust
//! (§9) and its recorded evidence carries names and parameters, never
//! values (§10).

use crate::context::FlowContext;
use crate::error::{code, Error, Result};
use crate::language::ContextRef;

/// One bind primitive (the extension point — built-ins and reference
/// plugins are the same shape; a deployment's own plugin is the same
/// trait).
pub trait BindPrimitive: Send + Sync {
    /// The name the flow language references (`primitive: <name>`).
    fn name(&self) -> &'static str;
    /// Validate this primitive's parameters against a bind step's
    /// `params` at LOAD time (fail-closed: a definition naming
    /// malformed parameters refuses before any flow runs).
    fn validate_params(&self, params: &serde_json::Value) -> Result<()>;
    /// Evaluate: the context → verdict. The verdict's evidence carries
    /// the primitive name and parameters, never values.
    fn bind(&self, context: &FlowContext, params: &serde_json::Value) -> Result<BindOutcome>;
}

/// The outcome one primitive returns: matched or not, plus the
/// refusal message on mismatch (names paths, never values).
#[derive(Debug)]
pub struct BindOutcome {
    pub matched: bool,
    /// Names the comparison that failed (paths, ids — never values).
    pub mismatch: Option<String>,
}

// ─── The one built-in ──────────────────────────────────────────────────────

/// `same-key` — the one built-in (100% unequivocal): both named
/// credentials' holder keys are the same key, by RFC 7638 SHA-256
/// thumbprint. Narrowly applicable by design (under the ARF each
/// attestation carries its own key); use it when the credentials'
/// rulebooks guarantee it.
pub struct SameKey;

const SAME_KEY: &str = "same-key";

impl BindPrimitive for SameKey {
    fn name(&self) -> &'static str {
        SAME_KEY
    }

    fn validate_params(&self, params: &serde_json::Value) -> Result<()> {
        for side in ["left", "right"] {
            parse_ref(SAME_KEY, params, side)?;
        }
        Ok(())
    }

    fn bind(&self, context: &FlowContext, params: &serde_json::Value) -> Result<BindOutcome> {
        let left = holder_thumbprint(context, &parse_ref(SAME_KEY, params, "left")?)?;
        let right = holder_thumbprint(context, &parse_ref(SAME_KEY, params, "right")?)?;
        Ok(BindOutcome {
            matched: left == right,
            mismatch: if left == right {
                None
            } else {
                Some("the two credentials' holder keys differ".to_owned())
            },
        })
    }
}

fn parse_ref(primitive: &str, params: &serde_json::Value, side: &str) -> Result<ContextRef> {
    let value = params.get(side).ok_or_else(|| {
        Error::language_invalid(format!("{primitive}: a {side} reference is required"))
    })?;
    serde_json::from_value(value.clone())
        .map_err(|e| Error::language_invalid(format!("{primitive}: the {side} reference: {e}")))
}

/// The holder key of the credential a `same-key` side names: the key
/// the presentation step recorded (SD-JWT `cnf.jwk` / mdoc
/// `DeviceKey` — extracted by the verifier, §8.2), RFC 7638
/// thumbprinted. The ref names the step's credential; a claim path is
/// a definition error (a key is not a claim — fail-closed, §5.4), and
/// the ref must name both the step and the credential.
fn holder_thumbprint(context: &FlowContext, reference: &ContextRef) -> Result<String> {
    if !reference.path.is_empty() {
        return Err(Error::language_invalid(format!(
            "same-key: {} names a claim path; the holder key is addressed by the credential alone",
            reference.render()
        )));
    }
    let Some(step) = &reference.step else {
        return Err(Error::context_unresolved(format!(
            "same-key: {} names no presentation step",
            reference.render()
        )));
    };
    let Some(result) = context.presentations.get(step) else {
        return Err(Error::context_unresolved(format!(
            "step {step:?} has no presentation result yet — steps run in order (§5.2)"
        )));
    };
    let Some(credential) = &reference.credential else {
        return Err(Error::context_unresolved(format!(
            "same-key: {} names no credential",
            reference.render()
        )));
    };
    let Some(presented) = result.credential(credential) else {
        return Err(Error::context_unresolved(format!(
            "step {step:?} presented no credential {credential:?}"
        )));
    };
    let key_value = presented.holder_key.clone().ok_or_else(|| {
        Error::context_unresolved(format!(
            "the credential {credential:?} presented at {step:?} carries no holder key"
        ))
    })?;
    let jwk: jose_rs::jwk::Jwk = serde_json::from_value(key_value).map_err(|e| {
        Error::context_unresolved(format!(
            "the holder key of {credential:?} is not a JWK ({e})"
        ))
    })?;
    if jwk.d.is_some() {
        return Err(Error::context_unresolved(format!(
            "the holder key of {credential:?} carries private material — refused"
        )));
    }
    jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk)
        .map_err(|e| Error::context_unresolved(format!("the holder key of {credential:?}: {e}")))
}

// ─── The reference plugins ─────────────────────────────────────────────────

/// Validate a definition's bind steps against a registry (§8.3, the
/// plugin-allowlist discipline): every `primitive:` name resolves and
/// its params pass the primitive's own `validate_params` — a
/// definition referencing a plugin outside the allowlist, or naming
/// malformed parameters, refuses at LOAD, never mid-flow.
pub fn validate_definition(
    definition: &crate::language::FlowDefinition,
    registry: &BindRegistry,
) -> Result<()> {
    for step in &definition.steps {
        if let crate::language::Step::Bind(bind) = step {
            let primitive = registry.resolve(&bind.primitive)?;
            primitive.validate_params(&bind.params)?;
        }
    }
    Ok(())
}

/// `rule-match` — reference plugin: a rule (claim path → expected
/// value) supplied by the flow's **initiating caller** (a flow input;
/// never in the definition — only the caller knows what "the same
/// user" means for its session), evaluated against one presentation.
/// vc's `IdentityMatch` semantics, verbatim — the issuer-core §6.5
/// port reused, not duplicated: every entry must pass, empty refused,
/// format-aware path lookup, exact compare deliberately not
/// normalized. On name attributes it is exact as a comparison but
/// **probabilistic as identity evidence** — the flow says so by
/// naming this plugin (§8.2).
pub struct RuleMatch;

const RULE_MATCH: &str = "rule-match";

impl BindPrimitive for RuleMatch {
    fn name(&self) -> &'static str {
        RULE_MATCH
    }

    fn validate_params(&self, params: &serde_json::Value) -> Result<()> {
        parse_ref(RULE_MATCH, params, "against")?;
        if params
            .get("rule_from")
            .and_then(|v| v.get("input"))
            .is_none()
        {
            return Err(Error::language_invalid(
                "rule-match: rule_from.input names the flow input carrying the caller's rule",
            ));
        }
        Ok(())
    }

    fn bind(&self, context: &FlowContext, params: &serde_json::Value) -> Result<BindOutcome> {
        let against = parse_ref(RULE_MATCH, params, "against")?;
        let rule_input = params
            .get("rule_from")
            .and_then(|v| v.get("input"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::language_invalid("rule-match: rule_from.input names the rule's input")
            })?
            .to_owned();
        let rule_value = context.resolve(&ContextRef {
            input: Some(rule_input),
            step: None,
            credential: None,
            path: Vec::new(),
        })?;
        let rule: siros_issuer_core::oid4vci::IdentityMatch = serde_json::from_value(rule_value)
            .map_err(|e| Error::invalid_input(format!("the identity-match rule: {e}")))?;
        rule.validate().map_err(issuer_error)?;
        let (format, claims) = resolve_presentation_claims(context, &against)?;
        let matched = rule
            .matches(&claims, format == "mso_mdoc")
            .map_err(issuer_error)?;
        Ok(BindOutcome {
            matched,
            mismatch: if matched {
                None
            } else {
                Some(format!(
                    "the presented credential does not satisfy the rule ({})",
                    rule.claim_paths().join(", ")
                ))
            },
        })
    }
}

/// An issuer-core error crossing the primitive boundary: same
/// codes where shared, invalid_input otherwise — stable either way.
fn issuer_error(error: siros_issuer_core::Error) -> Error {
    Error::new(crate::error::code::INVALID_INPUT, error.message)
}

/// `pseudonym-equals` — reference plugin: a pseudonym the **wallet
/// presented** (a claim such as the ADR 002 RP-scoped pseudonym, or a
/// ZK public output such as nym_auth's) equals the value the session
/// knows for this subject under this RP scope. The plugin compares; it
/// **never derives** (§1: the wallet derives, flow-core compares — an
/// RP holding the nonce could compute every other RP's pseudonym, so
/// the derivation inputs never reach the engine). Unequivocal *only if*
/// ADR 002's lifecycle guarantees hold (stability across PID renewal,
/// wallet replacement, recovery); until they do, a mismatch is not
/// proof of different identity — plugin, not built-in, for exactly
/// that reason (§8.2).
pub struct PseudonymEquals;

const PSEUDONYM_EQUALS: &str = "pseudonym-equals";

impl BindPrimitive for PseudonymEquals {
    fn name(&self) -> &'static str {
        PSEUDONYM_EQUALS
    }

    fn validate_params(&self, params: &serde_json::Value) -> Result<()> {
        parse_ref(PSEUDONYM_EQUALS, params, "presented")?;
        // The session-side value: a context ref (the recorded source of
        // the expected pseudonym) — never a literal in the definition
        // (a pseudonym is subject data; it arrives as a flow INPUT).
        // PARSED here, not merely present: a malformed ref refuses at
        // LOAD (fail-closed), never mid-flow.
        let expected = params.get("expected").ok_or_else(|| {
            Error::language_invalid(
                "pseudonym-equals: an expected reference is required (a flow input carrying the session's pseudonym for this subject)",
            )
        })?;
        serde_json::from_value::<ContextRef>(expected.clone()).map_err(|e| {
            Error::language_invalid(format!("pseudonym-equals: the expected reference: {e}"))
        })?;
        Ok(())
    }

    fn bind(&self, context: &FlowContext, params: &serde_json::Value) -> Result<BindOutcome> {
        let presented_ref = parse_ref(PSEUDONYM_EQUALS, params, "presented")?;
        let presented = context.resolve(&presented_ref)?;
        let expected: ContextRef = serde_json::from_value(params["expected"].clone())
            .map_err(|e| Error::language_invalid(format!("pseudonym-equals: expected: {e}")))?;
        let expected_value = context.resolve(&expected)?;
        let matched = values_equal(&presented, &expected_value);
        Ok(BindOutcome {
            matched,
            mismatch: if matched {
                None
            } else {
                Some(
                    "the presented pseudonym differs from the session's value for this subject and RP scope"
                        .to_owned(),
                )
            },
        })
    }
}

/// `claim-equals` — reference plugin: the claim at context path `left`
/// equals the claim at path `right` (or a caller-supplied literal).
/// Exact, format-aware path lookup; a value comparison, so the flow
/// says what it means by naming the plugin (§8.2).
pub struct ClaimEquals;

const CLAIM_EQUALS: &str = "claim-equals";

impl BindPrimitive for ClaimEquals {
    fn name(&self) -> &'static str {
        CLAIM_EQUALS
    }

    fn validate_params(&self, params: &serde_json::Value) -> Result<()> {
        parse_ref(CLAIM_EQUALS, params, "left")?;
        if params.get("right").is_none() {
            return Err(Error::language_invalid(
                "claim-equals: a right reference (or literal) is required",
            ));
        }
        Ok(())
    }

    fn bind(&self, context: &FlowContext, params: &serde_json::Value) -> Result<BindOutcome> {
        let left_ref = parse_ref(CLAIM_EQUALS, params, "left")?;
        let left = context.resolve(&left_ref)?;
        // The right side: a typed ref, a `{literal: …}` object, or a
        // bare literal — the object-with-one-literal-key form keeps
        // literals explicit in YAML (a bare string right side is
        // unambiguous too).
        let right = match params.get("right") {
            Some(serde_json::Value::Object(map))
                if map.len() == 1 && map.contains_key("literal") =>
            {
                map.get("literal").cloned().unwrap_or_default()
            }
            Some(serde_json::Value::Object(_)) => {
                let right_ref: ContextRef = serde_json::from_value(params["right"].clone())
                    .map_err(|e| Error::language_invalid(format!("claim-equals: right: {e}")))?;
                context.resolve(&right_ref)?
            }
            Some(literal) => literal.clone(),
            None => return Err(Error::language_invalid("claim-equals: no right side")),
        };
        let matched = values_equal(&left, &right);
        Ok(BindOutcome {
            matched,
            mismatch: if matched {
                None
            } else {
                Some(format!(
                    "the claim at {} differs from its comparison",
                    left_ref.render()
                ))
            },
        })
    }
}

/// Exact equality on strings (and string arrays containing the value —
/// vc `claimValueMatches`); other shapes do not satisfy a value
/// comparison.
fn values_equal(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    match (left, right) {
        (serde_json::Value::String(a), serde_json::Value::String(b)) => a == b,
        (serde_json::Value::Array(elements), serde_json::Value::String(b)) => {
            elements.iter().any(|e| e.as_str() == Some(b.as_str()))
        }
        (serde_json::Value::String(a), serde_json::Value::Array(elements)) => {
            elements.iter().any(|e| e.as_str() == Some(a.as_str()))
        }
        _ => false,
    }
}

/// Resolve a reference to (format, claims) of the presentation it
/// names (rule-match evaluates against a whole credential).
fn resolve_presentation_claims(
    context: &FlowContext,
    reference: &ContextRef,
) -> Result<(String, serde_json::Value)> {
    let Some(step) = &reference.step else {
        return Err(Error::context_unresolved(format!(
            "{} does not name a presentation step",
            reference.render()
        )));
    };
    let Some(result) = context.presentations.get(step) else {
        return Err(Error::context_unresolved(format!(
            "step {step:?} has no presentation result yet"
        )));
    };
    let Some(credential_id) = &reference.credential else {
        return Err(Error::context_unresolved(format!(
            "{} does not name a credential",
            reference.render()
        )));
    };
    let Some(credential) = result.credential(credential_id) else {
        return Err(Error::context_unresolved(format!(
            "step {step:?} presented no credential {credential_id:?}"
        )));
    };
    Ok((credential.format.clone(), credential.claims.clone()))
}

// ─── The registry ──────────────────────────────────────────────────────────

/// The primitive registry the engine resolves `primitive:` names
/// against: the built-ins plus the allowlisted plugins (§8.3). An
/// unknown name is a load refusal — the plugin-allowlist discipline.
pub struct BindRegistry {
    primitives: Vec<Box<dyn BindPrimitive>>,
}

impl BindRegistry {
    /// The default registry: the `same-key` built-in and the
    /// reference plugins (`rule-match`, `claim-equals`). A deployment
    /// adds its own on the same trait.
    pub fn standard() -> Self {
        Self {
            primitives: vec![
                Box::new(SameKey),
                Box::new(RuleMatch),
                Box::new(ClaimEquals),
                Box::new(PseudonymEquals),
            ],
        }
    }

    pub fn with(mut self, primitive: Box<dyn BindPrimitive>) -> Self {
        self.primitives.push(primitive);
        self
    }

    pub fn resolve(&self, name: &str) -> Result<&dyn BindPrimitive> {
        self.primitives
            .iter()
            .map(|primitive| primitive.as_ref())
            .find(|primitive| primitive.name() == name)
            .ok_or_else(|| {
                Error::new(
                    code::BIND_UNKNOWN_PRIMITIVE,
                    format!(
                        "bind primitive {name:?} is neither a built-in nor an allowlisted plugin"
                    ),
                )
            })
    }
}

impl Default for BindRegistry {
    fn default() -> Self {
        Self::standard()
    }
}
