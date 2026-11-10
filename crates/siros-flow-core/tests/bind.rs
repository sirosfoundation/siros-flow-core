//! The bind vocabulary (design §8): the owner's rule — **comparisons
//! are plugin-only except where they are 100% unequivocal** — and the
//! semantics of the one built-in plus the two P-bw1 reference
//! plugins. Sources of truth: vc's `identity_match.go` (rule-match,
//! via the issuer-core port), vc's `lookupClaimPath` (format-aware
//! paths), RFC 7638 (same-key's thumbprints).

use serde_json::json;

use siros_flow_core::bind::{
    BindPrimitive, BindRegistry, ClaimEquals, PseudonymEquals, RuleMatch, SameKey,
};
use siros_flow_core::context::{FlowContext, PresentationResult, PresentedCredential};
use siros_flow_core::language::ContextRef;

fn context_with_pid(claims: serde_json::Value, holder_key: serde_json::Value) -> FlowContext {
    let mut context = FlowContext::default();
    let mut result = PresentationResult::default();
    result.credentials.insert(
        "pid".to_owned(),
        PresentedCredential {
            format: "dc+sd-jwt".to_owned(),
            claims,
            holder_key: Some(holder_key),
        },
    );
    context
        .presentations
        .insert("present-pid".to_owned(), result);
    context
}

fn ec_jwk(x: &str) -> serde_json::Value {
    json!({ "kty": "EC", "crv": "P-256", "x": x, "y": "y", "alg": "ES256" })
}

// ─── same-key: the one built-in ────────────────────────────────────────────

#[test]
fn same_key_compares_the_recorded_holder_keys_by_thumbprint() {
    // RFC 7638: the SAME key material thumbprints equal; different
    // material does not. The context shape is the engine's (§5.5):
    // each presented credential carries its holder key.
    let key = ec_jwk("same-x");
    let mut context = context_with_pid(json!({}), key.clone());
    let mut other = context
        .presentations
        .get_mut("present-pid")
        .unwrap()
        .clone();
    other.credentials.insert(
        "poa".to_owned(),
        PresentedCredential {
            format: "dc+sd-jwt".to_owned(),
            claims: json!({}),
            holder_key: Some(key.clone()),
        },
    );
    // And a third credential with a DIFFERENT key.
    other.credentials.insert(
        "sca".to_owned(),
        PresentedCredential {
            format: "dc+sd-jwt".to_owned(),
            claims: json!({}),
            holder_key: Some(ec_jwk("other-x")),
        },
    );
    context
        .presentations
        .insert("present-pid".to_owned(), other);

    let params = json!({
        "left":  { "step": "present-pid", "credential": "pid", "path": [] },
        "right": { "step": "present-pid", "credential": "poa", "path": [] },
    });
    SameKey.validate_params(&params).unwrap();
    assert!(
        SameKey.bind(&context, &params).unwrap().matched,
        "the same holder key matches"
    );

    let params = json!({
        "left":  { "step": "present-pid", "credential": "pid", "path": [] },
        "right": { "step": "present-pid", "credential": "sca", "path": [] },
    });
    assert!(
        !SameKey.bind(&context, &params).unwrap().matched,
        "a different holder key mismatches"
    );
}

#[test]
fn same_key_refuses_a_claim_path_and_a_missing_key_fail_closed() {
    let context = context_with_pid(json!({ "given_name": "A" }), ec_jwk("x"));

    // A holder key is addressed by the credential ALONE: a claim path
    // on a key ref is a definition error, refused at validate time
    // (fail-closed, §5.4 — a key is not a claim).
    let params = json!({
        "left":  { "step": "present-pid", "credential": "pid", "path": ["given_name"] },
        "right": { "step": "present-pid", "credential": "pid", "path": [] },
    });
    let error = SameKey.bind(&context, &params).unwrap_err();
    assert!(
        error.message.contains("claim path"),
        "a path on a key ref refuses: {error}"
    );

    // A credential that carried no holder key (an anonymous
    // presentation) cannot satisfy a key comparison: declared
    // mismatch, never best-effort (§8.2 determinism).
    let mut bare = FlowContext::default();
    let mut result = PresentationResult::default();
    result.credentials.insert(
        "mdoc".to_owned(),
        PresentedCredential {
            format: "mso_mdoc".to_owned(),
            claims: json!({}),
            holder_key: None,
        },
    );
    bare.presentations.insert("present".to_owned(), result);
    let params = json!({
        "left":  { "step": "present", "credential": "mdoc", "path": [] },
        "right": { "step": "present", "credential": "mdoc", "path": [] },
    });
    let error = SameKey.bind(&bare, &params).unwrap_err();
    assert!(
        error.message.contains("no holder key"),
        "a missing holder key is a refusal, not a pass: {error}"
    );
}

#[test]
fn holder_keys_with_private_material_are_refused() {
    // The context never carries private material; a holder key that
    // arrives with a `d` member is refused — the built-in checks it.
    let mut context = FlowContext::default();
    let mut result = PresentationResult::default();
    result.credentials.insert(
        "pid".to_owned(),
        PresentedCredential {
            format: "dc+sd-jwt".to_owned(),
            claims: json!({}),
            holder_key: Some(json!({
                "kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "secret"
            })),
        },
    );
    context.presentations.insert("present".to_owned(), result);
    let params = json!({
        "left":  { "step": "present", "credential": "pid", "path": [] },
        "right": { "step": "present", "credential": "pid", "path": [] },
    });
    let error = SameKey.bind(&context, &params).unwrap_err();
    assert!(
        error.message.contains("private material"),
        "private key material in the context is refused: {error}"
    );
}

// ─── rule-match: the reference plugin (vc's IdentityMatch, reused) ─────────

#[test]
fn rule_match_binds_the_callers_rule_against_a_presentation() {
    let mut context = context_with_pid(
        json!({ "given_name": "Presented", "family_name": "Subject" }),
        ec_jwk("x"),
    );
    context.inputs.insert(
        "identity_match".to_owned(),
        json!({ "claims": {
            "given_name": { "equals": "Presented" },
            "family_name": { "equals": "Subject" }
        }}),
    );
    let params = json!({
        "against": { "step": "present-pid", "credential": "pid", "path": [] },
        "rule_from": { "input": "identity_match" },
    });
    RuleMatch.validate_params(&params).unwrap();
    let outcome = RuleMatch.bind(&context, &params).unwrap();
    assert!(outcome.matched);

    // The wrong person: mismatch, and the message names the rule's
    // paths — never values.
    context.inputs.insert(
        "identity_match".to_owned(),
        json!({ "claims": { "family_name": { "equals": "Someone Else" } } }),
    );
    let outcome = RuleMatch.bind(&context, &params).unwrap();
    assert!(!outcome.matched);
    let mismatch = outcome.mismatch.unwrap();
    assert!(mismatch.contains("family_name"), "{mismatch}");
    assert!(
        !mismatch.contains("Someone Else"),
        "never values: {mismatch}"
    );
}

#[test]
fn rule_match_refuses_an_empty_callers_rule() {
    let mut context = context_with_pid(json!({}), ec_jwk("x"));
    context
        .inputs
        .insert("identity_match".to_owned(), json!({ "claims": {} }));
    let params = json!({
        "against": { "step": "present-pid", "credential": "pid", "path": [] },
        "rule_from": { "input": "identity_match" },
    });
    let error = RuleMatch.bind(&context, &params).unwrap_err();
    assert!(
        error.message.contains("no claims to match on"),
        "vc's discipline: an empty rule is refused, not treated as anything-goes: {error}"
    );
}

// ─── claim-equals: the reference plugin ────────────────────────────────────

#[test]
fn claim_equals_compares_typed_refs_exactly() {
    let context = context_with_pid(
        json!({ "given_name": "Presented", "roles": ["admin", "signatory"] }),
        ec_jwk("x"),
    );
    let params = json!({
        "left":  { "step": "present-pid", "credential": "pid", "path": ["given_name"] },
        "right": { "literal": "Presented" },
    });
    ClaimEquals.validate_params(&params).unwrap();
    assert!(ClaimEquals.bind(&context, &params).unwrap().matched);

    let params = json!({
        "left":  { "step": "present-pid", "credential": "pid", "path": ["roles"] },
        "right": { "literal": "signatory" },
    });
    // An array matches when an element equals it (vc's
    // claimValueMatches).
    let outcome = ClaimEquals.bind(&context, &params).unwrap();
    assert!(
        outcome.matched,
        "an array satisfies a value comparison when an element equals it"
    );
}

#[test]
fn format_aware_paths_mdoc_literal_key_first() {
    let mut context = FlowContext::default();
    let mut result = PresentationResult::default();
    result.credentials.insert(
        "mdoc".to_owned(),
        PresentedCredential {
            format: "mso_mdoc".to_owned(),
            claims: json!({ "org.iso.18013.5.1.birth_date": "1999-12-31" }),
            holder_key: None,
        },
    );
    context.presentations.insert("present".to_owned(), result);
    // The mdoc literal namespace-qualified key resolves as ONE key.
    let value = context
        .resolve(&ContextRef {
            input: None,
            step: Some("present".to_owned()),
            credential: Some("mdoc".to_owned()),
            path: vec!["org.iso.18013.5.1.birth_date".to_owned()],
        })
        .unwrap();
    assert_eq!(value, json!("1999-12-31"));
}

// ─── the registry ──────────────────────────────────────────────────────────

#[test]
fn the_registry_resolves_builtins_and_reference_plugins() {
    let registry = BindRegistry::standard();
    assert!(registry.resolve("same-key").is_ok());
    assert!(registry.resolve("rule-match").is_ok());
    assert!(registry.resolve("claim-equals").is_ok());
    assert!(registry.resolve("pseudonym-equals").is_ok());
    let error = registry.resolve("fuzzy-names").err().unwrap();
    assert_eq!(error.code, "bind_unknown_primitive");
    assert!(
        error.message.contains("fuzzy-names"),
        "the refusal names the unknown primitive: {error}"
    );
}

#[test]
fn a_deployments_own_plugin_is_the_same_trait() {
    struct SameOrg;
    impl BindPrimitive for SameOrg {
        fn name(&self) -> &'static str {
            "same-org"
        }
        fn validate_params(&self, params: &serde_json::Value) -> siros_flow_core::Result<()> {
            if params.get("org_path").is_none() {
                return Err(siros_flow_core::Error::language_invalid(
                    "same-org: an org_path is required",
                ));
            }
            Ok(())
        }
        fn bind(
            &self,
            _context: &FlowContext,
            _params: &serde_json::Value,
        ) -> siros_flow_core::Result<siros_flow_core::bind::BindOutcome> {
            Ok(siros_flow_core::bind::BindOutcome {
                matched: true,
                mismatch: None,
            })
        }
    }
    let registry = BindRegistry::standard().with(Box::new(SameOrg));
    assert!(registry.resolve("same-org").is_ok());
    // The exit criterion's shape: a deployment's plugin is registered
    // on the same trait the reference plugins use — nothing
    // engine-privileged (§8.3).
    let _: &dyn BindPrimitive = registry.resolve("rule-match").unwrap();
}

// ─── pseudonym-equals: the P-bw2 reference plugin ──────────────────────────

#[test]
fn pseudonym_equals_compares_presented_against_the_sessions_value() {
    // ADR 002's shape: the WALLET presents the pseudonym it derived
    // for this RP scope; the session knows the value it recorded for
    // this subject. The plugin compares the two — it never derives
    // (§8.2: derivation inputs must not reach the engine).
    let mut context = context_with_pid(json!({ "pseudonym": "nym_9f3a_rp-scope-42" }), ec_jwk("x"));
    context.inputs.insert(
        "session".to_owned(),
        json!({ "subject_pseudonym": "nym_9f3a_rp-scope-42" }),
    );

    let params = json!({
        "presented": { "step": "present-pid", "credential": "pid", "path": ["pseudonym"] },
        "expected":  { "input": "session", "path": ["subject_pseudonym"] },
    });
    PseudonymEquals.validate_params(&params).unwrap();
    assert!(PseudonymEquals.bind(&context, &params).unwrap().matched);

    // A different subject's pseudonym: mismatch, and the refusal
    // message names the comparison — never the values (§10).
    context.inputs.insert(
        "session".to_owned(),
        json!({ "subject_pseudonym": "nym_other" }),
    );
    let outcome = PseudonymEquals.bind(&context, &params).unwrap();
    assert!(!outcome.matched);
    let mismatch = outcome.mismatch.unwrap();
    assert!(
        !mismatch.contains("nym_") && !mismatch.contains("other"),
        "never values: {mismatch}"
    );
}

#[test]
fn pseudonym_equals_params_refuse_at_load_fail_closed() {
    // Malformed params refuse at LOAD (validate_params — the
    // plugin-allowlist discipline, §8.3), never mid-flow; and the
    // refusal is attributed to THIS plugin (the ref parser carries
    // the primitive's name).
    let missing_presented = json!({
        "expected": { "input": "session", "path": ["subject_pseudonym"] },
    });
    let error = PseudonymEquals
        .validate_params(&missing_presented)
        .unwrap_err();
    assert!(
        error.message.contains("pseudonym-equals"),
        "attributed to the plugin: {error}"
    );
    assert!(
        error.message.contains("presented"),
        "names the missing side: {error}"
    );

    let missing_expected = json!({
        "presented": { "step": "s", "credential": "pid", "path": ["pseudonym"] },
    });
    let error = PseudonymEquals
        .validate_params(&missing_expected)
        .unwrap_err();
    assert!(
        error.message.contains("expected"),
        "an expected reference is required: {error}"
    );

    // A LITERAL expected value is a definition carrying subject data —
    // a pseudonym arrives as a flow INPUT; the literal shape refuses.
    let literal = json!({
        "presented": { "step": "s", "credential": "pid", "path": ["pseudonym"] },
        "expected": { "literal": "nym_from_the_definition" },
    });
    let error = PseudonymEquals.validate_params(&literal).unwrap_err();
    assert!(
        error.message.contains("expected reference"),
        "the expected side must be a reference: {error}"
    );
}

// ─── the load-time allowlist discipline (§8.3) ─────────────────────────────

/// A minimal definition whose one bind step carries the given
/// primitive + params (from_yaml is the loader's own front door).
fn definition_with_bind(
    primitive: &str,
    params: &serde_json::Value,
) -> siros_flow_core::language::FlowDefinition {
    let yaml = format!(
        "flow: allowlist-check\nlanguage_version: 1\nsteps:\n  - bind:\n      id: b\n      primitive: {primitive}\n      params: {}\n",
        serde_json::to_string(params).unwrap()
    );
    siros_flow_core::language::FlowDefinition::from_yaml(&yaml).unwrap()
}

#[test]
fn validate_definition_refuses_unknown_primitives_and_malformed_params() {
    use siros_flow_core::bind::validate_definition;
    let registry = BindRegistry::standard();

    // A definition referencing a plugin OUTSIDE the registry refuses
    // at LOAD (§8.3 — the allowlist discipline), never mid-flow.
    let unknown = definition_with_bind("fuzzy-names", &json!({}));
    let error = validate_definition(&unknown, &registry).unwrap_err();
    assert_eq!(error.code, "bind_unknown_primitive");

    // MALFORMED parameters refuse at load too (fail-closed: a
    // definition naming them never runs).
    let malformed = definition_with_bind(
        "same-key",
        &json!({ "left": { "step": "p", "credential": "pid", "path": [] } }),
    );
    let error = validate_definition(&malformed, &registry).unwrap_err();
    assert!(
        error.message.contains("right"),
        "names the missing side: {error}"
    );

    // A well-formed step passes, and a deployment's own registered
    // plugin is the same shape (nothing engine-privileged).
    let well_formed = definition_with_bind(
        "pseudonym-equals",
        &json!({
            "presented": { "step": "p", "credential": "pid", "path": ["pseudonym"] },
            "expected": { "input": "session", "path": ["subject_pseudonym"] },
        }),
    );
    validate_definition(&well_formed, &registry).unwrap();
}

#[test]
fn every_shipped_flow_validates_against_the_standard_registry() {
    // The service runs this at startup (app.rs); the shipped set is
    // the reviewed set — it must all pass the same validation.
    use siros_flow_core::bind::validate_definition;
    let registry = BindRegistry::standard();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../flows");
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yaml") {
            let definition = siros_flow_core::language::FlowDefinition::from_yaml(
                &std::fs::read_to_string(&path).unwrap(),
            )
            .unwrap();
            validate_definition(&definition, &registry)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }
}
