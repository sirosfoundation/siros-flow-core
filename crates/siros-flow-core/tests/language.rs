//! The flow language (design §5): fixture-backed — every definition in
//! `flows/` parses, validates, and digests (the goFF model: a
//! definition change is a visible diff against recorded expectations)
//! — plus the fail-closed negatives and the digest-identity tests
//! (§11: stability across YAML re-serialization, version refusal).

use std::path::PathBuf;

use siros_flow_core::language::{FlowDefinition, Step, LANGUAGE_VERSION};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

fn flows_dir() -> PathBuf {
    repo_root().join("flows")
}

fn load(name: &str) -> FlowDefinition {
    let text = std::fs::read_to_string(flows_dir().join(name))
        .unwrap_or_else(|e| panic!("reading flows/{name}: {e}"));
    FlowDefinition::from_yaml(&text)
        .unwrap_or_else(|e| panic!("flows/{name} must parse and validate: {e}"))
}

#[test]
fn every_shipped_flow_parses_validates_and_digests() {
    let mut entries: Vec<_> = std::fs::read_dir(flows_dir())
        .expect("the flows directory")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "yaml"))
        .collect();
    entries.sort();
    assert!(
        entries.len() >= 3,
        "the shipped flows are the fixture set — at least the three P-bw1/P-bw2 definitions"
    );
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let definition = load(&name);
        assert_eq!(definition.language_version, LANGUAGE_VERSION);
        // The digest is stable per content: same file, same digest.
        let again = load(&name);
        assert_eq!(
            definition.digest(),
            again.digest(),
            "{name}: the digest is content-determined"
        );
        assert!(
            !definition.steps.is_empty(),
            "{name}: a flow with no steps does nothing"
        );
    }
}

#[test]
fn the_early_ehic_flow_is_the_mode_b_shape() {
    let definition = load("ehic-pid-presentation.yaml");
    assert_eq!(definition.flow, "ehic-pid-presentation");
    // Present → issue, subject FROM the presentation: Mode B
    // semantics (the design doc's §8.5 early flow).
    match &definition.steps[0] {
        Step::Presentation(p) => {
            assert_eq!(p.id, "present-pid");
            // vct_values matches ANY listed type (DCQL §5.2) — the
            // registry's PID generations; the fixture lists them.
            let vct_values = p.request[0].meta["vct_values"]
                .as_array()
                .expect("the PID query lists its vct_values");
            assert!(vct_values.len() >= 2, "the fixture lists the generations");
        }
        other => panic!("the first step is a presentation, got {other:?}"),
    }
    match &definition.steps[1] {
        Step::Issuance(i) => {
            assert_eq!(i.credential, "urn:eudi:ehic:1");
            assert_eq!(i.subject.from.step.as_deref(), Some("present-pid"));
        }
        other => panic!("the second step is an issuance, got {other:?}"),
    }
}

#[test]
fn the_digest_is_stable_across_yaml_reformatting() {
    let definition = load("ehic-pid-presentation.yaml");
    // Re-serialize the DOCUMENT (YAML round-trip) and re-parse: the
    // typed form — and thus the digest — is the identity, not the
    // bytes (§5.4; §11's definition-identity test).
    let value: serde_json::Value = serde_yaml::from_str(
        &std::fs::read_to_string(flows_dir().join("ehic-pid-presentation.yaml")).unwrap(),
    )
    .unwrap();
    let reformatted = serde_yaml::to_string(&value).unwrap();
    let reparsed = FlowDefinition::from_yaml(&reformatted).unwrap();
    assert_eq!(definition.digest(), reparsed.digest());
}

#[test]
fn an_unknown_step_kind_refuses_at_load() {
    let error = FlowDefinition::from_yaml(
        "flow: bad-kind\nlanguage_version: 1\nsteps:\n  - teleport: {id: x}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
}

#[test]
fn a_two_key_step_entry_refuses_at_load() {
    let error = FlowDefinition::from_yaml(
        "flow: two-keys\nlanguage_version: 1\nsteps:\n  - presentation: {id: p}\n    bind: {id: b}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    assert!(error.message.contains("exactly one step kind"));
}

#[test]
fn an_unknown_language_version_refuses_at_load() {
    let error =
        FlowDefinition::from_yaml("flow: from-the-future\nlanguage_version: 2\nsteps:\n  - end\n")
            .unwrap_err();
    assert_eq!(error.code, "flow_language_version");
}

#[test]
fn an_empty_flow_name_refuses_and_the_name_grammar_holds() {
    let error = FlowDefinition::from_yaml("flow: \"\"\nlanguage_version: 1\nsteps:\n  - end\n")
        .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    let error =
        FlowDefinition::from_yaml("flow: Not_Snake\nlanguage_version: 1\nsteps:\n  - end\n")
            .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
}

#[test]
fn token_and_fetch_steps_parse_with_plugin_names() {
    // §6.4: a token step names its plugin and the input carrying the
    // JWT; the plugin validates the params at load (service-side).
    let definition = FlowDefinition::from_yaml(
        "flow: token-smoke\nlanguage_version: 1\nsteps:\n  - token:\n      id: consume-idp\n      plugin: test-idp\n      params:\n        token: {input: idp_assertion}\n",
    )
    .unwrap();
    let siros_flow_core::language::Step::Token(token) = &definition.steps[0] else {
        panic!("the first step is the token step");
    };
    assert_eq!(token.plugin, "test-idp");
    assert_eq!(
        token.params["token"]["input"], "idp_assertion",
        "the params carry the token reference verbatim (the plugin validates)"
    );

    // §6.5: a fetch step names its provider and declares the inputs
    // it may send (surface-checked at load, service-side).
    let definition = FlowDefinition::from_yaml(
        "flow: fetch-smoke\nlanguage_version: 1\nsteps:\n  - fetch:\n      id: employee-record\n      plugin: hr-api\n      inputs:\n        family_name: {step: present-pid, credential: pid, path: [family_name]}\n",
    )
    .unwrap();
    let siros_flow_core::language::Step::Fetch(fetch) = &definition.steps[0] else {
        panic!("the first step is the fetch step");
    };
    assert_eq!(fetch.plugin, "hr-api");
    assert!(fetch.inputs.contains_key("family_name"));
}

#[test]
fn every_shipped_flow_matches_the_recorded_digest() {
    // The goFF model: the recorded expectations live in
    // tests/fixtures/recorded-flow-digests.json — a definition change
    // is a VISIBLE diff against that file (the reviewer sees the
    // identity change, not just the YAML). A changed flow fails here
    // until the recorded digest is deliberately updated.
    let recorded: std::collections::BTreeMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/recorded-flow-digests.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../flows");
    let mut seen = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yaml") {
            let definition =
                FlowDefinition::from_yaml(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let digest = definition.digest().to_owned();
            let expected = recorded
                .get(&definition.flow)
                .unwrap_or_else(|| panic!("{} carries no recorded digest", definition.flow));
            assert_eq!(
                &digest, expected,
                "{}: the definition changed — update the recorded digest deliberately                  (tests/fixtures/recorded-flow-digests.json)",
                definition.flow
            );
            seen.insert(definition.flow.clone(), digest);
        }
    }
    assert_eq!(
        seen.len(),
        recorded.len(),
        "the recorded set and the shipped set agree (a removed flow leaves a stale record)"
    );
}

#[test]
fn notify_steps_parse_and_refuse_value_references() {
    // §6.6: the typed event — a stable kind token + an optional
    // definition-authored message LITERAL.
    let definition = FlowDefinition::from_yaml(
        "flow: notify-smoke\nlanguage_version: 1\nsteps:\n  - notify:\n      id: tell-done\n      event: credential-issued\n      message: The offer is ready\n",
    )
    .unwrap();
    let siros_flow_core::language::Step::Notify(notify) = &definition.steps[0] else {
        panic!("the first step is the notify step");
    };
    assert_eq!(notify.event, "credential-issued");
    assert_eq!(notify.message.as_deref(), Some("The offer is ready"));

    // A context REFERENCE as the message refuses at load: events are
    // narration, and context values never leave the process (§10.1)
    // nor ride event surfaces (§10.2). The message member is a
    // string literal by type — an object ref cannot deserialize.
    let error = FlowDefinition::from_yaml(
        "flow: notify-ref\nlanguage_version: 1\nsteps:\n  - notify:\n      id: t\n      event: e\n      message: {step: present, path: [given_name]}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");

    // The event kind is a stable token: an empty kind or a
    // non-token kind refuses.
    for bad in ["", "Not A Token"] {
        let yaml = format!(
            "flow: notify-bad\nlanguage_version: 1\nsteps:\n  - notify:\n      id: t\n      event: {bad:?}\n"
        );
        let error = FlowDefinition::from_yaml(&yaml).unwrap_err();
        assert_eq!(error.code, "flow_language_invalid", "{bad:?}");
    }
}

#[test]
fn the_carrier_vocabulary_is_closed() {
    // `dc_api` parses (the step names its carrier, §7)...
    let definition = FlowDefinition::from_yaml(
        "flow: dc-smoke\nlanguage_version: 1\nsteps:\n  - presentation:\n      id: p\n      carrier: dc_api\n      request:\n        - id: pid\n          format: dc+sd-jwt\n          meta: {vct_values: [\"urn:eudi:pid:1\"]}\n",
    )
    .unwrap();
    let siros_flow_core::language::Step::Presentation(step) = &definition.steps[0] else {
        panic!("the first step is the presentation");
    };
    assert_eq!(
        step.carrier,
        Some(siros_flow_core::language::Carrier::DcApi)
    );

    // ...and an absent carrier inherits the deployment default (None
    // here; the service resolves it against `service.default_carrier`).
    let definition = FlowDefinition::from_yaml(
        "flow: dl-smoke\nlanguage_version: 1\nsteps:\n  - presentation:\n      id: p\n      request:\n        - id: pid\n          format: dc+sd-jwt\n          meta: {vct_values: [\"urn:eudi:pid:1\"]}\n",
    )
    .unwrap();
    let siros_flow_core::language::Step::Presentation(step) = &definition.steps[0] else {
        panic!("the first step is the presentation");
    };
    assert_eq!(step.carrier, None);

    // WMP is a carrier of the same kind at P-bw4 (§7); naming it
    // today is a LOAD refusal — the closed vocabulary, never a
    // best-effort interpretation.
    let error = FlowDefinition::from_yaml(
        "flow: early-wmp\nlanguage_version: 1\nsteps:\n  - presentation:\n      id: p\n      carrier: wmp\n      request:\n        - id: pid\n          format: dc+sd-jwt\n          meta: {vct_values: [\"urn:eudi:pid:1\"]}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    assert!(
        error.message.contains("wmp"),
        "the refusal names the unknown carrier: {error}"
    );
}

#[test]
fn duplicate_step_ids_refuse_at_load() {
    let error = FlowDefinition::from_yaml(
        "flow: dup\nlanguage_version: 1\nsteps:\n  - presentation: {id: same, request: [{id: pid, format: dc+sd-jwt, meta: {vct_values: [urn:eudi:pid:1]}}]}\n  - store: {id: same, value: v}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    assert!(error.message.contains("duplicate step id"));
}

#[test]
fn a_presentation_with_an_unknown_format_refuses_at_load() {
    let error = FlowDefinition::from_yaml(
        "flow: bad-format\nlanguage_version: 1\nsteps:\n  - presentation: {id: p, request: [{id: x, format: jwt_vc_json, meta: {}}]}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    assert!(error.message.contains("dc+sd-jwt"));
}

#[test]
fn require_must_name_carried_queries() {
    let error = FlowDefinition::from_yaml(
        "flow: bad-require\nlanguage_version: 1\nsteps:\n  - presentation: {id: p, request: [{id: pid, format: dc+sd-jwt, meta: {vct_values: [urn:eudi:pid:1]}}], require: [other]}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    assert!(error.message.contains("require"));
}

#[test]
fn a_subject_derivation_must_name_a_typed_source() {
    // A bare path (dotted-string style) is refused — references are
    // typed objects (§5.4: mdoc namespaces contain dots).
    let error = FlowDefinition::from_yaml(
        "flow: bare-ref\nlanguage_version: 1\nsteps:\n  - issuance: {id: i, credential: urn:eudi:ehic:1, subject: {from: {path: [given_name]}}}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    assert!(error.message.contains("neither an input nor a step"));
}

#[test]
fn a_when_matcher_must_reference_a_bind_step() {
    let error = FlowDefinition::from_yaml(
        "flow: bad-when\nlanguage_version: 1\nsteps:\n  - presentation: {id: p, request: [{id: pid, format: dc+sd-jwt, meta: {vct_values: [urn:eudi:pid:1]}}]}\n  - bind: {id: b, primitive: same-key, params: {left: {step: p, credential: pid, path: [cnf, jwk]}, right: {step: p, credential: pid, path: [cnf, jwk]}}, when: {step: p, matched: true}}\n",
    )
    .unwrap_err();
    assert_eq!(error.code, "flow_language_invalid");
    assert!(error.message.contains("not a bind step"));
}

#[test]
fn end_is_a_step_and_carries_no_parameters() {
    let definition =
        FlowDefinition::from_yaml("flow: early-end\nlanguage_version: 1\nsteps:\n  - end\n")
            .unwrap();
    assert!(matches!(definition.steps[0], Step::End));
}
