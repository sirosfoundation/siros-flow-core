//! Parse, validate, and digest a flow definition — the language's whole
//! public surface in one run.
//!
//! ```sh
//! cargo run -p siros-flow-core --example parse-and-validate -- flows/ehic-pid-presentation.yaml
//! ```
//!
//! Fail-closed at every shape: a definition that does not parse, does not
//! validate, or carries the wrong `language_version` is a refusal with a
//! stable `code()`, never a patched-up parse.

use siros_flow_core::language::{FlowDefinition, Step};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "flows/ehic-pid-presentation.yaml".to_owned());
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("reading {path}: {e}");
        std::process::exit(1);
    });

    // Parse + validate: two calls, both fallible, both fail-closed.
    let definition = FlowDefinition::from_yaml(&text).unwrap_or_else(|e| {
        eprintln!("parse refused: {} [{}]", e, e.code);
        std::process::exit(1);
    });
    definition.validate().unwrap_or_else(|e| {
        eprintln!("validate refused: {} [{}]", e, e.code);
        std::process::exit(1);
    });

    // The identity the PDP evidence pins (§5.4): the content digest.
    println!("flow:       {}", definition.flow);
    println!("digest:     {}", definition.digest());
    println!("steps ({}):", definition.steps.len());
    for (i, step) in definition.steps.iter().enumerate() {
        let kind = match step {
            Step::Presentation(_) => "presentation",
            Step::Bind(_) => "bind",
            Step::Issuance(_) => "issuance",
            Step::Store(_) => "store",
            Step::Token(_) => "token",
            Step::Fetch(_) => "fetch",
            Step::Notify(_) => "notify",
            Step::End => "end",
        };
        let id = siros_flow_core::engine::step_id(step).unwrap_or("-");
        println!("  {i}. {kind} ({id})");
    }
}
