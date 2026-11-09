# siros-flow-core

[![CI](https://github.com/sirosfoundation/siros-flow-core/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-flow-core/actions/workflows/ci.yml)

The SIROS **flow orchestration layer**: configurable business logic —
flows that involve **authentication, verification, and issuance** — as
data over primitives, embedding `siros-issuer-core` and
`siros-verifier-core` as libraries. A *business wallet* (WE BUILD
usage: issuer + wallet + verifier + orchestration) is one deployment of
it.

- **Flows are YAML pipelines** — a linear sequence of steps from a
  closed vocabulary over a working set, non-Turing-complete by
  construction (the pyFF/goFF shape). A definition's content digest
  is its identity; the PDP evidence pins it.
- **Primitives call the cores**: presentations verify through
  verifier-core, issuance runs through issuer-core's session API —
  flow-core re-implements no protocol.
- **Identity binding is a vocabulary, not a policy**: comparisons are
  plugin-only except where they are 100% unequivocal (`same-key` is
  the one built-in; `claim-equals`, `pseudonym-equals`, `rule-match`
  are reference plugins on the same trait a deployment's own plugin
  would use).
- **Trust is go-trust's, fail-closed** — the engine constructs
  evidence and consumes permits; it has no local trust fallback.
- **Subject data never transits the engine in plaintext at rest**:
  the flow record is a clear/sealed split, the vault owns the key, the
  PII disciplines of the issuer carry up a level unchanged.

The authoritative design is
[docs/siros-flow-core-design.md](docs/siros-flow-core-design.md).
The reviewed flow definitions live in [flows/](flows/) — every one is
a CI-tested fixture.

## Layout

- `crates/siros-flow-core` — the sans-I/O core: the flow language
  (parse + validate + digest), the working set, the bind vocabulary,
  the flow lifecycle.
- `crates/siros-flow-service` — the deployable service: the FlowStore
  (clear/sealed record split; in-memory reference backend), the
  primitive implementations over the cores, the carriers
  (deep link / DC API / WMP).
- `flows/` — the reviewed flow definitions (fixtures, shipped and
  installable).

## Build and test

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

## License

BSD-2-Clause. Copyright (c) 2026, SIROS Foundation.
