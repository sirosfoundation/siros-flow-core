# Agent guide: siros-flow-core

This workspace contains the sans-I/O flow core and the deployable flow
service. The authoritative design is `docs/siros-flow-core-design.md`
(§5 the language, §8 identity binding, §8.6 the lifecycle, §10 the
security properties — normative). Keep changes small and
vocabulary-driven.

- **The core is sans-I/O.** Transport, storage, time and trust
  verdicts belong to the service. Effects cross explicit traits; the
  core never hides I/O in protocol or engine code.
- **Definitions are data, fail-closed.** The language is a closed
  vocabulary; unknown step kinds, unknown primitives, unknown
  `language_version`s, ambiguous shapes — every one is a load refusal
  with a stable code, never a best-effort interpretation. The content
  digest of the normalized definition is its identity; the PDP
  evidence carries it.
- **Non-Turing-complete by construction.** Linear steps, bounded
  `map:`, declarative `when:`, `end`. No variables, no arithmetic, no
  string interpolation, no recursion. A flow that needs real
  computation needs a plugin — code, reviewed as code (the ZK
  rulebook boundary).
- **Comparisons are plugin-only except where they are 100%
  unequivocal.** `same-key` is the one built-in. Everything that
  compares values is a named plugin on the `BindPrimitive` trait,
  allowlisted per deployment; nothing about the reference plugins is
  engine-privileged. The built-in criterion is structural: the key
  class of `same-key`, never the judgment class of a value
  comparison.
- **Binding is math, trust is go-trust's.** A bind primitive refuses
  mismatches; it never consults policy, and the PDP never substitutes
  for a bind. Recorded verdicts carry names and parameters, never
  values.
- **One lifecycle, position is data.** `created → running ⇄ waiting →
  completed | failed | expired`; the step cursor and per-step states
  ride the record. Illegal transitions refuse with stable codes; no
  new state without a design-doc change first.
- **Subject data is sealed at rest.** The flow record is a
  clear/sealed split; the plaintext context exists in memory for one
  step, is never logged, and never leaves the process. No standing
  subject index; refusals name paths and codes, never values.
- **The cores are libraries, not forks.** Presentations verify through
  verifier-core; issuance runs through issuer-core's session
  machinery. flow-core re-implements no protocol and no comparison
  semantics already owned by a core (reuse, cite, don't duplicate).

## Configuration rules

- Flow definitions are YAML (`flows/` ships the reviewed set);
  deployment configuration is TOML (the family convention).
- The schema is a JSON tree: YAML is a frontend, the typed definition
  is the document, the canonical-JSON digest is the identity.
- Plugins are deployment config + reviewed code; a definition
  referencing a plugin outside the allowlist is a load refusal.

## Tests

- New tests live outside the source files, in each crate's `tests/`
  directory, and exercise the public API. No `#[test]` or
  `#[cfg(test)]` under `src/`; do not widen visibility for a test.
- Every definition in `flows/` is a CI-tested fixture: it parses,
  validates, and digests. A definition change is a visible diff
  against recorded expectations (the goFF model).
- Every test enforces a source of truth outside the code it tests: the
  design document's lifecycle and vocabulary rules, ADR 002, vc's
  ported semantics (cite the file), or RFC 7638. Delete a test whose
  expected value comes from the implementation.

## Working rules

- Cite the design document for non-obvious behavior (`§5.4`,
  `§8.2`, `§8.6`). Do not use another implementation as an unstated
  specification — vc is the reference for *ported semantics*, cited in
  the design doc's Appendix B.
- Do not run `git commit`, `git push`, `git rebase`, `git reset`, or
  create a tag unless the user explicitly approved that operation.
- Fix every review finding and every instance of the same bug class.
  Merge only reviewed, green PRs.

## Build and test

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```
