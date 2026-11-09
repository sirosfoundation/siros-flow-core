//! siros-flow-core — the sans-I/O flow core (design §4.2).
//!
//! The **flow orchestration layer** (a business wallet is one
//! deployment of it): configurable business logic — flows that
//! involve authentication, verification, and issuance — as **data
//! over primitives**, embedding `siros-issuer-core` and
//! `siros-verifier-core` as libraries (the primitives call the cores;
//! this crate itself owns no I/O).
//!
//! The split (the family discipline):
//!
//! - **The language** (`language`): definitions are YAML pipelines —
//!   a linear sequence of steps from a closed vocabulary over a
//!   working set, non-Turing-complete by construction (§5). The
//!   schema is a JSON tree; the content digest of the normalized
//!   definition is its identity. Fail-closed everywhere.
//! - **The working set** (`context`): the flow context — inputs,
//!   presentation results, derived values, issuance refs, recorded
//!   bind verdicts. The store persists the clear/sealed split; this
//!   type is the unsealed copy that exists for one step.
//! - **Identity binding** (`bind`): the generic concept assembled
//!   from bind primitives. **Comparisons are plugin-only except
//!   where they are 100% unequivocal** — `same-key` is the one
//!   built-in; `claim-equals`, `pseudonym-equals`, and `rule-match`
//!   are reference plugins (§8.2).
//! - **The lifecycle** (`engine`): one state machine per flow
//!   instance, generic over definitions — `created → running ⇄
//!   waiting → completed | failed | expired`, the position in the
//!   definition is data (§8.6). Illegal transitions refuse with
//!   stable codes.
//!
//! Effects (persistence, the primitive implementations that call the
//! cores, carriers, the HTTP surface) live in `siros-flow-service`,
//! crossing explicit traits — the sans-I/O line is load-bearing.

pub mod bind;
pub mod context;
pub mod engine;
pub mod error;
pub mod language;

pub use error::{code, Error, Result};

/// The crate version, stamped into evidence alongside the definition
/// digest (§9: the PDP evidence names the definition AND the engine
/// that ran it).
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
