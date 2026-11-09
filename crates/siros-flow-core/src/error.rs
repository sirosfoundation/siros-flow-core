//! Errors with stable, machine-readable refusal codes (the family
//! discipline: codes are part of the surface and must not be renamed;
//! messages are for logs and never carry subject data — values,
//! claims, openings, pseudonyms).

pub type Result<T> = std::result::Result<T, Error>;

/// Refusal codes. Stable across releases.
pub mod code {
    /// A definition (or one of its steps) does not parse or validate.
    /// Fail-closed: unknown kinds, unknown primitives, unknown
    /// versions, ambiguous shapes — a definition that cannot say what
    /// it means is refused, never patched up.
    pub const FLOW_LANGUAGE_INVALID: &str = "flow_language_invalid";
    /// An unknown `language_version` — the circuit-catalog load
    /// discipline: refuse, never best-effort interpret.
    pub const FLOW_LANGUAGE_VERSION: &str = "flow_language_version";
    /// A state-machine transition the flow's lifecycle does not allow
    /// (the `session.rs` discipline, new machine).
    pub const ILLEGAL_TRANSITION: &str = "illegal_transition";
    /// A bind primitive resolved and answered *no* — the verdict is
    /// the refusal when `on_mismatch: fail` (the default). Message
    /// names paths and the primitive, never values.
    pub const BIND_MISMATCH: &str = "bind_mismatch";
    /// A bind step names a primitive that is neither a built-in nor an
    /// allowlisted plugin (the plugin-allowlist discipline).
    pub const BIND_UNKNOWN_PRIMITIVE: &str = "bind_unknown_primitive";
    /// A context reference does not resolve (unknown step id, unknown
    /// credential id, absent claim path) — a refusal, never a skip:
    /// a primitive that cannot resolve declares mismatch or errors,
    /// never best-effort.
    pub const CONTEXT_UNRESOLVED: &str = "context_unresolved";
    /// The PDP refused (recorded, never invented locally — the engine
    /// has no trust fallback).
    pub const PDP_DENIED: &str = "pdp_denied";
    pub const PDP_UNAVAILABLE: &str = "pdp_unavailable";
    /// Not in this engine version yet (a construct the language
    /// accepts and the engine has not grown — e.g. `map:`), stated at
    /// load, never a silent no-op.
    pub const NOT_IMPLEMENTED: &str = "not_implemented";
    pub const INVALID_INPUT: &str = "invalid_input";
    pub const CONFIGURATION: &str = "configuration";
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn language_invalid(message: impl Into<String>) -> Self {
        Self::new(code::FLOW_LANGUAGE_INVALID, message)
    }

    pub fn illegal_transition(message: impl Into<String>) -> Self {
        Self::new(code::ILLEGAL_TRANSITION, message)
    }

    pub fn bind_mismatch(message: impl Into<String>) -> Self {
        Self::new(code::BIND_MISMATCH, message)
    }

    pub fn context_unresolved(message: impl Into<String>) -> Self {
        Self::new(code::CONTEXT_UNRESOLVED, message)
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_INPUT, message)
    }

    pub fn configuration(message: impl Into<String>) -> Self {
        Self::new(code::CONFIGURATION, message)
    }
}
