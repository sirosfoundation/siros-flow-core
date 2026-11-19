//! The shared test scaffolding for the e2e AppState literals (ONE
//! copy of the pin-line postures — sonar's duplication gate tripped on
//! the same three lines across three test files).

/// The embedded issuer's postures from the issuer-core v0.2 pin:
/// a FRESH public-nonce ring per service (a window of live public
/// nonces — issuer-core's #3), the ring bound (8 concurrent
/// pre-session proofs), and the DELIBERATE plain posture (the review's
/// #8: the v0.2 default is encryption REQUIRED and the gdc plain-mode
/// wallets would be refused by it; the to_wallet floor holds either
/// way — endpoint-enforced).
#[allow(clippy::type_complexity)]
pub fn embedded_postures() -> (
    std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(String, i64)>>>,
    usize,
    bool,
) {
    (
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        8,
        false,
    )
}
