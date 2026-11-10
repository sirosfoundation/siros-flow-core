//! The family's key-file shapes, loaded once: a PKCS#8 EC P-256 PEM
//! (create-pki.sh's shape) or JWK JSON, detected by the PEM header —
//! the same two shapes the verifier signing loader, the embedded
//! issuer, the integrator client and the token plugins all take.

use siros_flow_core::{Error, Result};

/// A PKCS#8 EC P-256 PEM text → the JWK (no kid defaulting).
pub fn pkcs8_pem_jwk(text: &str, path: &str) -> Result<jose_rs::jwk::Jwk> {
    let blocks: Vec<pem::Pem> =
        pem::parse_many(text).map_err(|e| Error::configuration(format!("parsing {path}: {e}")))?;
    let der = blocks
        .iter()
        .find(|block| block.tag() == "PRIVATE KEY")
        .map(|block| block.contents().to_vec())
        .ok_or_else(|| Error::configuration(format!("{path}: no PRIVATE KEY block")))?;
    let secret: p256::SecretKey = p256::pkcs8::DecodePrivateKey::from_pkcs8_der(&der)
        .map_err(|e| Error::configuration(format!("{path}: {e}")))?;
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    let point = secret.public_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let scalar = secret.to_bytes();
    serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": siros_issuer_core::sdjwt_issue::b64u(&bytes[1..33]),
        "y": siros_issuer_core::sdjwt_issue::b64u(&bytes[33..]),
        "d": siros_issuer_core::sdjwt_issue::b64u(scalar.as_slice()),
        "alg": "ES256",
        "use": "sig",
    }))
    .map_err(|e| Error::configuration(format!("the loaded jwk: {e}")))
}

/// A key FILE: the family's two shapes — PKCS#8 EC P-256 PEM (detected
/// by the header) or JWK JSON. The kid defaults to the RFC 7638
/// thumbprint when absent (a signing key without a kid is awkward to
/// reference; the thumbprint is its canonical name).
pub fn load_key_file(path: &str) -> Result<jose_rs::jwk::Jwk> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::configuration(format!("reading {path}: {e}")))?;
    let mut jwk = if text.trim_start().starts_with("-----BEGIN") {
        pkcs8_pem_jwk(&text, path)?
    } else {
        serde_json::from_str::<jose_rs::jwk::Jwk>(&text)
            .map_err(|e| Error::configuration(format!("parsing {path}: {e}")))?
    };
    if jwk.alg.is_none() {
        jwk.alg = Some("ES256".to_owned());
    }
    if jwk.kid.is_none() {
        let kid = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk)
            .map_err(|e| Error::configuration(format!("thumbprinting {path}: {e}")))?;
        jwk.kid = Some(kid);
    }
    Ok(jwk)
}

/// A public key FILE (the same two shapes, public members only):
/// what a verifier-side config points at an asserting party's key
/// with.
pub fn load_public_key_file(path: &str) -> Result<jose_rs::jwk::Jwk> {
    let jwk = load_key_file(path)?;
    if jwk.d.is_some() {
        return Err(Error::configuration(format!(
            "{path}: a public-key configuration carries private material — refused"
        )));
    }
    Ok(jwk)
}
