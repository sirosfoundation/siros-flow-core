//! The in-process status list (draft-ietf-oauth-status-list): the
//! embedded issuer's fail-closed alternative to a deployed
//! siros-status-service — `[embedded.status_service] mode = "local"`.
//!
//! The discipline from the conformance suite's status fixtures, kept:
//! ONE shared list (herd privacy — a batch shares the list URI with
//! distinct indices, RFC 9180 / VCIWarnBatchStatusListUrisProvideHerdPrivacy)
//! and RANDOM indices (VCIEnsureBatchStatusListIndicesAreUnpredictable —
//! a constant stride lets an observer infer credentials were issued
//! together). The list serves at `GET /lists/{id}` as a Status List
//! Token (the draft's JWT shape: `status_list: {bits, lst}`), signed
//! by the embedded issuer's key — the same `iss` the credentials
//! carry, so a verifier that already trusts the issuer trusts the
//! list.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use url::Url;

use siros_issuer_core::status_client::{Status, StatusRef};
use siros_issuer_core::{Error, Result};

/// One status list: 2 bits per index (the draft's `bits: 2`), 4096
/// slots, byte-packed big-endian per index (the draft's packing).
const BITS_PER_INDEX: u64 = 2;
const SLOTS: usize = 4096;

pub struct LocalStatusList {
    /// The list id — the URL path segment (`/lists/{id}`).
    pub id: String,
    /// The public URL the list serves at (rides each credential's
    /// `status.list_url` — must resolve for the wallet).
    pub public_url: Url,
    bytes: Mutex<Vec<u8>>,
    /// The occupied set — random indices need to know the free ones.
    used: Mutex<std::collections::HashSet<u64>>,
}

impl LocalStatusList {
    pub fn new(id: &str, public_url: Url) -> Self {
        Self {
            id: id.to_owned(),
            public_url,
            bytes: Mutex::new(vec![0u8; SLOTS * BITS_PER_INDEX as usize / 8]),
            used: Mutex::new(std::collections::HashSet::new()),
        }
    }

    fn set_bits(&self, index: u64, status: Status) -> Result<()> {
        let value: u8 = match status {
            Status::Valid => 0,
            Status::Invalid | Status::Suspended | Status::Resume => 1,
        };
        let mut bytes = self
            .bytes
            .lock()
            .map_err(|_| Error::configuration("the status list lock is poisoned"))?;
        // draft-ietf-oauth-status-list -21 §4.1: each index's block of
        // bits is packed into bytes from the LEAST significant bit to
        // the most significant — the shift is the bit position within
        // the byte, counted from bit 0 (the old MSB-first packing read
        // wrong under every draft-conformant consumer, verifier-core's
        // status_at included).
        let offset = (index * BITS_PER_INDEX) as usize;
        let byte = &mut bytes[offset / 8];
        let shift = offset % 8;
        let mask: u8 = ((1 << BITS_PER_INDEX) - 1) as u8;
        *byte = (*byte & !(mask << shift)) | (value << shift);
        Ok(())
    }

    /// The list's §4.1 compressed byte array: DEFLATE **in the ZLIB
    /// format** (RFC 1950 — the draft's own vectors are 78da-prefixed;
    /// verifier-core's ZlibDecoder expects exactly this). The ONE
    /// compressed array feeds both containers: the JWT form
    /// base64url-encodes it, the CWT form carries it raw.
    fn lst_compressed(&self) -> Result<Vec<u8>> {
        let bytes = self
            .bytes
            .lock()
            .map_err(|_| Error::configuration("the status list lock is poisoned"))?
            .clone();
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &bytes)
            .map_err(|e| Error::configuration(format!("the status list: {e}")))?;
        encoder
            .finish()
            .map_err(|e| Error::configuration(format!("the status list: {e}")))
    }

    /// The list's own URI (the §5.1 `sub` — REQUIRED, and the value the
    /// Referenced Tokens' status uri carries).
    fn list_uri(&self) -> Result<url::Url> {
        self.public_url
            .join(&format!("lists/{}", self.id))
            .map_err(|e| Error::configuration(format!("the list url: {e}")))
    }

    /// The Status List Token (§5.1): a JWT signed by the embedded
    /// issuer. `sub` is REQUIRED (§5.1) — the list's own URI, the value
    /// every credential's status uri carries and what a conformant
    /// verifier (verifier-core's verify_token) binds the list to; the
    /// old token had none, so it was unverifiable by our own read side.
    pub fn token(&self, signer: &dyn siros_issuer_core::signer::Signer, now: i64) -> Result<Value> {
        let compressed = self.lst_compressed()?;
        let lst = siros_issuer_core::sdjwt_issue::b64u(&compressed);
        let mut header = jose_rs::JoseHeader::new("ES256");
        header.typ = Some("statuslist+jwt".to_owned());
        header.kid = signer.public_jwk()?.kid.clone();
        let payload = serde_json::to_vec(&json!({
            "iss": siros_issuer_core::oid4vci::issuer_identifier(&self.public_url),
            "sub": self.list_uri()?.as_str(),
            "iat": now,
            "status_list": { "bits": BITS_PER_INDEX, "lst": lst },
        }))
        .map_err(|e| Error::invalid_input(e.to_string()))?;
        Ok(json!({
            "list_url": self.list_uri().ok().map(|u| u.as_str().to_owned()),
            "token": signer.sign_es256(&header, &payload)?,
        }))
    }

    /// The Status List Token in CWT form (§5.2 — gap 2): the same
    /// compressed array (raw bytes, never base64 in CBOR), the same
    /// key, the same `sub` — the mdoc status form the ARF specifies.
    pub fn token_cwt(
        &self,
        signer: &dyn siros_issuer_core::signer::Signer,
        now: i64,
    ) -> Result<Vec<u8>> {
        siros_issuer_core::status_cwt::status_list_cwt(
            signer,
            &siros_issuer_core::status_cwt::StatusListCwt {
                subject: self.list_uri()?.as_str(),
                issuer: Some(
                    siros_issuer_core::oid4vci::issuer_identifier(&self.public_url).as_str(),
                ),
                iat: now,
                exp: None,
                ttl: None,
                lst_compressed: &self.lst_compressed()?,
                bits: BITS_PER_INDEX,
                aggregation_uri: None,
                kid: signer.public_jwk()?.kid.as_deref(),
            },
        )
    }
}

/// The adapter: the trait object the AppState holds, delegating to
/// the SAME Arc the /lists route serves (one shared list).
pub struct LocalAllocator(pub std::sync::Arc<LocalStatusList>);

#[async_trait::async_trait]
impl siros_issuer_service::status::StatusAllocator for LocalAllocator {
    async fn allocate(&self, _exp: Option<String>) -> Result<StatusRef> {
        self.0.allocate(_exp).await
    }
    async fn update(&self, list_url: &Url, index: u64, status: Status) -> Result<()> {
        self.0.update(list_url, index, status).await
    }
}

#[async_trait::async_trait]
impl siros_issuer_service::status::StatusAllocator for LocalStatusList {
    async fn allocate(&self, _exp: Option<String>) -> Result<StatusRef> {
        // RANDOM index (the suite's unpredictability discipline).
        let mut used = self
            .used
            .lock()
            .map_err(|_| Error::configuration("the status list lock is poisoned"))?;
        if used.len() >= SLOTS {
            return Err(Error::configuration("the local status list is full"));
        }
        loop {
            let mut buf = [0u8; 2];
            getrandom::fill(&mut buf).map_err(|e| {
                Error::new(
                    siros_flow_core::error::code::TRANSPORT,
                    format!("OS randomness: {e}"),
                )
            })?;
            let candidate = u16::from_be_bytes(buf) as u64 % SLOTS as u64;
            if used.insert(candidate) {
                let list_url = self
                    .public_url
                    .join(&format!("lists/{}", self.id))
                    .map_err(|e| Error::configuration(format!("the list url: {e}")))?;
                return Ok(StatusRef {
                    list_url,
                    index: candidate,
                });
            }
        }
    }

    async fn update(&self, list_url: &Url, index: u64, status: Status) -> Result<()> {
        let ours = self
            .public_url
            .join(&format!("lists/{}", self.id))
            .map_err(|e| Error::configuration(format!("the list url: {e}")))?;
        if list_url.as_str() != ours.as_str() {
            return Err(Error::configuration(format!(
                "this allocator serves one list ({ours}); {list_url} is not it"
            )));
        }
        self.set_bits(index, status)
    }
}

/// The `GET /lists/{id}` handler factory: serves the Status List
/// Token for THIS list (the embedded issuer's own `iss` signs it).
pub async fn serve_list(
    list: std::sync::Arc<LocalStatusList>,
    signer: Arc<dyn siros_issuer_core::signer::Signer>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // Content negotiation (vc's serving contract, draft §5.1/§5.2): the
    // CWT form — the mdoc status form the ARF specifies — when the
    // consumer asks for it; the JWT form (the default) otherwise. The
    // same allocation, the same compressed bytes, the same key.
    let wants_cwt = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|accept| {
            accept
                .split(',')
                .map(str::trim)
                .any(|media| media.starts_with(siros_issuer_core::status_cwt::MEDIA_TYPE_CWT))
        })
        .unwrap_or(false);
    let now = siros_issuer_service::status::now_unix();
    let built = if wants_cwt {
        list.token_cwt(signer.as_ref(), now)
            .map(|bytes| (siros_issuer_core::status_cwt::MEDIA_TYPE_CWT, bytes))
    } else {
        list.token(signer.as_ref(), now).map(|token| {
            let body = token["token"].as_str().unwrap_or_default().to_owned();
            ("application/statuslist+jwt", body.into_bytes())
        })
    };
    match built {
        Ok((content_type, body)) => axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, content_type)
            .body(axum::body::Body::from(body))
            .expect("static response parts"),
        Err(_) => axum::response::Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::empty())
            .expect("static response parts"),
    }
}
