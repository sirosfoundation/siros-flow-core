//! The flow service state: the loaded definitions (the general
//! service — every definition in the configured set is exposed, not
//! just one flow), the store, the vault, the signer, the PDP, and the
//! issuer client the `issuance` primitive drives.

use std::collections::BTreeMap;
use std::sync::Arc;

use siros_flow_core::language::FlowDefinition;
use siros_flow_core::{Error, Result};

use crate::issuer_client::IssuerClient;
use crate::store::FlowStore;

/// The service state every handler shares.
pub struct FlowServiceState {
    /// The loaded, validated definitions by flow name (startup
    /// refuses an invalid definition — fail-closed, the circuit-
    /// catalog load discipline). The service is general: ANY loaded
    /// flow is startable.
    pub definitions: BTreeMap<String, FlowDefinition>,
    /// The definition directory the definitions were loaded from (for
    /// the readiness report).
    pub definitions_dir: String,
    pub store: Arc<dyn FlowStore>,
    /// The vault sealing subject-shaped context (the issuer-core
    /// vault shape, reused).
    pub vault: siros_issuer_service::vault::Vault,
    /// The signer for OID4VP request objects (the verifier role).
    pub signer: Arc<dyn siros_issuer_core::signer::Signer>,
    /// The certificate chain (DER, leaf first) the request object's
    /// x5c carries.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// The PDP deciding presentation trust (fail-closed by the
    /// trait's default).
    pub pdp: Arc<dyn siros_issuer_service::pdp::TrustPdp>,
    /// The issuer backend the `issuance` primitive drives.
    pub issuer: Arc<dyn IssuerClient>,
    /// The externally visible base URL (response_uri derivation).
    pub public_url: url::Url,
    pub presentation_ttl_seconds: i64,
    pub retention_after_final_seconds: i64,
    /// The bind registry the driver resolves `primitive:` names
    /// against: the standard set (same-key + the reference plugins);
    /// a deployment adds its own on the same trait.
    pub bind_registry: siros_flow_core::bind::BindRegistry,
}

impl FlowServiceState {
    /// Load every `.yaml` in the definitions directory. One invalid
    /// definition refuses startup: a deployment's flow set is
    /// reviewed, or it does not run.
    pub fn load_definitions(dir: &str) -> Result<BTreeMap<String, FlowDefinition>> {
        let mut definitions = BTreeMap::new();
        let entries = std::fs::read_dir(dir)
            .map_err(|e| Error::configuration(format!("the definitions directory {dir:?}: {e}")))?;
        for entry in entries {
            let path = entry
                .map_err(|e| Error::configuration(format!("the definitions directory: {e}")))?
                .path();
            if path
                .extension()
                .is_some_and(|extension| extension == "yaml")
            {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| Error::configuration(format!("reading {path:?}: {e}")))?;
                let definition = FlowDefinition::from_yaml(&text)
                    .map_err(|e| Error::configuration(format!("{}: {e}", path.display())))?;
                definitions.insert(definition.flow.clone(), definition);
            }
        }
        if definitions.is_empty() {
            return Err(Error::configuration(format!(
                "the definitions directory {dir:?} carries no flow definitions"
            )));
        }
        Ok(definitions)
    }
}
