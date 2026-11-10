//! The application builder (main and the tests call the same code):
//! wires the flow service — and, when `[issuer.embedded]` is set, a
//! complete siros-issuer-service in-process, sharing the vault's PDP
//! and merging its wallet-facing OID4VCI routes with the flow API on
//! one port. One process = one additional trusted issuer + verifier,
//! nothing disabled: the PDP is go-trust's either way.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use url::Url;

use siros_flow_core::bind::BindRegistry;
use siros_flow_core::{Error, Result};

use crate::config::Config;
use crate::issuer_client::{IssuerClient, IssuerCoreClient};
use crate::state::FlowServiceState;
use crate::store::MemoryFlowStore;

/// A status allocator that writes to one configured list (the
/// deployment's status service): sequential indices with
/// unpredictable starts (the §9.1 discipline is the service's, not
/// the client's, when it owns allocation).
struct SequentialAllocator {
    list_url: Url,
    next: AtomicU64,
}

#[async_trait::async_trait]
impl siros_issuer_service::status::StatusAllocator for &SequentialAllocator {
    async fn allocate(
        &self,
        _exp: Option<String>,
    ) -> siros_issuer_core::Result<siros_issuer_core::status_client::StatusRef> {
        Ok(siros_issuer_core::status_client::StatusRef {
            list_url: self.list_url.clone(),
            index: self.next.fetch_add(1, Ordering::SeqCst),
        })
    }
    async fn update(
        &self,
        _list_url: &Url,
        _index: u64,
        _status: siros_issuer_core::status_client::Status,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }
}

/// Build the whole application from the config: the flow state, the
/// (optional) embedded issuer, and the merged router.
pub struct App {
    pub router: axum::Router,
    pub state: Arc<FlowServiceState>,
    /// The embedded issuer's identifier when configured (for the
    /// readiness log; the issuer surface serves on the same router).
    pub embedded_issuer: Option<String>,
}

pub async fn build(config: &Config) -> Result<App> {
    // The definitions: every one loads and validates, or startup
    // refuses (fail-closed — a deployment's flow set is reviewed).
    let definitions_dir = config
        .definitions
        .dir
        .clone()
        .unwrap_or_else(|| "flows".to_owned());
    let definitions = FlowServiceState::load_definitions(&definitions_dir)?;

    // The plugin-allowlist discipline (§8.3): every definition's bind
    // steps resolve against the registry and pass their primitive's
    // parameter validation HERE — an unknown primitive or malformed
    // params refuse startup (a load refusal), never a mid-flow walk.
    let bind_registry = BindRegistry::standard();
    // The plugin allowlist (§6.7): token plugins and fetch providers
    // built from config — reviewed code, registered by name.
    let mut token_registry = crate::plugins::TokenRegistry::new();
    for plugin_cfg in &config.plugins.token {
        token_registry = token_registry.with(Box::new(crate::plugins::IdTokenPlugin::from_config(
            plugin_cfg,
        )?));
    }
    let mut fetch_registry = crate::plugins::FetchRegistry::new();
    for plugin_cfg in &config.plugins.fetch {
        fetch_registry = fetch_registry.with(Box::new(
            crate::plugins::HttpJsonPlugin::from_config(plugin_cfg)?,
        ));
    }
    for definition in definitions.values() {
        siros_flow_core::bind::validate_definition(definition, &bind_registry)?;
        crate::plugins::validate_definition(definition, &token_registry, &fetch_registry)?;
    }

    let public_url = Url::parse(
        &config
            .service
            .public_url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_owned()),
    )
    .map_err(|e| Error::configuration(format!("service.public_url: {e}")))?;

    // The request-object signer (the verifier role) + its x5c.
    let (verifier_signer, cert_chain_der) = verifier_signing(config)?;
    let _ = cert_chain_der.clone();

    // The PDP: configured ⇒ go-trust's AuthZEN client; absent ⇒
    // fail-closed (every presentation trust decision refuses).
    let pdp: Arc<dyn siros_issuer_service::pdp::TrustPdp> = match &config.pdp {
        Some(url) => Arc::new(siros_issuer_service::pdp::AuthZenPdp::new(url.clone())),
        None => {
            eprintln!(
                "siros-flow-service: no pdp configured: every presentation trust decision is pdp_unavailable"
            );
            Arc::new(siros_issuer_service::pdp::FailClosedPdp)
        }
    };

    // The embedded issuer (the additional trusted issuer), when
    // configured — its OID4VCI routes merge with the flow API.
    let mut issuer_router: Option<axum::Router> = None;
    let mut embedded_issuer_identifier = None;
    if let Some(embedded) = &config.embedded {
        let identifier = siros_issuer_core::oid4vci::issuer_identifier(
            &Url::parse(&embedded.issuer.issuer.url)
                .map_err(|e| Error::configuration(format!("issuer.embedded.issuer.url: {e}")))?,
        );
        // status_mode lives on the FLOW config's issuer section (the
        // embedded issuer's own config carries no such knob).
        let status_mode = config
            .issuer
            .status_mode
            .clone()
            .unwrap_or_else(|| "local".to_owned());
        if embedded.issuer.status_service.is_some() && status_mode != "service" {
            return Err(Error::configuration(
                "issuer.status_mode: status_service is configured but the mode is not service",
            ));
        }
        let (router, issuer_state, local_list) =
            build_embedded_issuer(&embedded.issuer, &pdp, config, &status_mode).await?;
        // The local status list serves on the merged router (the
        // wallet's GET /lists/{id}).
        let mut merged = router;
        if let Some(list) = local_list {
            let signer = issuer_state.signer.clone();
            merged = merged.route(
                format!("/lists/{}", list.id).as_str(),
                axum::routing::get({
                    let list = list.clone();
                    move || {
                        let list = list.clone();
                        let signer = signer.clone();
                        async move { crate::local_status::serve_list(list, signer).await }
                    }
                }),
            );
        }
        issuer_router = Some(merged);
        embedded_issuer_identifier = Some(identifier);
    }

    // The issuer backend the issuance steps drive: the embedded
    // issuer when present (the flow drives itself over its own public
    // backend API), else the configured external backend. The
    // assertion's aud is the issuer's IDENTIFIER (the normalized form
    // verify_bearer_assertion compares against), not the raw URL.
    let backend = match (&config.embedded, &config.issuer.backend_url) {
        (Some(embedded), _) => embedded.issuer.issuer.url.clone(),
        (None, Some(url)) => url.clone(),
        (None, None) => "http://127.0.0.1:8080".to_owned(),
    };
    let audience = config.issuer.audience.clone().unwrap_or_else(|| {
        Url::parse(&backend)
            .map(|url| siros_issuer_core::oid4vci::issuer_identifier(&url).to_owned())
            .unwrap_or_else(|_| backend.clone())
    });
    let integrator_id = config
        .issuer
        .integrator_id
        .clone()
        .unwrap_or_else(|| "https://flow.siros.org/".to_owned());
    let key_path = config
        .issuer
        .integrator_key_path
        .clone()
        .unwrap_or_else(|| "config/integrator.jwk".to_owned());
    let issuer: Arc<dyn IssuerClient> = Arc::new(IssuerCoreClient::new(
        Url::parse(&backend)
            .map_err(|e| Error::configuration(format!("the issuer backend: {e}")))?,
        audience,
        integrator_id,
        &key_path,
    )?);

    let state = Arc::new(FlowServiceState {
        definitions,
        definitions_dir,
        store: Arc::new(MemoryFlowStore::new()),
        vault: siros_issuer_service::vault::Vault::new()
            .map_err(|e| Error::configuration(e.to_string()))?,
        signer: verifier_signer,
        cert_chain_der,
        pdp,
        issuer,
        public_url: public_url.clone(),
        presentation_ttl_seconds: config.presentation_ttl_seconds,
        default_carrier: config
            .service
            .default_carrier
            .unwrap_or(siros_flow_core::language::Carrier::Deeplink),
        retention_after_final_seconds: config.retention_after_final_seconds,
        bind_registry,
        token_registry,
        fetch_registry,
    });

    // The embedded merge: the issuer's own /healthz serves the
    // composite origin (one app, one health), so the flow routes ride
    // without theirs.
    let router = match issuer_router {
        Some(issuer_router) => crate::http::routes(state.clone()).merge(issuer_router),
        None => crate::http::router(state.clone()),
    };
    Ok(App {
        router,
        state,
        embedded_issuer: embedded_issuer_identifier,
    })
}

type VerifierSigning = (Arc<dyn siros_issuer_core::signer::Signer>, Vec<Vec<u8>>);

/// Load a PKCS#8 EC P-256 PEM into the JWK the signer wants (the
/// family's key shape — create-pki.sh's verifier-style private key).
/// A PEM certificate chain (leaf first) → DER vectors.
fn pem_chain_to_der(path: &str) -> Result<Vec<Vec<u8>>> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| Error::configuration(format!("reading {path}: {e}")))?;
    pem::parse_many(pem)
        .map_err(|e| Error::configuration(format!("parsing {path}: {e}")))
        .map(|blocks| {
            blocks
                .into_iter()
                .map(|block| block.contents().to_vec())
                .collect()
        })
}

/// The verifier role's signing material: the request-object JWK and
/// the x5c chain.
fn verifier_signing(config: &Config) -> Result<VerifierSigning> {
    let signer: Arc<dyn siros_issuer_core::signer::Signer> = match (
        &config.signing.jwk_path,
        &config.signing.pem_path,
    ) {
        (Some(path), None) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| Error::configuration(format!("reading {path}: {e}")))?;
            let mut jwk: jose_rs::jwk::Jwk = serde_json::from_str(&text)
                .map_err(|e| Error::configuration(format!("parsing {path}: {e}")))?;
            if jwk.alg.is_none() {
                jwk.alg = Some("ES256".to_owned());
            }
            if jwk.kid.is_none() {
                jwk.kid = Some(
                    siros_issuer_service::auth::thumbprint(&jwk)
                        .map_err(|e| Error::configuration(e.to_string()))?,
                );
            }
            Arc::new(
                siros_issuer_core::signer::JwkSigner::new(jwk)
                    .map_err(|e| Error::configuration(e.to_string()))?,
            )
        }
        (None, Some(path)) => {
            // The family's PKCS#8 EC P-256 PEM (create-pki.sh's shape)
            // — loaded into the same JWK.
            let jwk = crate::keys::load_key_file(path)?;
            Arc::new(
                siros_issuer_core::signer::JwkSigner::new(jwk)
                    .map_err(|e| Error::configuration(e.to_string()))?,
            )
        }
        (Some(_), Some(_)) => {
            return Err(Error::configuration(
                "signing: exactly one of jwk_path and pem_path",
            ));
        }
        (None, None) => {
            eprintln!(
                "siros-flow-service: no signing key configured: an ephemeral dev key signs request objects; development only"
            );
            let jwk = jose_rs::jwk::generate_ec("P-256")
                .map_err(|e| Error::configuration(format!("keygen: {e}")))?;
            Arc::new(
                siros_issuer_core::signer::JwkSigner::new(jwk)
                    .map_err(|e| Error::configuration(e.to_string()))?,
            )
        }
    };
    // The verifier role's x5c: PEM chain, leaf first → DER vectors.
    let cert_chain_der = match &config.signing.cert_chain_path {
        Some(path) => pem_chain_to_der(path)?,
        None => Vec::new(),
    };
    Ok((signer, cert_chain_der))
}

/// Wire the embedded issuer: a complete siros-issuer-service AppState
/// and router, sharing the flow's PDP. The flow's own integrator
/// identity is registered into the client registry automatically —
/// the issuance steps drive this issuer over its own backend API.
type EmbeddedIssuer = (
    axum::Router,
    Arc<siros_issuer_service::api::AppState>,
    Option<std::sync::Arc<crate::local_status::LocalStatusList>>,
);

async fn build_embedded_issuer(
    config: &siros_issuer_service::config::Config,
    pdp: &Arc<dyn siros_issuer_service::pdp::TrustPdp>,
    flow_config: &Config,
    status_mode: &str,
) -> Result<EmbeddedIssuer> {
    let catalog_source = siros_issuer_service::fetch::CatalogSource::from_config(&config.catalog)
        .map_err(|e| Error::configuration(e.to_string()))?;
    // Await the catalog (a network load when mirrors are configured —
    // the registry; fail-closed on any refusal, the circuit-catalog
    // discipline). Metadata generation SKIPS types this deployment
    // cannot issue (issuer-core 467d073: the metadata advertises what
    // it issues; a skipped type still fails closed at resolve).
    let catalog = siros_issuer_service::fetch::load_catalog(&catalog_source)
        .await
        .map_err(|e| Error::configuration(e.to_string()))?;

    // The issuer's credential-signing key (its own identity — NOT the
    // verifier role's key, the siros-verifier rule). The file may be
    // the family's PKCS#8 PEM (create-pki.sh's shape) or JWK JSON —
    // detected by the PEM header.
    let mut jwk = match &config.signing.jwk_path {
        Some(path) => crate::keys::load_key_file(&path.display().to_string())?,
        None => {
            eprintln!(
                "siros-flow-service: the embedded issuer has no signing.jwk_path: an ephemeral dev key signs its credentials; development only"
            );
            jose_rs::jwk::generate_ec("P-256")
                .map_err(|e| Error::configuration(format!("keygen: {e}")))?
        }
    };
    if jwk.alg.is_none() {
        jwk.alg = Some("ES256".to_owned());
    }
    if jwk.kid.is_none() {
        jwk.kid = Some(
            siros_issuer_service::auth::thumbprint(&jwk)
                .map_err(|e| Error::configuration(e.to_string()))?,
        );
    }
    let signer = siros_issuer_core::signer::JwkSigner::new(jwk.clone())
        .map_err(|e| Error::configuration(e.to_string()))?;
    let issuer_signer: Arc<dyn siros_issuer_core::signer::Signer> = Arc::new(signer.clone());
    let cert_chain_der = match &config.signing.cert_chain_path {
        Some(path) => pem_chain_to_der(&path.display().to_string())?,
        None => Vec::new(),
    };

    // The status allocator: the deployment's status service when
    // configured; the LOCAL in-process list when the mode asks for it
    // (the embedded default — fail-closed would mean no issuance);
    // NoAllocator otherwise (fail-closed).
    let mut local_list: Option<std::sync::Arc<crate::local_status::LocalStatusList>> = None;
    let allocator: Arc<dyn siros_issuer_service::status::StatusAllocator> = match &config
        .status_service
    {
        Some(status_cfg) => Arc::new(siros_issuer_service::status::SirosStatusClient::new(
            Url::parse(&status_cfg.as_url)
                .map_err(|e| Error::configuration(format!("status_service.as_url: {e}")))?,
            Url::parse(&status_cfg.ingestion_url)
                .map_err(|e| Error::configuration(format!("status_service.ingestion_url: {e}")))?,
            Arc::new(signer),
            config.issuer.url.clone(),
        )),
        None if status_mode == "local" => {
            // The in-process list: one shared list, random indices —
            // dev/staging posture, the conformance fixtures'
            // discipline. The SAME Arc backs the allocator, the
            // /lists/{id} route, and the update path — one list.
            eprintln!(
                "siros-flow-service: the embedded issuer uses the LOCAL status list (dev/staging): no deployed status_service"
            );
            let issuer_public = Url::parse(&config.issuer.url)
                .map_err(|e| Error::configuration(format!("issuer.url: {e}")))?;
            let list = std::sync::Arc::new(crate::local_status::LocalStatusList::new(
                "local",
                issuer_public,
            ));
            local_list = Some(list.clone());
            Arc::new(crate::local_status::LocalAllocator(list))
        }
        None => {
            eprintln!(
                "siros-flow-service: the embedded issuer has no status_service: issuance refuses (fail-closed, no silent unrevocable credentials)"
            );
            Arc::new(siros_issuer_service::status::NoAllocator)
        }
    };

    // The client registry: the configured set, plus the flow's own
    // integrator identity (the issuance step drives this issuer over
    // its own backend API).
    let mut clients = config.authorization.clients.clone();
    let integrator_id = flow_config
        .issuer
        .integrator_id
        .clone()
        .unwrap_or_else(|| "https://flow.siros.org/".to_owned());
    if let Some(key_path) = &flow_config.issuer.integrator_key_path {
        // The family's key shape accepted: PKCS#8 EC P-256 PEM (detected
        // by the header) or JWK JSON — one loader, the same shapes the
        // verifier signing and token-plugin configs take.
        let jwk: jose_rs::jwk::Jwk = crate::keys::load_key_file(key_path)?;
        let public = jwk.to_public_jwk();
        let jwk_value = serde_json::to_value(&public)
            .map_err(|e| Error::configuration(format!("the integrator key: {e}")))?;
        clients
            .clients
            .entry(integrator_id.clone())
            .or_insert_with(|| siros_issuer_service::client_auth::ClientRegistration {
                jwks: vec![jwk_value],
                redirect_uris: vec![],
                allow_any_redirect_uri: false,
                scope: None,
            });
    }

    let (events_tx, _) = tokio::sync::broadcast::channel(64);
    let state = Arc::new(siros_issuer_service::api::AppState {
        catalog: Arc::new(std::sync::RwLock::new(Arc::new(catalog))),
        issuer_base: Url::parse(&config.issuer.url)
            .map_err(|e| Error::configuration(format!("issuer.url: {e}")))?,
        authorization_servers: vec![],
        refresh: Arc::new(siros_issuer_service::api::RefreshStatus::default()),
        sessions: Arc::new(siros_issuer_service::store::MemoryStore::new()),
        dpop: Arc::new(siros_issuer_service::dpop::DpopValidator::new(60)),
        last_public_nonce: Arc::new(Mutex::new(String::new())),
        login_url: None,
        clients: Arc::new(clients),
        scopes: config.authorization.scopes.clone(),
        endpoint_paths: siros_issuer_core::oid4vci::EndpointPaths::default(),
        deferred_interval_seconds: 5,
        auxiliary_data_plans: BTreeMap::new(),
        request_encryption_key: None,
        cert_chain_der,
        attestation: Arc::new(siros_issuer_service::client_auth::WildcardRulesPolicy::new(
            Vec::new(),
        )),
        wallet_attestation: None,
        pre_auth_binding: None,
        signer: issuer_signer,
        vault: Arc::new(
            siros_issuer_service::vault::Vault::new()
                .map_err(|e| Error::configuration(e.to_string()))?,
        ),
        pdp: pdp.clone(),
        allocator,
        events_tx,
        credential_validity_seconds: config.issuance.credential_validity_seconds,
        access_token_ttl_seconds: config.issuance.access_token_ttl_seconds,
        c_nonce_ttl_seconds: config.issuance.c_nonce_ttl_seconds,
        rulebooks: HashMap::new(),
        zk_seeds: Default::default(),
        rate_counters: siros_issuer_service::rate_limit::WalletRateCounters::from_config(
            &config.rate_limit,
        ),
        rate_limit: config.rate_limit.clone(),
        circuit_manifest: None,
    });

    Ok((
        siros_issuer_service::api::router((*state).clone()),
        state,
        local_list,
    ))
}
