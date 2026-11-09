//! siros-flow-service — the deployable flow service. One binary, one
//! deployment's flows: the definitions directory, the issuer backend
//! it drives, the request-object signer, the PDP, the store.
//!
//! Deployment (sirosid-dev): the flow service stands beside the
//! issuer — it arms OID4VP presentations (verifier role), and its
//! `issuance` steps drive the issuer's backend session API (the
//! integrator role). The wallet sees only protocol surfaces: the
//! request object / direct_post.jwt, then the issuer's own
//! credential-offer / token / credential traffic.

use std::sync::Arc;

use siros_flow_core::{Error, Result};
use url::Url;

use siros_flow_service::config::Config;
use siros_flow_service::state::FlowServiceState;
use siros_flow_service::store::MemoryFlowStore;

fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_owned());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("building the tokio runtime");
    runtime.block_on(async move {
        let text = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
            eprintln!("siros-flow-service: reading {config_path}: {e}");
            std::process::exit(1);
        });
        let mut config = Config::from_toml_str(&text).unwrap_or_else(|e| {
            eprintln!("siros-flow-service: {e}");
            std::process::exit(1);
        });
        // Env overrides (the compose deployments parameterize the
        // same file): FLOW_CORE_BIND / FLOW_CORE_PUBLIC_URL.
        if let Ok(bind) = std::env::var("FLOW_CORE_BIND") {
            config.service.bind = Some(bind);
        }
        if let Ok(public) = std::env::var("FLOW_CORE_PUBLIC_URL") {
            config.service.public_url = Some(public);
        }
        if let Err(e) = run(config).await {
            eprintln!("siros-flow-service: {e}");
            std::process::exit(1);
        }
    });
}

async fn run(config: Config) -> Result<()> {
    // The definitions: every one loads and validates, or startup
    // refuses (fail-closed — a deployment's flow set is reviewed).
    let definitions_dir = config
        .definitions
        .dir
        .clone()
        .unwrap_or_else(|| "flows".to_owned());
    let definitions = FlowServiceState::load_definitions(&definitions_dir)?;

    // The request-object signer (the verifier role): a configured JWK,
    // or an ephemeral dev key (development only — restarts rotate it).
    let signer: Arc<dyn siros_issuer_core::signer::Signer> = match &config.signing.jwk_path {
        Some(path) => {
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
        None => {
            eprintln!(
                "siros-flow-service: no signing.jwk_path configured: an ephemeral dev key signs request objects; development only"
            );
            let jwk = jose_rs::jwk::generate_ec("P-256")
                .map_err(|e| Error::configuration(format!("keygen: {e}")))?;
            Arc::new(
                siros_issuer_core::signer::JwkSigner::new(jwk)
                    .map_err(|e| Error::configuration(e.to_string()))?,
            )
        }
    };
    // The request object's x5c: the signer's certificate chain when
    // configured (signing.cert_chain_path semantics mirror the
    // issuer's); absent, verifier-core signs without x5c (dev).
    let cert_chain_der: Vec<Vec<u8>> = Vec::new();

    // The PDP: configured ⇒ the go-trust AuthZEN client; absent ⇒
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

    // The issuer backend the issuance steps drive.
    let issuer: Arc<dyn siros_flow_service::issuer_client::IssuerClient> = {
        let backend = Url::parse(
            &config
                .issuer
                .backend_url
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:8080".to_owned()),
        )
        .map_err(|e| Error::configuration(format!("issuer.backend_url: {e}")))?;
        let audience = config
            .issuer
            .audience
            .clone()
            .unwrap_or_else(|| backend.to_string());
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
        Arc::new(siros_flow_service::issuer_client::IssuerCoreClient::new(
            backend,
            audience,
            integrator_id,
            &key_path,
        )?)
    };

    let public_url = Url::parse(
        &config
            .service
            .public_url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_owned()),
    )
    .map_err(|e| Error::configuration(format!("service.public_url: {e}")))?;
    let bind = config
        .service
        .bind
        .clone()
        .unwrap_or_else(|| "0.0.0.0:8080".to_owned());

    let state_definitions_count = definitions.len();
    let state = Arc::new(FlowServiceState {
        definitions,
        definitions_dir: definitions_dir.clone(),
        store: Arc::new(MemoryFlowStore::new()),
        vault: siros_issuer_service::vault::Vault::new()
            .map_err(|e| Error::configuration(e.to_string()))?,
        signer,
        cert_chain_der,
        pdp,
        issuer,
        public_url,
        presentation_ttl_seconds: config.presentation_ttl_seconds,
        retention_after_final_seconds: config.retention_after_final_seconds,
        bind_registry: siros_flow_service::driver::standard_registry(),
    });

    // The retention sweep (§10): expire past-TTL instances, purge
    // sealed data past retention, on an interval.
    let sweep_state = state.clone();
    let retention = config.retention_after_final_seconds;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let _ = sweep_state
                .store
                .sweep(siros_issuer_service::status::now_unix(), retention)
                .await;
        }
    });

    let router = siros_flow_service::http::router(state);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| Error::configuration(format!("binding {bind}: {e}")))?;
    eprintln!(
        "siros-flow-service: listening on {bind} ({} flows loaded from {definitions_dir:?})",
        state_definitions_count,
    );
    axum::serve(listener, router)
        .await
        .map_err(|e| Error::configuration(format!("serving: {e}")))?;
    Ok(())
}
