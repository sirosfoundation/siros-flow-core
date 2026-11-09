//! siros-flow-service — the deployable flow service. One binary, one
//! deployment's flows: the definitions, the PDP, the issuer backend —
//! and, with `[issuer.embedded]`, a complete issuer in-process: one
//! service standing as an additional trusted issuer AND verifier,
//! with no trust disabled anywhere (the PDP is go-trust's either way).

use siros_flow_core::{Error, Result};

use siros_flow_service::config::Config;

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
        // Env overrides (the compose/Fly deployments parameterize the
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
    let bind = config
        .service
        .bind
        .clone()
        .unwrap_or_else(|| "0.0.0.0:8080".to_owned());
    let retention = config.retention_after_final_seconds;
    let app = siros_flow_service::app::build(&config)?;

    // The retention sweep (§10): expire past-TTL instances, purge
    // sealed data past retention, on an interval.
    let state = app.state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let _ = state
                .store
                .sweep(siros_issuer_service::status::now_unix(), retention)
                .await;
        }
    });

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| Error::configuration(format!("binding {bind}: {e}")))?;
    match app.embedded_issuer {
        Some(identifier) => eprintln!(
            "siros-flow-service: listening on {bind} — {} flows, issuer {identifier} (embedded)",
            app.state.definitions.len(),
        ),
        None => eprintln!(
            "siros-flow-service: listening on {bind} — {} flows (external issuer backend)",
            app.state.definitions.len(),
        ),
    }
    axum::serve(listener, app.router)
        .await
        .map_err(|e| Error::configuration(format!("serving: {e}")))?;
    Ok(())
}
