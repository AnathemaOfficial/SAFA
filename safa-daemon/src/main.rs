use safa_core::actuator::file::cleanup_orphan_temps;
use safa_core::config::AmaConfig;
use safa_daemon::server::{build_router, shutdown_signal, AppState};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = AmaConfig::load(Path::new("config"))?;
    tracing::info!(hashes = ?config.boot_hashes, "Boot integrity verified");
    tracing::info!(
        agent_count = config.agents.len(),
        default_agent = ?config.default_agent_id,
        "Agent configurations loaded"
    );

    let cleaned = cleanup_orphan_temps(&config.workspace_root);
    if cleaned > 0 {
        tracing::warn!(
            count = cleaned,
            "Cleaned up orphan temp files from previous session"
        );
    }

    let bind_addr = format!("{}:{}", config.bind_host, config.bind_port);
    let state = AppState::new(config);

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!(addr = %bind_addr, "SAFA listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("SAFA shut down cleanly");
    Ok(())
}
