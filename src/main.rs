mod config;
mod db;
mod http;
mod maintenance;
mod metrics;
mod rate_limit;
mod request_context;
mod secret;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::AppConfig,
    db::Database,
    http::build_router_with_metrics,
    maintenance::spawn_periodic_maintenance,
    metrics::AppMetrics,
};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = AppConfig::from_env()?;
    let database = Database::bootstrap(&config)?;
    let metrics = AppMetrics::new();
    spawn_periodic_maintenance(config.clone(), database.clone(), metrics.clone());
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;

    info!(
        bind_addr = %config.bind_addr,
        database_path = %database.path().display(),
        enable_create = config.enable_create,
        maintenance_interval_seconds = config.maintenance_interval_seconds,
        "starting psst-rs"
    );

    axum::serve(
        listener,
        build_router_with_metrics(config.clone(), database, metrics)
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn init_tracing() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_log_filter()));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().compact().with_target(false))
        .init();
}

fn default_log_filter() -> &'static str {
    "psst_rs=info,warn"
}
