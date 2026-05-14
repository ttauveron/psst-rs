mod config;
mod http;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{config::AppConfig, http::build_router};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = AppConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;

    info!(
        bind_addr = %config.bind_addr,
        database_path = %config.database_path.display(),
        enable_create = config.enable_create,
        "starting secret-rs"
    );

    axum::serve(listener, build_router()).await?;
    Ok(())
}

fn init_tracing() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("secret_rs=info,info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().compact().with_target(false))
        .init();
}
