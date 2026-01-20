use crate::Metrics;
use anyhow::{Error as AnyhowError, Result};
use axum::{Router, routing::get, extract::State};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct MetricsServerConfig {
    pub metrics_address: IpAddr,
    pub metrics_port: u16,
    pub timeout: u64,
}

impl From<&MetricsServerConfig> for SocketAddr {
    fn from(config: &MetricsServerConfig) -> Self {
        SocketAddr::from((config.metrics_address, config.metrics_port))
    }
}

async fn prometheus_metrics_handler(State(metrics): State<Arc<Metrics>>) -> String {
    metrics.gather()
}

pub async fn run_metrics_server(config: MetricsServerConfig, metrics: Arc<Metrics>) -> Result<()> {
    let addr = SocketAddr::from(&config);
    eprintln!("metrics server listening on {addr}");

    let router = Router::new()
        .route("/metrics", get(prometheus_metrics_handler))
        .with_state(metrics);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("TCP listener bound successfully");

    // Use axum's serve helper to run the server with connect info
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await
        .map_err(AnyhowError::new)?;

    Ok(())
}
