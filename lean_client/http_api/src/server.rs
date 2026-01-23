use core::net::SocketAddr;

use anyhow::{Context, Error as AnyhowError, Result};
use futures::{TryFutureExt as _, future::FutureExt as _};
use tracing::info;

use crate::{config::HttpServerConfig, routing::normal_routes};

pub async fn run_server(config: HttpServerConfig) -> Result<()> {
    let router = normal_routes(&config);

    let listener = config
        .listener()
        .await
        .context("failed to start http server")?;

    let service = router.into_make_service_with_connect_info::<SocketAddr>();

    let serve_requests = axum::serve(listener, service)
        .into_future()
        .map_err(AnyhowError::new);

    info!("HTTP server listening on {}", config.address());

    serve_requests.fuse().await
}
