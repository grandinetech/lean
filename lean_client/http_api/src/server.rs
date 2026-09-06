use core::net::SocketAddr;

use anyhow::{Context, Error as AnyhowError, Result};
use futures::{TryFutureExt as _, future::FutureExt as _};
use tracing::info;

use crate::{
    aggregator_controller::SharedController,
    config::HttpServerConfig,
    handlers::{SharedSignedBlocks, SharedStore},
    routing::normal_routes,
    test_driver::{TestDriverState, test_driver_routes},
};

pub async fn run_server(
    config: HttpServerConfig,
    store: SharedStore,
    signed_blocks: SharedSignedBlocks,
    aggregator_controller: SharedController,
) -> Result<()> {
    let router = normal_routes(&config, store, signed_blocks, aggregator_controller);
    serve(config, router).await
}

/// Variant of [`run_server`] that additionally mounts the
/// `/lean/v0/test_driver/*` endpoints.
///
/// The test-driver routes are needed for the hive `spec-assets-*` test
/// suites; they are gated behind a separate startup path so they cannot
/// accidentally be served in production. The caller is responsible for
/// deciding (e.g. via the `HIVE_LEAN_TEST_DRIVER` environment variable)
/// whether to invoke this variant or [`run_server`].
pub async fn run_test_driver_server(
    config: HttpServerConfig,
    store: SharedStore,
    signed_blocks: SharedSignedBlocks,
    aggregator_controller: SharedController,
) -> Result<()> {
    let driver_state = TestDriverState::new(store.clone());
    let router = normal_routes(&config, store, signed_blocks, aggregator_controller)
        .merge(test_driver_routes(driver_state));
    serve(config, router).await
}

async fn serve(config: HttpServerConfig, router: axum::Router) -> Result<()> {
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
