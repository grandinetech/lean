use std::{error::Error as StdError, time::Duration};

use anyhow::{Error as AnyhowError, Result};
use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use clap::Args;
use http_api_utils::ApiError;
use prometheus::TextEncoder;
use thiserror::Error;
use tower_http::cors::AllowOrigin;

#[derive(Clone, Debug, Args)]
pub struct MetricsServerConfig {
    #[arg(long = "metrics-timeout", default_value_t = Self::default().timeout, requires = "metrics_enabled")]
    timeout: u64,

    #[arg(long = "metrics")]
    metrics_enabled: bool,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: false,
            timeout: Duration::from_secs(1000)
                .as_millis()
                .try_into()
                .expect("should fit into u64"),
        }
    }
}

impl MetricsServerConfig {
    pub fn enabled(&self) -> bool {
        self.metrics_enabled
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("internal error")]
    Internal(#[from] AnyhowError),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl ApiError for Error {
    fn sources(&self) -> impl Iterator<Item = &dyn StdError> {
        let mut error: Option<&dyn StdError> = Some(self);

        core::iter::from_fn(move || {
            let source = error?.source();
            core::mem::replace(&mut error, source)
        })
    }
}

pub fn metrics_module(config: MetricsServerConfig) -> Router {
    let router = Router::new().route("/metrics", get(get_metrics));

    let router = http_api_utils::extend_router_with_middleware::<Error>(
        router,
        Some(Duration::from_millis(config.timeout)),
        AllowOrigin::any(),
        None,
    );

    router
}

/// `GET /metrics`
async fn get_metrics() -> Result<String, Error> {
    let mut buffer = String::new();

    TextEncoder::new()
        .encode_utf8(prometheus::gather().as_slice(), &mut buffer)
        .map_err(AnyhowError::new)?;

    Ok(buffer)
}
