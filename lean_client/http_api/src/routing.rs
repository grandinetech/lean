use axum::Router;
use metrics::metrics_module;

use crate::config::HttpServerConfig;

pub fn normal_routes(config: &HttpServerConfig) -> Router {
    let mut router = Router::new();

    if config.metrics_enabled() {
        router = router.merge(metrics_module(config.metrics.clone()));
    }

    router
}
