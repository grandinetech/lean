use axum::{Router, routing::get};

use crate::{
    aggregator_controller::SharedController,
    aggregator_handlers,
    config::HttpServerConfig,
    handlers::{self, AppState, SharedStore},
};

pub fn normal_routes(
    _config: &HttpServerConfig,
    store: SharedStore,
    controller: SharedController,
) -> Router {
    let app_state = AppState { store, controller };

    Router::new()
        .route("/lean/v0/health", get(handlers::health))
        .route("/lean/v0/states/finalized", get(handlers::states_finalized))
        .route("/lean/v0/blocks/finalized", get(handlers::blocks_finalized))
        .route(
            "/lean/v0/checkpoints/justified",
            get(handlers::checkpoints_justified),
        )
        .route("/lean/v0/fork_choice", get(handlers::fork_choice))
        .route(
            "/lean/v0/admin/aggregator",
            get(aggregator_handlers::handle_status).post(aggregator_handlers::handle_toggle),
        )
        .with_state(app_state)
}
