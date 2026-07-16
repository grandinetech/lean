use std::{collections::HashMap, sync::Arc};

use axum::{
    Json,
    extract::{FromRef, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use containers::SignedBlock;
use fork_choice::store::Store;
use parking_lot::RwLock;
use serde_json::{Value, json};
use ssz::{H256, SszWrite};

use crate::aggregator_controller::SharedController;

pub type SharedStore = Arc<RwLock<Store>>;
pub type SharedSignedBlocks = Arc<RwLock<HashMap<H256, SignedBlock>>>;

#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub signed_blocks: SharedSignedBlocks,
    pub controller: SharedController,
}

impl FromRef<AppState> for SharedStore {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.store.clone()
    }
}

impl FromRef<AppState> for SharedSignedBlocks {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.signed_blocks.clone()
    }
}

impl FromRef<AppState> for SharedController {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.controller.clone()
    }
}

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "lean-rpc-api"
    }))
}

pub async fn states_finalized(State(store): State<SharedStore>) -> Result<Response, StatusCode> {
    let store = store.read();

    let finalized_root = store.latest_finalized.root;

    let state = store
        .states
        .get(&finalized_root)
        .ok_or(StatusCode::NOT_FOUND)?;

    let ssz_bytes = state
        .to_ssz()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        ssz_bytes,
    )
        .into_response())
}

pub async fn blocks_finalized(
    State(store): State<SharedStore>,
    State(signed_blocks): State<SharedSignedBlocks>,
) -> Result<Response, StatusCode> {
    let store = store.read();
    let signed_blocks = signed_blocks.read();

    let finalized_root = store.latest_finalized.root;

    let block = signed_blocks
        .get(&finalized_root)
        .ok_or(StatusCode::NOT_FOUND)?;

    let ssz_bytes = block
        .to_ssz()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        ssz_bytes,
    )
        .into_response())
}

pub async fn checkpoints_justified(State(store): State<SharedStore>) -> impl IntoResponse {
    let store = store.read();

    Json(json!({
        "slot": store.latest_justified.slot.0,
        "root": format!("0x{}", hex::encode(store.latest_justified.root.as_bytes()))
    }))
}

pub async fn fork_choice(State(store): State<SharedStore>) -> impl IntoResponse {
    let store = store.read();

    let finalized_slot = store.latest_finalized.slot;
    let weights = store.compute_block_weights();

    let nodes: Vec<Value> = store
        .blocks
        .iter()
        .filter(|(_, block)| block.slot >= finalized_slot)
        .map(|(root, block)| {
            let weight = weights.get(root).copied().unwrap_or(0);
            json!({
                "root": format!("0x{}", hex::encode(root.as_bytes())),
                "slot": block.slot.0,
                "parent_root": format!("0x{}", hex::encode(block.parent_root.as_bytes())),
                "proposer_index": block.proposer_index,
                "weight": weight
            })
        })
        .collect();

    let validator_count = store
        .states
        .get(&store.head)
        .map(|state| state.validators.len_u64())
        .unwrap_or(0);

    Json(json!({
        "nodes": nodes,
        "head": format!("0x{}", hex::encode(store.head.as_bytes())),
        "justified": {
            "slot": store.latest_justified.slot.0,
            "root": format!("0x{}", hex::encode(store.latest_justified.root.as_bytes()))
        },
        "finalized": {
            "slot": store.latest_finalized.slot.0,
            "root": format!("0x{}", hex::encode(store.latest_finalized.root.as_bytes()))
        },
        "safe_target": format!("0x{}", hex::encode(store.safe_target.as_bytes())),
        "validator_count": validator_count
    }))
}
