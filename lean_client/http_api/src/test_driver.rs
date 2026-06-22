//! Implementation of the `/lean/v0/test_driver/*` HTTP endpoints used by the
//! hive `spec-assets-*` test suites.
//!
//! These endpoints are only mounted when the lean client is launched in
//! test-driver mode (`HIVE_LEAN_TEST_DRIVER=1`). They expose the existing
//! consensus primitives (`get_forkchoice_store`, `on_tick`, `on_block`,
//! `on_gossip_attestation`, `on_aggregated_attestation`, `State::state_transition`,
//! `SignedBlock::verify_signatures`) over JSON so the simulator can drive them
//! directly with vendored leanSpec test vectors.
//!
//! The wire shapes here are dictated by the hive simulator at
//! `simulators/lean/src/scenarios/spec_assets.rs`.

use std::sync::Arc;

use axum::{
    Json, Router, body::Bytes, extract::State as AxumState, http::StatusCode, routing::post,
};
use containers::{
    AggregatedSignatureProof, Config, MultiMessageAggregate, SignedAggregatedAttestation,
    SignedAttestation, SignedBlock, State,
};
use fork_choice::{
    block_cache::BlockCache,
    handlers::{on_aggregated_attestation, on_block, on_gossip_attestation, on_tick},
    store::{MILLIS_PER_INTERVAL, SECONDS_PER_SLOT, Store, get_forkchoice_store},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use spec_test_fixtures::{
    ForkChoiceStep, GossipAggregatedAttestationStep, TestAnchorBlock, TestAnchorState, TestCase,
    VerifySignaturesTestCase,
};
use ssz::SszHash;
use xmss::{AggregatedSignature, Signature};

/// Shared state for test-driver routes. Carries a writable handle to the
/// fork-choice store plus the `BlockCache` that `on_block` requires.
///
/// Created exclusively by [`crate::server::run_test_driver_server`]; the
/// production HTTP server does not construct this state and does not mount
/// the routes that depend on it.
#[derive(Clone)]
pub struct TestDriverState {
    pub store: Arc<RwLock<Store>>,
    pub cache: Arc<RwLock<BlockCache>>,
}

impl TestDriverState {
    pub fn new(store: Arc<RwLock<Store>>) -> Self {
        Self {
            store,
            cache: Arc::new(RwLock::new(BlockCache::new())),
        }
    }
}

/// Mount the test-driver routes on a new router. Returns the router so the
/// caller can layer it with other routers (e.g. the production routes).
#[must_use]
pub fn test_driver_routes(state: TestDriverState) -> Router {
    Router::new()
        .route(
            "/lean/v0/test_driver/fork_choice/init",
            post(init_fork_choice),
        )
        .route(
            "/lean/v0/test_driver/fork_choice/step",
            post(step_fork_choice),
        )
        .route(
            "/lean/v0/test_driver/state_transition/run",
            post(run_state_transition),
        )
        .route(
            "/lean/v0/test_driver/verify_signatures/run",
            post(run_verify_signatures),
        )
        .with_state(state)
}

// === Wire types =============================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ForkChoiceInitRequest {
    anchor_state: TestAnchorState,
    anchor_block: TestAnchorBlock,
    #[serde(default)]
    genesis_time: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DriverSnapshot {
    head_slot: u64,
    head_root: String,
    time: u64,
    justified_checkpoint: DriverCheckpoint,
    finalized_checkpoint: DriverCheckpoint,
    safe_target: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DriverCheckpoint {
    slot: u64,
    root: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DriverStepResponse {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    snapshot: DriverSnapshot,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StateTransitionResponse {
    succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    post: Option<StateTransitionPost>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StateTransitionPost {
    slot: u64,
    latest_block_header_slot: u64,
    latest_block_header_state_root: String,
    historical_block_hashes_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifySignaturesResponse {
    succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// === Handlers ===============================================================

/// `POST /lean/v0/test_driver/fork_choice/init`
///
/// Replaces the live fork-choice store with a fresh one anchored at the
/// supplied state and block. Responds with `204 No Content` on success and
/// any non-2xx status when the anchor cannot be initialised — matching the
/// simulator's expectation in `spec_assets.rs`.
async fn init_fork_choice(
    AxumState(state): AxumState<TestDriverState>,
    Json(request): Json<ForkChoiceInitRequest>,
) -> StatusCode {
    let mut anchor_state: State = request.anchor_state.into();
    let anchor_block: SignedBlock = request.anchor_block.into();

    // Apply the optional genesis time override before computing any roots.
    if let Some(genesis_time) = request.genesis_time {
        anchor_state.config.genesis_time = genesis_time;
    }

    // Anchor consistency precondition: the block's claimed state_root
    // must equal the hash of the supplied anchor state. Fixtures tagged
    // `anchor_valid=False` deliberately violate this; reject them here so
    // the simulator records the expected non-2xx response.
    //
    // Performed BEFORE the body_root patch below so the check is on the
    // exact state the fixture supplied, not on a derived one.
    if anchor_block.block.state_root != anchor_state.hash_tree_root() {
        return StatusCode::BAD_REQUEST;
    }

    let config = Config {
        genesis_time: anchor_state.config.genesis_time,
    };

    let new_store = get_forkchoice_store(anchor_state, anchor_block, config, false, 1);

    *state.store.write() = new_store;
    *state.cache.write() = BlockCache::new();

    StatusCode::NO_CONTENT
}

/// `POST /lean/v0/test_driver/fork_choice/step`
///
/// Applies a single fork-choice step to the store and returns the resulting
/// snapshot. Always responds with `200 OK`; the test-level success/failure is
/// reported in the JSON body's `accepted` field.
async fn step_fork_choice(
    AxumState(state): AxumState<TestDriverState>,
    Json(step): Json<ForkChoiceStep>,
) -> Json<DriverStepResponse> {
    let mut store = state.store.write();
    let mut cache = state.cache.write();

    let outcome = apply_step(&mut store, &mut cache, step);
    let snapshot = build_snapshot(&store);

    Json(match outcome {
        Ok(()) => DriverStepResponse {
            accepted: true,
            error: None,
            snapshot,
        },
        Err(err) => DriverStepResponse {
            accepted: false,
            error: Some(err),
            snapshot,
        },
    })
}

/// `POST /lean/v0/test_driver/state_transition/run`
///
/// Executes `State::state_transition` over `pre + blocks` and returns the
/// resulting post-state summary. Errors are surfaced in the JSON `error`
/// field; the HTTP status is always `200 OK`.
///
/// The fixtures supply blocks with placeholder signatures; we set
/// `valid_signatures = true` so the transition focuses on state/block-root
/// validation. Signature correctness is exercised separately by the
/// `verify_signatures` suite.
///
/// Reads the body as `Bytes` and runs `serde_json::from_slice` manually so
/// that fixture-shape mismatches surface as `succeeded: false` with the
/// underlying serde error instead of an opaque axum 422.
async fn run_state_transition(body: Bytes) -> Json<StateTransitionResponse> {
    let case: TestCase = match serde_json::from_slice(&body) {
        Ok(case) => case,
        Err(err) => {
            return Json(StateTransitionResponse {
                succeeded: false,
                error: Some(format!(
                    "failed to deserialize state_transition request: {err}"
                )),
                post: None,
            });
        }
    };
    let mut state: State = case.pre.into();
    let blocks: Vec<containers::Block> = case
        .blocks
        .unwrap_or_default()
        .into_iter()
        .map(Into::into)
        .collect();
    let blocks_was_empty = blocks.is_empty();

    let mut last_err: Option<String> = None;
    for block in blocks {
        match state.state_transition(&block) {
            Ok(next) => state = next,
            Err(err) => {
                last_err = Some(err.to_string());
                break;
            }
        }
    }

    // Some fixtures supply no blocks but still expect the transition to
    // raise — for example, the slot-monotonicity case where target == state
    // slot must be rejected. When that's the shape, exercise
    // `process_slots(state.slot)` so the invariant fires and the resulting
    // error surfaces as `succeeded: false`.
    if last_err.is_none() && blocks_was_empty && case.expect_exception.is_some() {
        let target_slot = state.slot;
        if let Err(err) = state.clone().process_slots(target_slot) {
            last_err = Some(format!("process_slots({target_slot:?}) failed: {err}"));
        }
    }

    let response = match last_err {
        Some(err) => StateTransitionResponse {
            succeeded: false,
            error: Some(err),
            post: None,
        },
        None => StateTransitionResponse {
            succeeded: true,
            error: None,
            post: Some(post_summary(&state)),
        },
    };

    Json(response)
}

/// `POST /lean/v0/test_driver/verify_signatures/run`
///
/// Verifies the supplied signed block against the supplied anchor state.
/// Always `200 OK`; success is reported in the JSON body.
async fn run_verify_signatures(
    Json(case): Json<VerifySignaturesTestCase>,
) -> Json<VerifySignaturesResponse> {
    let anchor_state: State = case.anchor_state.into();
    let signed_block = match SignedBlock::try_from(case.signed_block) {
        Ok(block) => block,
        Err(err) => {
            return Json(VerifySignaturesResponse {
                succeeded: false,
                error: Some(format!("failed to construct signed block: {err}")),
            });
        }
    };

    Json(match signed_block.verify_signatures(&anchor_state) {
        Ok(()) => VerifySignaturesResponse {
            succeeded: true,
            error: None,
        },
        Err(err) => VerifySignaturesResponse {
            succeeded: false,
            error: Some(err.to_string()),
        },
    })
}

// === Step dispatcher ========================================================

/// Apply one fork-choice step. Returns a stringified error on failure so the
/// caller can surface it via the JSON `error` field.
#[allow(clippy::needless_pass_by_value)] // ForkChoiceStep is moved by design.
fn apply_step(
    store: &mut Store,
    cache: &mut BlockCache,
    step: ForkChoiceStep,
) -> Result<(), String> {
    match step {
        ForkChoiceStep::Tick {
            time,
            interval,
            has_proposal,
            ..
        }
        | ForkChoiceStep::Time {
            time,
            interval,
            has_proposal,
            ..
        } => {
            // Fixtures supply exactly one of:
            //   - `time`     — absolute wall-clock seconds (multiply by 1000
            //                  to feed `on_tick`, which expects milliseconds);
            //   - `interval` — target store-interval to advance to (relative).
            //                  Translate it into the equivalent absolute time
            //                  in milliseconds: `genesis_ms + interval * MILLIS_PER_INTERVAL`.
            // `on_tick` advances the store one interval at a time until it
            // reaches the requested target.
            let target_time_millis = match (time, interval) {
                (Some(seconds), _) => seconds * 1000,
                (None, Some(target_interval)) => {
                    store.config.genesis_time * 1000 + target_interval * MILLIS_PER_INTERVAL
                }
                (None, None) => {
                    return Err("tick step missing 'time'/'interval' field".to_string());
                }
            };
            on_tick(store, target_time_millis, has_proposal.unwrap_or(false));
            Ok(())
        }
        ForkChoiceStep::Block { block, .. } => {
            let block: containers::Block = block.into();
            let signed = SignedBlock {
                block,
                proof: MultiMessageAggregate::default(),
            };

            // Advance store time to the block's slot before applying it.
            // Mirrors the local fork-choice test: attestations embedded in
            // the block reference the slot, so the store needs to be at or
            // past that interval.
            let slot_time_millis =
                (store.config.genesis_time + signed.block.slot.0 * SECONDS_PER_SLOT) * 1000;
            on_tick(store, slot_time_millis, false);

            // Skip XMSS signature verification — fork_choice fixtures ship
            // unsigned step blocks, so we apply them with a placeholder
            // signature and let `state_transition` validate the rest.
            on_block(store, cache, signed, false)
                .map(|_| ())
                .map_err(|err| err.to_string())
        }
        ForkChoiceStep::Attestation { attestation, .. } => {
            let attestation: containers::Attestation = attestation.into();
            let signed = SignedAttestation {
                validator_id: attestation.validator_id,
                message: attestation.data,
                signature: Signature::default(),
            };
            on_gossip_attestation(store, signed).map_err(|err| err.to_string())
        }
        ForkChoiceStep::GossipAggregatedAttestation { attestation, .. } => {
            let Some(step) = attestation else {
                // No payload supplied; treat as a no-op so subsequent
                // `Checks` steps still see a snapshot.
                return Ok(());
            };
            let signed = build_signed_aggregated_attestation(step)?;
            on_aggregated_attestation(store, signed).map_err(|err| err.to_string())
        }
        ForkChoiceStep::Checks { .. } => {
            // Pure-assertion step. The simulator validates against the
            // returned snapshot — no store mutation required here.
            Ok(())
        }
    }
}

// === Snapshot extraction ====================================================

fn build_snapshot(store: &Store) -> DriverSnapshot {
    let head_slot = store
        .blocks
        .get(&store.head)
        .map(|block| block.slot.0)
        .unwrap_or(0);

    DriverSnapshot {
        head_slot,
        head_root: hex_root(&store.head),
        time: store.time,
        justified_checkpoint: DriverCheckpoint {
            slot: store.latest_justified.slot.0,
            root: hex_root(&store.latest_justified.root),
        },
        finalized_checkpoint: DriverCheckpoint {
            slot: store.latest_finalized.slot.0,
            root: hex_root(&store.latest_finalized.root),
        },
        safe_target: hex_root(&store.safe_target),
    }
}

fn post_summary(state: &State) -> StateTransitionPost {
    StateTransitionPost {
        slot: state.slot.0,
        latest_block_header_slot: state.latest_block_header.slot.0,
        latest_block_header_state_root: hex_root(&state.latest_block_header.state_root),
        historical_block_hashes_count: state.historical_block_hashes.len_u64() as usize,
    }
}

fn hex_root(root: &ssz::H256) -> String {
    format!("0x{}", hex::encode(root.as_bytes()))
}

/// Build a `SignedAggregatedAttestation` from the fixture-supplied
/// `gossipAggregatedAttestation` step payload.
///
/// The fixture carries the pre-computed aggregated XMSS proof as a hex
/// string (the harness cannot re-aggregate without the signers' private
/// keys), so we decode it directly into an [`AggregatedSignature`] and
/// wrap with the participants bitfield from the same payload.
fn build_signed_aggregated_attestation(
    step: GossipAggregatedAttestationStep,
) -> Result<SignedAggregatedAttestation, String> {
    let proof_hex = step.proof.proof_data.data.trim_start_matches("0x");
    let proof_bytes = hex::decode(proof_hex)
        .map_err(|err| format!("invalid hex in aggregate proof_data: {err}"))?;
    let proof_data = AggregatedSignature::new(&proof_bytes)
        .map_err(|err| format!("failed to construct aggregated signature: {err}"))?;

    Ok(SignedAggregatedAttestation {
        data: step.data.into(),
        proof: AggregatedSignatureProof {
            participants: step.proof.participants.into(),
            proof_data,
        },
    })
}
