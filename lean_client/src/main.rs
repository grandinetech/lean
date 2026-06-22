#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::{Context as _, Result};
use clap::Parser;
use containers::{
    Block, BlockBody, BlockHeader, Checkpoint, Config, MultiMessageAggregate, SignedBlock, Slot,
    State, Status, Validator,
};
use dedicated_executor::DedicatedExecutor;
use ethereum_types::H256;
use features::Feature;
use fork_choice::{
    block_cache::BlockCache,
    handlers::{
        apply_verified_block, on_aggregated_attestation_async, on_attestation,
        on_gossip_attestation, on_tick, verify_and_transition,
    },
    store::{
        INTERVALS_PER_SLOT, MILLIS_PER_INTERVAL, Store, execute_block_production,
        get_forkchoice_store, prepare_block_production,
    },
    sync_state::SyncState,
};
use http_api::{AggregatorController, HttpServerConfig};
use libp2p_identity::Keypair;
use metrics::{METRICS, Metrics, MetricsServerConfig};
use networking::gossipsub::config::GossipsubConfig;
use networking::gossipsub::topic::{compute_subnet_id, get_subscription_topics};
use networking::network::{NetworkService, NetworkServiceConfig};
use networking::types::{
    CanonicalBlocksProvider, ChainMessage, MAX_BLOCK_CACHE_SIZE, NetworkFinalizedSlot,
    OutboundP2pRequest, SignedBlockProvider, StatusProvider, ValidatorChainMessage,
};
use parking_lot::{Mutex, RwLock};
use ssz::{PersistentList, SszHash, SszReadDefault as _};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io::IsTerminal, net::IpAddr};
use tokio::{
    sync::{Notify, mpsc, oneshot, watch},
    task,
    time::{Duration, Instant, MissedTickBehavior, interval, interval_at},
};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, warn};
use validator::{ValidatorConfig, ValidatorService};
use xmss::{PublicKey, Signature};

mod aggregation;

const BACKFILL_ORPHAN_TRIGGER: usize = 5;
const BACKFILL_RANGE_COUNT: u64 = 256;

fn dispatch_backfill(
    missing: Vec<H256>,
    local_head_slot: u64,
    orphan_count: usize,
    outbound_p2p_sender: &mpsc::UnboundedSender<OutboundP2pRequest>,
) {
    if orphan_count >= BACKFILL_ORPHAN_TRIGGER {
        let request = OutboundP2pRequest::RequestBlocksByRange {
            start_slot: local_head_slot.saturating_add(1),
            count: BACKFILL_RANGE_COUNT,
        };
        if let Err(e) = outbound_p2p_sender.send(request) {
            warn!("Failed to dispatch BlocksByRange backfill: {}", e);
        }
    } else if !missing.is_empty() {
        if let Err(e) = outbound_p2p_sender.send(OutboundP2pRequest::RequestBlocksByRoot(missing)) {
            warn!("Failed to dispatch BlocksByRoot backfill: {}", e);
        }
    }
}

fn load_node_key(path: &str) -> Result<Keypair, Box<dyn std::error::Error>> {
    let hex_str = std::fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(&hex_str)?;
    let secret = libp2p_identity::secp256k1::SecretKey::try_from_bytes(bytes)?;
    let keypair = libp2p_identity::secp256k1::Keypair::from(secret);
    Ok(Keypair::from(keypair))
}

/// Timeout for establishing the TCP/QUIC connection to the checkpoint peer.
/// Fail fast if the peer is unreachable.
const CHECKPOINT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Inactivity timeout for reading the state body.
/// Resets on each successful read, so large states can download as long as
/// data keeps flowing, while stalled connections are detected promptly.
const CHECKPOINT_READ_TIMEOUT: Duration = Duration::from_secs(15);

async fn download_checkpoint_state(url: &str) -> Result<State> {
    info!("Downloading checkpoint state from: {}", url);

    let client = reqwest::Client::builder()
        .connect_timeout(CHECKPOINT_CONNECT_TIMEOUT)
        .read_timeout(CHECKPOINT_READ_TIMEOUT)
        .build()
        .context("Failed to build HTTP client")?;

    let response = client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()
        .await
        .context("Failed to send HTTP request for checkpoint state")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Checkpoint sync failed: HTTP {} from {}",
            response.status(),
            url
        );
    }

    let bytes = response
        .bytes()
        .await
        .context("Failed to read checkpoint state response body")?;

    let state = State::from_ssz_default(&bytes)
        .map_err(|e| anyhow::anyhow!("Failed to decode SSZ checkpoint state: {:?}", e))?;

    info!(
        "Downloaded checkpoint state at slot {} ({} bytes)",
        state.latest_block_header.slot.0,
        bytes.len()
    );

    Ok(state)
}

fn verify_checkpoint_state(state: &State, genesis_state: &State) -> Result<()> {
    // Checkpoint cannot be genesis
    anyhow::ensure!(
        state.slot.0 > 0,
        "Checkpoint state slot must be > 0 (got genesis slot)"
    );

    // Verify genesis time matches
    anyhow::ensure!(
        state.config.genesis_time == genesis_state.config.genesis_time,
        "Genesis time mismatch: checkpoint has {}, expected {}. Wrong network?",
        state.config.genesis_time,
        genesis_state.config.genesis_time
    );

    // Verify state has validators
    let state_validator_count = state.validators.len_u64();
    let expected_validator_count = genesis_state.validators.len_u64();

    anyhow::ensure!(
        state_validator_count > 0,
        "Invalid checkpoint state: no validators in registry"
    );

    // Verify validator count matches
    anyhow::ensure!(
        state_validator_count == expected_validator_count,
        "Validator count mismatch: checkpoint has {}, genesis expects {}. Wrong network?",
        state_validator_count,
        expected_validator_count
    );

    // Verify validator indices are sequential (0, 1, 2, ...)
    for i in 0..state_validator_count {
        let validator = state.validators.get(i).expect("validator exists");
        anyhow::ensure!(
            validator.index == i,
            "Non-sequential validator index at position {i}: expected {i}, got {}",
            validator.index
        );
    }

    // Verify each validator pubkey matches genesis
    for i in 0..state_validator_count {
        let sv = state.validators.get(i).expect("validator exists");
        let gv = genesis_state.validators.get(i).expect("validator exists");

        anyhow::ensure!(
            sv.attestation_pubkey == gv.attestation_pubkey
                && sv.proposal_pubkey == gv.proposal_pubkey,
            "Validator pubkey mismatch at index {i}: checkpoint has different validator set. Wrong network?"
        );
    }

    // Finalized checkpoint cannot be in the future relative to the state
    anyhow::ensure!(
        state.latest_finalized.slot <= state.slot,
        "Finalized slot {} exceeds state slot {}",
        state.latest_finalized.slot.0,
        state.slot.0
    );

    // Justified must be at or after finalized
    anyhow::ensure!(
        state.latest_justified.slot >= state.latest_finalized.slot,
        "Justified slot {} is before finalized slot {}",
        state.latest_justified.slot.0,
        state.latest_finalized.slot.0
    );

    // If justified and finalized are at the same slot, their roots must agree
    if state.latest_justified.slot == state.latest_finalized.slot {
        anyhow::ensure!(
            state.latest_justified.root == state.latest_finalized.root,
            "Justified and finalized are at the same slot ({}) but have different roots",
            state.latest_justified.slot.0
        );
    }

    // Block header cannot be ahead of the state
    anyhow::ensure!(
        state.latest_block_header.slot <= state.slot,
        "Block header slot {} exceeds state slot {}",
        state.latest_block_header.slot.0,
        state.slot.0
    );

    info!(
        "Checkpoint state verified: slot={}, genesis_time={}, validators={}, finalized={}, justified={}",
        state.slot.0,
        state.config.genesis_time,
        state_validator_count,
        state.latest_finalized.slot.0,
        state.latest_justified.slot.0,
    );

    Ok(())
}

fn print_chain_status(store: &Store, connected_peers: u64) {
    let current_slot = store.time / INTERVALS_PER_SLOT;

    // Per leanSpec, store.blocks now contains Block (not SignedBlockWithAttestation)
    let head_slot = store.blocks.get(&store.head).map(|b| b.slot.0).unwrap_or(0);

    let behind = if current_slot > head_slot {
        current_slot - head_slot
    } else {
        0
    };

    // Per leanSpec, store.blocks now contains Block (not SignedBlockWithAttestation)
    let (head_root, parent_root, state_root) = if let Some(block) = store.blocks.get(&store.head) {
        let head_root = store.head;
        let parent_root = block.parent_root;
        let state_root = block.state_root;
        (head_root, parent_root, state_root)
    } else {
        (H256::zero(), H256::zero(), H256::zero())
    };

    // Read from store's checkpoints (updated by on_block, reflects highest seen)
    let justified = store.latest_justified.clone();
    let finalized = store.latest_finalized.clone();

    let timely = behind == 0;

    METRICS
        .get()
        .map(|m| m.grandine_slots_behind.set(behind as i64));

    println!("\n+===============================================================+");
    println!(
        "  CHAIN STATUS: Current Slot: {} | Head Slot: {} | Behind: {}",
        current_slot, head_slot, behind
    );
    println!("+---------------------------------------------------------------+");
    println!("  Connected Peers:    {}", connected_peers);
    println!("+---------------------------------------------------------------+");
    println!("  Head Block Root:    0x{:x}", head_root);
    println!("  Parent Block Root:  0x{:x}", parent_root);
    println!("  State Root:         0x{:x}", state_root);
    println!(
        "  Timely:             {}",
        if timely { "YES" } else { "NO" }
    );
    println!("+---------------------------------------------------------------+");
    println!(
        "  Latest Justified:   Slot {:>5} | Root: 0x{:x}",
        justified.slot.0, justified.root
    );
    println!(
        "  Latest Finalized:   Slot {:>5} | Root: 0x{:x}",
        finalized.slot.0, finalized.root
    );
    println!("+===============================================================+\n");
}

fn check_sync_trigger(state: &mut SyncState, head_slot: u64, network_finalized: Option<u64>) {
    if state.is_syncing() {
        return;
    }
    let Some(nf) = network_finalized else {
        return;
    };
    if nf > head_slot || state.is_idle() {
        let prev = *state;
        *state = SyncState::Syncing;
        info!(head_slot, network_finalized = nf, prev = ?prev, "Sync state: → SYNCING");
        METRICS.get().map(|m| m.set_sync_status("syncing"));
    }
}

fn check_sync_complete(
    state: &mut SyncState,
    head_slot: u64,
    orphan_count: usize,
    network_finalized: Option<u64>,
) {
    if !state.is_syncing() {
        return;
    }
    if orphan_count > 0 {
        return;
    }
    let Some(nf) = network_finalized else {
        return;
    };
    if head_slot >= nf {
        *state = SyncState::Synced;
        info!(
            head_slot,
            network_finalized = nf,
            "Sync state: SYNCING → SYNCED"
        );
        METRICS.get().map(|m| m.set_sync_status("synced"));
    }
}

fn check_sync_idle(state: &mut SyncState) {
    if state.is_idle() {
        return;
    }
    let prev = *state;
    *state = SyncState::Idle;
    info!(prev = ?prev, "Sync state: → IDLE (no peers)");
    METRICS.get().map(|m| m.set_sync_status("idle"));
}

fn evaluate_sync_state(
    state: &mut SyncState,
    peers: u64,
    head_slot: u64,
    network_finalized: Option<u64>,
) {
    if peers == 0 {
        check_sync_idle(state);
    } else {
        check_sync_trigger(state, head_slot, network_finalized);
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    address: IpAddr,

    #[arg(short, long, default_value_t = 8083)]
    port: u16,

    #[arg(short, long, default_value_t = 8084)]
    discovery_port: u16,

    #[arg(long, default_value_t = false)]
    disable_discovery: bool,

    #[arg(short, long)]
    bootnodes: Vec<String>,

    #[arg(short, long)]
    genesis: Option<String>,

    #[arg(long)]
    node_id: Option<String>,

    /// Path: validators.yaml
    #[arg(long)]
    validator_registry_path: Option<String>,

    /// Path: p2p private key
    #[arg(long)]
    node_key: Option<String>,

    /// Path: directory containing XMSS validator keys (validator_N_sk.ssz files)
    #[arg(long)]
    hash_sig_key_dir: Option<String>,

    #[command(flatten)]
    http_config: HttpServerConfig,

    #[command(flatten)]
    metrics_config: MetricsServerConfig,

    /// List of optional runtime features to enable
    #[clap(long, value_delimiter = ',')]
    features: Vec<Feature>,

    /// Enable aggregator mode (devnet-3)
    /// When enabled, this node will aggregate attestations at interval 2
    #[arg(long = "is-aggregator", default_value_t = false)]
    is_aggregator: bool,

    /// Comma-separated attestation subnet IDs to additionally subscribe and aggregate from
    /// (e.g. "0,1,2"). Requires --is-aggregator. Additive to validator-derived subnets.
    #[arg(long = "aggregate-subnet-ids", value_delimiter = ',')]
    aggregate_subnet_ids: Vec<u64>,

    /// Override attestation committee count (devnet-3)
    /// When set, uses this value instead of the hardcoded default
    #[arg(long = "attestation-committee-count")]
    attestation_committee_count: Option<u64>,

    #[arg(long)]
    checkpoint_sync_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let rayon_threads = num_cpus::get().saturating_sub(3).max(1);
    xmss::configure_rayon_pool(rayon_threads);
    xmss::setup_aggregation();

    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    info!(
        "Starting grandine v{} ({})",
        env!("CARGO_PKG_VERSION"),
        git_version::git_version!(args = ["--always", "--abbrev=8"]),
    );

    let args = Args::parse();

    for feature in args.features {
        feature.enable();
    }

    let metrics = if args.metrics_config.enabled() {
        let metrics = Metrics::new()?;
        metrics.register_with_default_metrics()?;
        let metrics = Arc::new(metrics);
        METRICS.get_or_init(|| metrics.clone());

        Some(metrics)
    } else {
        None
    };

    metrics
        .map(|metrics| {
            metrics.set_client_version("grandine".to_owned(), "0.0.0".to_owned());
            metrics.set_start_time(SystemTime::now())
        })
        .transpose()
        .context("failed to set metrics on start")?;

    // Record aggregator metric on startup (committee count set after genesis is loaded).
    METRICS.get().map(|metrics| {
        metrics
            .lean_is_aggregator
            .set(if args.is_aggregator { 1 } else { 0 });
    });

    let (outbound_p2p_sender, outbound_p2p_receiver) =
        mpsc::unbounded_channel::<OutboundP2pRequest>();
    let (chain_message_sender, mut chain_message_receiver) = mpsc::channel::<ChainMessage>(1024);
    // Separate channel for validator task → chain task request-response messages.
    // Keeps ValidatorChainMessage (which carries oneshot senders) separate from
    // ChainMessage (which is Clone and used by the network layer).
    let (validator_chain_sender, mut validator_chain_receiver) =
        mpsc::unbounded_channel::<ValidatorChainMessage>();

    let num_cpus = num_cpus::get();

    let cpu_normal_executor = Arc::new(DedicatedExecutor::new(
        "lean-cpu-normal",
        (num_cpus / 2).max(2),
        None,
        None,
    ));
    let cpu_snark_executor = Arc::new(DedicatedExecutor::new("lean-snark", 1, None, None));
    let cpu_verify_executor = Arc::new(DedicatedExecutor::new("lean-verify", 1, None, None));
    let cpu_aggregation_executor =
        Arc::new(DedicatedExecutor::new("lean-aggregation", 1, None, None));

    // Verified blocks travel back from the executor to the chain task on this channel.
    // Tuple: (block_root, signed_block, should_gossip, verify outcome).
    // `should_gossip` is threaded so Phase 3 can rebroadcast only blocks that arrived
    // with should_gossip=true AND applied successfully (Bug 1 invariant).
    // tx side increments `grandine_verify_result_channel_depth`; rx decrements after recv.
    //
    // Shutdown semantics: if the chain task exits, `verify_result_rx` is dropped and
    // any in-flight `tx.send()` returns Err — the spawned forwarder rolls back the
    // gauge inc and exits. The verify itself runs to completion on the executor
    // (output discarded). `DedicatedExecutor::Drop` joins worker threads, so no
    // verify thread leaks past process shutdown.
    let (verify_result_tx, mut verify_result_rx) =
        mpsc::channel::<(H256, SignedBlock, bool, Result<State>)>(1024);

    let (genesis_time, validators, genesis_log_inv_rate, genesis_attestation_committee_count) =
        if let Some(genesis_path) = &args.genesis {
            let genesis_config = containers::GenesisConfig::load_from_file(genesis_path)
                .expect("Failed to load genesis config");

            let validators: Vec<Validator> = genesis_config
                .genesis_validators
                .iter()
                .enumerate()
                .map(|(i, entry)| {
                    let attestation_pubkey: PublicKey = entry
                        .attestation_pubkey
                        .parse()
                        .expect("Invalid genesis validator attestation_pubkey");
                    let proposal_pubkey: PublicKey = entry
                        .proposal_pubkey
                        .parse()
                        .expect("Invalid genesis validator proposal_pubkey");
                    Validator {
                        attestation_pubkey,
                        proposal_pubkey,
                        index: i as u64,
                    }
                })
                .collect();

            (
                genesis_config.genesis_time,
                validators,
                genesis_config.log_inv_rate,
                genesis_config.attestation_committee_count,
            )
        } else {
            let num_validators = 3;
            let validators = (0..num_validators)
                .map(|i| Validator {
                    attestation_pubkey: PublicKey::default(),
                    proposal_pubkey: PublicKey::default(),
                    index: i as u64,
                })
                .collect();
            (1763757427, validators, 2u8, 1u64)
        };

    // CLI --attestation-committee-count overrides genesis config; both fall back to 1.
    let attestation_committee_count = args
        .attestation_committee_count
        .unwrap_or(genesis_attestation_committee_count)
        .max(1);
    METRICS.get().map(|metrics| {
        metrics
            .lean_attestation_committee_count
            .set(attestation_committee_count as i64);
    });

    let genesis_state = State::generate_genesis_with_validators(genesis_time, validators);

    let genesis_block = Block {
        slot: Slot(0),
        proposer_index: 0,
        parent_root: H256::zero(),
        state_root: genesis_state.hash_tree_root(),
        body: BlockBody {
            attestations: Default::default(),
        },
    };

    let genesis_signed_block = SignedBlock {
        block: genesis_block,
        proof: MultiMessageAggregate::default(),
    };

    let config = Config { genesis_time };

    // ── Anchor state: download checkpoint or use genesis ─────────────────────────────────────
    // For checkpoint sync: state is downloaded now; the anchor block is fetched from the
    // network after the network service starts.  `checkpoint_block_root` holds the expected
    // block root that MUST arrive before the store is initialised.
    // For genesis: state and block are both ready immediately; no network wait is needed.
    let anchor_state: State;
    let checkpoint_block_root: Option<H256>;
    let anchor_block_root: H256;

    if let Some(ref url) = args.checkpoint_sync_url {
        info!("Checkpoint sync enabled, downloading from: {}", url);
        match download_checkpoint_state(url).await {
            Ok(checkpoint_state) => {
                if let Err(e) = verify_checkpoint_state(&checkpoint_state, &genesis_state) {
                    error!("Checkpoint verification failed: {}. Refusing to start.", e);
                    return Err(e);
                }
                let checkpoint_state_root = checkpoint_state.hash_tree_root();
                let checkpoint_block_header = BlockHeader {
                    slot: checkpoint_state.latest_block_header.slot,
                    proposer_index: checkpoint_state.latest_block_header.proposer_index,
                    parent_root: checkpoint_state.latest_block_header.parent_root,
                    state_root: checkpoint_state_root,
                    body_root: checkpoint_state.latest_block_header.body_root,
                };
                let root = checkpoint_block_header.hash_tree_root();
                info!(
                    slot = checkpoint_state.slot.0,
                    finalized = checkpoint_state.latest_finalized.slot.0,
                    justified = checkpoint_state.latest_justified.slot.0,
                    block_root = %format!("0x{:x}", root),
                    state_root = %format!("0x{:x}", checkpoint_state_root),
                    "Checkpoint state downloaded and verified — will fetch anchor block from network"
                );
                anchor_state = checkpoint_state;
                checkpoint_block_root = Some(root);
                anchor_block_root = root;
            }
            Err(e) => {
                return Err(e.context(
                    "Checkpoint sync failed. Fix the error and restart; \
                     the node will not fall back to genesis when --checkpoint-sync-url is set.",
                ));
            }
        }
    } else {
        anchor_state = genesis_state.clone();
        checkpoint_block_root = None;
        // Genesis path: reconstruct root from state's latest block header.
        anchor_block_root = BlockHeader {
            slot: anchor_state.latest_block_header.slot,
            proposer_index: anchor_state.latest_block_header.proposer_index,
            parent_root: anchor_state.latest_block_header.parent_root,
            state_root: anchor_state.hash_tree_root(),
            body_root: anchor_state.latest_block_header.body_root,
        }
        .hash_tree_root();
    }

    let num_validators = anchor_state.validators.len_u64();
    info!(num_validators = num_validators, "Anchor state loaded");

    let validator_service = if let (Some(node_id), Some(registry_path)) =
        (&args.node_id, &args.validator_registry_path)
    {
        match ValidatorConfig::load_from_file(registry_path, node_id) {
            Ok(config) => {
                // Use explicit hash-sig-key-dir if provided
                if let Some(ref keys_dir) = args.hash_sig_key_dir {
                    let keys_path = std::path::Path::new(keys_dir);
                    if keys_path.exists() {
                        match ValidatorService::new_with_keys_and_aggregator(
                            config.clone(),
                            num_validators,
                            keys_path,
                            cpu_normal_executor.clone(),
                            cpu_verify_executor.clone(),
                            cpu_snark_executor.clone(),
                            args.is_aggregator,
                        ) {
                            Ok(service) => {
                                info!(
                                    node_id = %node_id,
                                    indices = ?config.validator_indices,
                                    keys_dir = ?keys_path,
                                    aggregator = args.is_aggregator,
                                    "Validator mode enabled with XMSS signing"
                                );
                                Some(service)
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to load XMSS keys: {}, falling back to zero signatures",
                                    e
                                );
                                Some(ValidatorService::new_with_aggregator(
                                    config,
                                    num_validators,
                                    cpu_normal_executor.clone(),
                                    cpu_verify_executor.clone(),
                                    cpu_snark_executor.clone(),
                                    args.is_aggregator,
                                ))
                            }
                        }
                    } else {
                        warn!(
                            "Hash-sig key directory not found: {:?}, using zero signatures",
                            keys_path
                        );
                        Some(ValidatorService::new_with_aggregator(
                            config,
                            num_validators,
                            cpu_normal_executor.clone(),
                            cpu_verify_executor.clone(),
                            cpu_snark_executor.clone(),
                            args.is_aggregator,
                        ))
                    }
                } else {
                    info!(
                        node_id = %node_id,
                        indices = ?config.validator_indices,
                        aggregator = args.is_aggregator,
                        "Validator mode enabled (no --hash-sig-key-dir specified - using zero signatures)"
                    );
                    Some(ValidatorService::new_with_aggregator(
                        config,
                        num_validators,
                        cpu_normal_executor.clone(),
                        cpu_verify_executor.clone(),
                        cpu_snark_executor.clone(),
                        args.is_aggregator,
                    ))
                }
            }
            Err(e) => {
                warn!("Failed to load validator config: {}", e);
                None
            }
        }
    } else {
        info!("Running in passive mode (no validator duties)");
        None
    };

    // Wrap in Arc so chain task (aggregation at tick 2) and validator task (proposal/attestation)
    // can both access ValidatorService without cloning the XMSS keys.
    let validator_service: Option<Arc<ValidatorService>> = validator_service.map(Arc::new);
    // Chain task clone: used only for tick-2 aggregation (maybe_aggregate takes &self)
    let vs_for_chain = validator_service.clone();
    let vs_for_chain_proposer = validator_service.clone();
    // Validator task: takes ownership for proposal and attestation duties
    let vs_for_validator = validator_service.clone();
    // Admin API controller: toggles is_aggregator at runtime on both store and validator service
    let vs_for_controller = validator_service.clone();
    // Validator task needs to send ProcessBlock / ProcessAttestation back to the chain task
    let chain_msg_sender_for_validator = chain_message_sender.clone();

    // Validate: --aggregate-subnet-ids requires --is-aggregator
    if !args.aggregate_subnet_ids.is_empty() && !args.is_aggregator {
        eprintln!("error: --aggregate-subnet-ids requires --is-aggregator to be set");
        std::process::exit(1);
    }

    // Collect all registered validator indices for subnet subscription.
    // Per leanSpec PR #482: every validator's derived subnet is subscribed, not just the first.
    let validator_ids: Vec<u64> = validator_service
        .as_ref()
        .map(|service| service.config.validator_indices.clone())
        .unwrap_or_default();

    // Record subnet metric for the first validator if available.
    if let Some(&first_vid) = validator_ids.first() {
        let subnet_id = compute_subnet_id(first_vid, attestation_committee_count);
        METRICS.get().map(|metrics| {
            metrics
                .lean_attestation_committee_subnet
                .set(subnet_id as i64);
        });
    }

    let fork = "12345678".to_string();
    // Subscribe to topics based on validator role (leanSpec PR #482):
    // - All validators: subscribe to each validator's derived subnet
    // - Aggregators: additionally subscribe to explicit aggregate_subnet_ids
    // - Aggregators with no validators: fall back to subnet 0
    // - Non-validators/non-aggregators: skip attestation subscriptions entirely
    let gossipsub_topics = get_subscription_topics(
        fork,
        &validator_ids,
        args.is_aggregator,
        &args.aggregate_subnet_ids,
        attestation_committee_count,
    );
    let mut gossipsub_config = GossipsubConfig::new();
    gossipsub_config.set_topics(gossipsub_topics);

    let discovery_enabled = !args.disable_discovery;

    let network_service_config = Arc::new(NetworkServiceConfig::new(
        gossipsub_config,
        args.address,
        args.port,
        args.discovery_port,
        discovery_enabled,
        args.bootnodes,
    ));

    let peer_count = Arc::new(AtomicU64::new(0));
    let peer_count_for_status = peer_count.clone();

    // Create shared block provider for BlocksByRoot requests.
    // Start empty: the anchor block is inserted after it is received from the network
    // (checkpoint path) or after get_forkchoice_store returns (genesis path).
    let signed_block_provider: SignedBlockProvider = Arc::new(RwLock::new(HashMap::new()));
    let signed_block_provider_for_network = signed_block_provider.clone();

    // Build initial status from anchor state so peers know our finalized checkpoint and head
    // before the store is initialised.  Updated once the store is ready.
    let initial_status = Status::new(
        anchor_state.latest_finalized.clone(),
        Checkpoint {
            root: anchor_block_root,
            slot: anchor_state.latest_block_header.slot,
        },
    );
    let status_provider: StatusProvider = Arc::new(RwLock::new(initial_status));
    let status_provider_for_network = status_provider.clone();

    let network_finalized_slot: NetworkFinalizedSlot = Arc::new(Mutex::new(None));
    let network_finalized_slot_for_network = network_finalized_slot.clone();

    let canonical_blocks_provider: CanonicalBlocksProvider = {
        let block_provider = signed_block_provider.clone();
        let status = status_provider.clone();
        Arc::new(move |start_slot: u64, count: u64| -> Vec<SignedBlock> {
            if count == 0 {
                return Vec::new();
            }
            let end_slot = start_slot.saturating_add(count.saturating_sub(1));
            let head_root = status.read().head.root;
            let mut by_slot: HashMap<u64, SignedBlock> = HashMap::new();
            {
                let blocks = block_provider.read();
                let mut current_root = head_root;
                while !current_root.is_zero() {
                    let Some(block) = blocks.get(&current_root) else {
                        break;
                    };
                    let slot = block.block.slot.0;
                    if slot < start_slot {
                        break;
                    }
                    if slot <= end_slot {
                        by_slot.insert(slot, block.clone());
                    }
                    current_root = block.block.parent_root;
                }
            }
            let mut result: Vec<(u64, SignedBlock)> = by_slot.into_iter().collect();
            result.sort_by_key(|(s, _)| *s);
            result.into_iter().map(|(_, b)| b).collect()
        })
    };

    let status_notify = Arc::new(Notify::new());

    // LOAD NODE KEY
    let mut network_service = if let Some(key_path) = &args.node_key {
        match load_node_key(key_path) {
            Ok(keypair) => {
                let peer_id = keypair.public().to_peer_id();
                info!(peer_id = %peer_id, "Using custom node key");
                NetworkService::new_with_keypair(
                    network_service_config.clone(),
                    outbound_p2p_receiver,
                    chain_message_sender.clone(),
                    peer_count,
                    keypair,
                    signed_block_provider_for_network,
                    status_provider_for_network,
                    canonical_blocks_provider.clone(),
                    network_finalized_slot_for_network,
                    status_notify.clone(),
                )
                .await
                .expect("Failed to create network service with custom key")
            }
            Err(e) => {
                warn!("Failed to load node key: {}, using random key", e);
                NetworkService::new_with_peer_count(
                    network_service_config.clone(),
                    outbound_p2p_receiver,
                    chain_message_sender.clone(),
                    peer_count,
                    signed_block_provider_for_network,
                    status_provider_for_network,
                    canonical_blocks_provider.clone(),
                    network_finalized_slot_for_network,
                    status_notify.clone(),
                )
                .await
                .expect("Failed to create network service")
            }
        }
    } else {
        NetworkService::new_with_peer_count(
            network_service_config.clone(),
            outbound_p2p_receiver,
            chain_message_sender.clone(),
            peer_count,
            signed_block_provider_for_network,
            status_provider_for_network,
            canonical_blocks_provider.clone(),
            network_finalized_slot_for_network,
            status_notify.clone(),
        )
        .await
        .expect("Failed to create network service")
    };

    let network_handle = task::spawn(async move {
        if let Err(err) = network_service.start().await {
            panic!("Network service exited with error: {err}");
        }
    });

    // ── Anchor block: fetch from network (checkpoint) or use genesis block directly ──────────
    // Genesis path  : genesis_signed_block is ready immediately; no network wait needed.
    // Checkpoint path: send periodic BlocksByRoot(checkpoint_block_root) requests until a peer
    //   delivers the block.  Blocks that arrive with a non-matching root are discarded here;
    //   they will be re-requested by the normal backfill mechanism once the chain task starts.
    //   Abort with a clear error if no valid block arrives within the timeout.
    const ANCHOR_BLOCK_TIMEOUT_SECS: u64 = 300;

    let anchor_block: SignedBlock = if let Some(expected_root) = checkpoint_block_root {
        info!(
            block_root = %format!("0x{:x}", expected_root),
            timeout_secs = ANCHOR_BLOCK_TIMEOUT_SECS,
            "Waiting for anchor block from network"
        );

        let mut retry_interval = interval(Duration::from_secs(5));

        // Wrap the loop in tokio::time::timeout so the deadline fires unconditionally at
        // T+ANCHOR_BLOCK_TIMEOUT_SECS, regardless of how many non-anchor messages arrive.
        // A deadline arm inside a biased select would be starved when peers continuously
        // deliver other blocks and the channel is never empty.
        let timeout_result = tokio::time::timeout(
            Duration::from_secs(ANCHOR_BLOCK_TIMEOUT_SECS),
            async {
                loop {
                    tokio::select! {
                        msg = chain_message_receiver.recv() => {
                            let Some(msg) = msg else {
                                return Err(anyhow::anyhow!(
                                    "Chain message channel closed during anchor block wait"
                                ));
                            };
                            METRICS.get().map(|m| m.grandine_chain_message_channel_depth.dec());
                            if let ChainMessage::ProcessBlock { signed_block, .. } = msg {
                                let root = signed_block.block.hash_tree_root();
                                if root == expected_root {
                                    // Root match guarantees slot, proposer_index, parent_root,
                                    // state_root, and body contents (via body_root).
                                    // proposer_signature is NOT covered by the hash — verify it
                                    // explicitly so a peer serving a validly-hashed but unsigned
                                    // block cannot become our anchor.
                                    match signed_block.verify_signatures(&anchor_state) {
                                        Ok(()) => {
                                            info!(
                                                slot = signed_block.block.slot.0,
                                                block_root = %format!("0x{:x}", root),
                                                "Anchor block received and verified — initialising fork-choice store"
                                            );
                                            return Ok(signed_block);
                                        }
                                        Err(e) => {
                                            warn!(
                                                slot = signed_block.block.slot.0,
                                                block_root = %format!("0x{:x}", root),
                                                error = %e,
                                                "Anchor block signature verification failed — \
                                                 discarding, waiting for valid block from another peer"
                                            );
                                            // Keep waiting; the retry interval will re-request from peers.
                                        }
                                    }
                                } else {
                                    debug!(
                                        slot = signed_block.block.slot.0,
                                        root = %format!("0x{:x}", root),
                                        "Waiting for anchor block — discarding non-anchor block"
                                    );
                                }
                            }
                            // Attestations and aggregations before the store is ready: discard silently.
                        }
                        _ = retry_interval.tick() => {
                            let _ = outbound_p2p_sender.send(
                                OutboundP2pRequest::RequestBlocksByRoot(vec![expected_root])
                            );
                        }
                    }
                }
            },
        )
        .await;

        match timeout_result {
            Err(_elapsed) => {
                return Err(anyhow::anyhow!(
                    "Anchor block 0x{:x} not received within {} seconds. \
                     The checkpoint source may be on a minority fork. \
                     Verify the checkpoint URL and retry.",
                    expected_root,
                    ANCHOR_BLOCK_TIMEOUT_SECS,
                ));
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok(block)) => block,
        }
    } else {
        // Genesis path: block was prepared at startup, no network wait needed.
        genesis_signed_block
    };

    // ── Initialise fork-choice store with the real anchor block ──────────────────────────────
    let anchor_block_for_provider = anchor_block.clone();

    let store = Arc::new(RwLock::new(get_forkchoice_store(
        anchor_state.clone(),
        anchor_block,
        config.clone(),
        args.is_aggregator,
        genesis_log_inv_rate as usize,
    )));

    // Seed the block provider so we can serve the anchor block to peers via BlocksByRoot.
    {
        let mut provider = signed_block_provider.write();
        provider.insert(anchor_block_root, anchor_block_for_provider);
    }

    // Sync status_provider to the now-initialised store (ensures head root/slot are accurate).
    {
        let s = store.read();
        let mut status = status_provider.write();
        status.finalized = s.latest_finalized.clone();
        status.head = Checkpoint {
            root: s.head,
            slot: s.blocks.get(&s.head).map(|b| b.slot).unwrap_or(Slot(0)),
        };

        METRICS.get().map(|m| {
            if let Ok(j) = i64::try_from(s.latest_justified.slot.0) {
                m.lean_latest_justified_slot.set(j);
            }
            if let Ok(f) = i64::try_from(s.latest_finalized.slot.0) {
                m.lean_latest_finalized_slot.set(f);
            }
        });
    }

    let chain_outbound_sender = outbound_p2p_sender.clone();

    let http_store = store.clone();
    let aggregator_controller =
        Arc::new(AggregatorController::new(store.clone(), vs_for_controller));
    // The hive `spec-assets-*` test suites drive the client through the
    // `/lean/v0/test_driver/*` endpoints. They are only mounted when the
    // simulator launches the client with `HIVE_LEAN_TEST_DRIVER=1`, so a
    // production-mode binary will continue to expose the normal HTTP API
    // and return 404 for any test-driver paths that get accidentally hit.
    let test_driver_enabled = matches!(
        std::env::var("HIVE_LEAN_TEST_DRIVER")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("TRUE") | Some("yes")
    );
    task::spawn(async move {
        let result = if test_driver_enabled {
            info!("HTTP server starting in test-driver mode (HIVE_LEAN_TEST_DRIVER=1)");
            http_api::run_test_driver_server(
                args.http_config,
                http_store,
                Some(aggregator_controller),
            )
            .await
        } else {
            http_api::run_server(args.http_config, http_store, Some(aggregator_controller)).await
        };
        if let Err(err) = result {
            error!("HTTP Server failed with error: {err:?}");
        }
    });

    task::spawn(async move {
        if args.metrics_config.enabled()
            && let Err(err) = metrics::run_server(args.metrics_config, genesis_time).await
        {
            error!("Metrics server failed with error: {err:?}");
        }
    });

    // Compute genesis-aligned tick delay once; both tasks capture genesis_millis and
    // genesis_tick_delay by copy (u64 / Duration are Copy).
    let genesis_millis = genesis_time * 1000;
    let genesis_tick_delay = {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let elapsed = now.saturating_sub(genesis_millis);
        let next = elapsed / MILLIS_PER_INTERVAL + 1;
        Duration::from_millis((genesis_millis + next * MILLIS_PER_INTERVAL).saturating_sub(now))
    };

    let chain_log_inv_rate = genesis_log_inv_rate as usize;

    // ── Aggregation background task ────────────────────────────────────────────
    // XMSS aggregation takes 1-3 s. Running it inside the tick loop via .await
    // blocks the executor, causing Tokio to burst-fire all missed ticks and keeps
    // the node 15-19 slots behind. Instead we decouple it: the tick loop sends a
    // (slot, store_snapshot) trigger and immediately continues; a dedicated task
    // runs spawn_blocking and sends the result back via a result channel.
    //
    // watch channel = lossless latest-value semantics: send() always overwrites so
    // the aggregation task always sees the most recent trigger even if XMSS was
    // still running when a newer slot arrived. No trigger is ever silently dropped.
    let mut aggregator = vs_for_chain.map(|vs| {
        aggregation::AggregationService::new(
            vs,
            store.clone(),
            chain_log_inv_rate,
            cpu_aggregation_executor.clone(),
        )
    });
    // Whether this node has any validator service at all. Used for sync-state
    // coloring; NOT a per-slot aggregator gate. The per-slot aggregator check
    // lives at the snapshot trigger site below and goes through
    // `AggregationService::is_aggregator_for_slot`.
    let has_aggregator = aggregator.is_some();

    // Channel for the chain task to signal block arrival to the validator task.
    let (block_slot_tx, block_slot_rx) = watch::channel::<u64>(0);

    let chain_handle = task::spawn(async move {
        let mut tick_interval = interval_at(
            Instant::now() + genesis_tick_delay,
            Duration::from_millis(MILLIS_PER_INTERVAL),
        );
        tick_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_logged_slot = 0u64;
        // Track the last slot for which aggregation was triggered so the catch-up
        // guard never fires twice for the same slot.
        let mut last_agg_slot: u64 = 0;
        let mut last_status_slot: Option<u64> = None;
        // Tracks the previous tick instant so the duration between consecutive
        // chain-task ticks can be observed at the top of each tick arm.
        let mut last_tick_instant: Option<Instant> = None;
        let mut block_cache = BlockCache::new();
        let mut sync_state = if has_aggregator {
            SyncState::Syncing
        } else {
            SyncState::Idle
        };
        METRICS
            .get()
            .map(|m| m.set_sync_status(if has_aggregator { "syncing" } else { "idle" }));

        let peer_count = peer_count_for_status;

        loop {
            tokio::select! {
                biased;
                _ = tick_interval.tick() => {
                    // Observe the duration since the previous tick before any
                    // processing. The first tick after startup has nothing to
                    // measure against and is skipped.
                    let tick_instant = Instant::now();
                    let tick_elapsed = last_tick_instant
                        .map(|prev| tick_instant.duration_since(prev).as_secs_f64());
                    if let Some(elapsed) = tick_elapsed {
                        METRICS.get().map(|m| {
                            m.lean_tick_interval_duration_seconds.observe(elapsed)
                        });
                    }
                    last_tick_instant = Some(tick_instant);

                    let now_millis = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let target_interval = now_millis.saturating_sub(genesis_millis) / MILLIS_PER_INTERVAL;
                    let target_slot = target_interval / INTERVALS_PER_SLOT;
                    let next_is_interval_0 = target_interval % INTERVALS_PER_SLOT == 0;
                    let has_proposal = next_is_interval_0
                        && target_slot > 0
                        && vs_for_chain_proposer
                            .as_ref()
                            .and_then(|vs| vs.get_proposer_for_slot(Slot(target_slot)))
                            .is_some();
                    on_tick(&mut *store.write(), now_millis, has_proposal);

                    // Sample executor queue depths once per tick.
                    METRICS.get().map(|m| {
                        m.grandine_cpu_normal_executor_tasks_in_flight
                            .set(cpu_normal_executor.tasks() as i64);
                        m.grandine_cpu_snark_executor_tasks_in_flight
                            .set(cpu_snark_executor.tasks() as i64);
                        m.grandine_cpu_verify_executor_tasks_in_flight
                            .set(cpu_verify_executor.tasks() as i64);
                        m.grandine_cpu_aggregation_executor_tasks_in_flight
                            .set(cpu_aggregation_executor.tasks() as i64)
                    });

                    let (current_slot, current_interval) = {
                        let s = store.read();
                        (s.time / INTERVALS_PER_SLOT, s.time % INTERVALS_PER_SLOT)
                    };

                    if let Some(elapsed) = tick_elapsed {
                        info!(
                            slot = current_slot,
                            interval = current_interval,
                            duration_s = elapsed,
                            "tick"
                        );
                    }

                    if last_status_slot != Some(current_slot) {
                        let peers = peer_count.load(Ordering::Relaxed);
                        print_chain_status(&*store.read(), peers);
                        last_status_slot = Some(current_slot);

                        let head_slot = { let s = store.read(); s.blocks.get(&s.head).map(|b| b.slot.0).unwrap_or(0) };
                        let nf = *network_finalized_slot.lock();
                        evaluate_sync_state(&mut sync_state, peers, head_slot, nf);
                    }

                    // Aggregation results no longer drained here; a dedicated
                    // `select!` arm below wakes the chain task the moment the
                    // worker finishes, removing the up-to-800 ms poll lag that
                    // caused interval-3 `update_safe_target` to read an empty
                    // `latest_new_aggregated_payloads`.

                    // ── Aggregation catch-up / interval-2 guard ───────────────────────
                    // Trigger aggregation whenever we reach OR pass interval 2 for a
                    // new slot. This covers two cases:
                    //   1. Normal: on_tick lands exactly at interval 2 → trigger fires.
                    //   2. Catch-up: on_tick skips past interval 2 (e.g. lands at 3 or 4
                    //      after a long block-processing burst) → trigger still fires for
                    //      the current slot via an explicit catch-up.
                    // last_agg_slot prevents double-firing within the same slot.
                    // Only trigger if this node is the aggregator for this slot.
                    // Previously gated on `has_aggregator` (any-validator-service),
                    // which made every validator node deep-clone the Store every
                    // slot — pure waste on non-aggregators. The per-slot check via
                    // AggregationService::is_aggregator_for_slot routes through the
                    // ValidatorService AtomicBool flag, so admin-API runtime toggles
                    // are still honored.
                    if current_interval >= 2 && current_slot > last_agg_slot {
                        last_agg_slot = current_slot;
                        let is_agg = aggregator
                            .as_ref()
                            .map(|a| a.is_aggregator_for_slot(Slot(current_slot)))
                            .unwrap_or(false);
                        if is_agg {
                            METRICS.get().map(|m| {
                                m.lean_aggregation_snapshots_triggered_total.inc()
                            });
                            if let Some(ref agg) = aggregator {
                                agg.trigger(current_slot);
                            }
                            info!(slot = current_slot, "Aggregation phase - triggered");
                        } else {
                            METRICS.get().map(|m| {
                                m.lean_aggregator_skipped_total
                                    .with_label_values(&["not_aggregator"])
                                    .inc()
                            });
                        }
                    }

                    match current_interval {
                        0 | 1 | 2 => {} // interval-2 aggregation handled by guard above
                        3 => {
                            info!(slot = current_slot, tick = store.read().time, "Computing safe target");
                        }
                        4 => {
                            info!(slot = current_slot, tick = store.read().time, "Accepting new attestations");
                        }
                        _ => {}
                    }

                    if current_slot != last_logged_slot && current_slot % 10 == 0 {
                        debug!("(Okay)Store time updated : slot {}, pending blocks: {}",
                            current_slot,
                            block_cache.len()
                        );
                        last_logged_slot = current_slot;
                    }
                }
                _ = status_notify.notified() => {
                    let peers = peer_count.load(Ordering::Relaxed);
                    let head_slot = { let s = store.read(); s.blocks.get(&s.head).map(|b| b.slot.0).unwrap_or(0) };
                    let nf = *network_finalized_slot.lock();
                    evaluate_sync_state(&mut sync_state, peers, head_slot, nf);
                }
                // Phase 3 (apply) is placed ABOVE `chain_message_receiver.recv()` in the
                // biased select so completed verifies always drain before we accept new
                // chain messages. Without this priority, a backlog of incoming gossip
                // would starve apply: chain_message would always be ready, biased polling
                // would pick it every iteration, and verified blocks would never land in
                // store.blocks (observed live: depth 200+ growing, store_blocks_size frozen).
                result = verify_result_rx.recv() => {
                    let Some((block_root, signed_block, should_gossip, outcome)) = result else { break };
                    METRICS
                        .get()
                        .map(|m| m.grandine_verify_result_channel_depth.dec());
                    // RAII timer for Phase 3 apply wall-clock; records on Drop so
                    // all `continue` early-exits are captured automatically.
                    let _apply_timer = METRICS
                        .get()
                        .map(|m| m.lean_chain_task_apply_seconds.start_timer());

                    // Skip if another path already applied this block (e.g. cascade race).
                    if store.read().blocks.contains_key(&block_root) {
                        continue;
                    }

                    // Skip if parent state was pruned by finalization while verify ran.
                    // `apply_verified_block` retains finalized + buffer states only; if
                    // finalization advanced past this block's parent during the verify
                    // window, the post-state we just received is no longer applicable.
                    // Drop it; if the block becomes head-relevant it will be re-fetched
                    // via BlocksByRoot.
                    let parent_root = signed_block.block.parent_root;
                    if !store.read().states.contains_key(&parent_root) {
                        warn!(
                            block_root = %format!("0x{:x}", block_root),
                            "Parent state pruned during verify, dropping result"
                        );
                        continue;
                    }

                    let block_slot = signed_block.block.slot;

                    match outcome {
                        Ok(new_state) => {
                            let apply_result = apply_verified_block(
                                &mut *store.write(),
                                signed_block.clone(),
                                new_state,
                                block_root,
                            );

                            match apply_result {
                                Ok(()) => {
                                    info!("Block processed successfully");
                                    let _ = block_slot_tx.send(block_slot.0);

                                    {
                                        let exec = cpu_verify_executor.clone();
                                        let store_for_reagg = store.clone();
                                        let signed_block_for_reagg = signed_block.clone();
                                        let log_inv_rate = chain_log_inv_rate;
                                        tokio::spawn(async move {
                                            let job = exec.spawn(async move {
                                                fork_choice::reaggregate::run_in_executor(
                                                    store_for_reagg,
                                                    signed_block_for_reagg,
                                                    log_inv_rate,
                                                );
                                            });
                                            if let Err(e) = job.await {
                                                warn!("reaggregate executor failed: {e}");
                                            }
                                        });
                                    }

                                    {
                                        let s = store.read();
                                        let mut status = status_provider.write();
                                        status.finalized = s.latest_finalized.clone();
                                        status.head = Checkpoint {
                                            root: s.head,
                                            slot: s.blocks.get(&s.head).map(|b| b.slot).unwrap_or(Slot(0)),
                                        };
                                    }

                                    // Bug 1 invariant: rebroadcast only on Apply (apply_verified_block
                                    // is reached only when the dedup guard above missed, i.e. the
                                    // block is new to us). The original ChainMessage carried
                                    // should_gossip; cascade respawns will set it to false.
                                    if should_gossip {
                                        if let Err(e) = outbound_p2p_sender.send(
                                            OutboundP2pRequest::GossipBlock(signed_block.clone())
                                        ) {
                                            warn!("Failed to gossip block: {}", e);
                                        } else {
                                            info!(slot = block_slot.0, "Broadcasted block");
                                        }
                                    }

                                    let head_slot = { let s = store.read(); s.blocks.get(&s.head).map(|b| b.slot.0).unwrap_or(0) };
                                    let nf = *network_finalized_slot.lock();
                                    check_sync_complete(&mut sync_state, head_slot, block_cache.orphan_count(), nf);

                                    // Cascade: orphans waiting on this block can now verify.
                                    // Spawn each cached child against the just-applied state and
                                    // route the result back through `verify_result_tx`. The reply
                                    // re-enters this same arm, so grandchildren are picked up
                                    // automatically without going through `chain_message_sender`
                                    // (avoids burst pressure on the bounded chain channel).
                                    let cascade_children: Vec<(H256, SignedBlock)> = block_cache
                                        .get_children(&block_root)
                                        .into_iter()
                                        .map(|p| (p.root, p.block.clone()))
                                        .collect();

                                    if !cascade_children.is_empty() {
                                        if let Some(cascade_parent_state) =
                                            store.read().states.get(&block_root).cloned()
                                        {
                                            for (child_root, child_block) in cascade_children {
                                                let exec = cpu_verify_executor.clone();
                                                let result_tx = verify_result_tx.clone();
                                                let parent_state_for_child =
                                                    cascade_parent_state.clone();
                                                let child_for_verify = child_block.clone();
                                                METRICS.get().map(|m| {
                                                    m.grandine_verify_result_channel_depth.inc()
                                                });
                                                tokio::spawn(async move {
                                                    let child_for_send = child_for_verify.clone();
                                                    let job = exec.spawn(async move {
                                                        verify_and_transition(
                                                            parent_state_for_child,
                                                            child_for_verify,
                                                            true,
                                                        )
                                                    });
                                                    let outcome = job.await.unwrap_or_else(|e| {
                                                        Err(anyhow::anyhow!("executor: {e}"))
                                                    });
                                                    if result_tx
                                                        .send((
                                                            child_root,
                                                            child_for_send,
                                                            false, // cascade: never re-gossip
                                                            outcome,
                                                        ))
                                                        .await
                                                        .is_err()
                                                    {
                                                        METRICS.get().map(|m| {
                                                            m.grandine_verify_result_channel_depth
                                                                .dec()
                                                        });
                                                    }
                                                });
                                                block_cache.remove(&child_root);
                                            }
                                        }
                                    }

                                    METRICS
                                        .get()
                                        .map(|m| m.grandine_block_cache_size.set(block_cache.len() as i64));

                                    let missing: Vec<H256> = store.write().pending_fetch_roots.drain().collect();
                                    METRICS.get().map(|m| m.grandine_pending_fetch_roots.set(0));
                                    let local_head_slot = {
                                        let s = store.read();
                                        s.blocks.get(&s.head).map(|b| b.slot.0).unwrap_or(0)
                                    };
                                    dispatch_backfill(
                                        missing,
                                        local_head_slot,
                                        block_cache.orphan_count(),
                                        &outbound_p2p_sender,
                                    );
                                }
                                Err(e) => warn!(
                                    block_root = %format!("0x{:x}", block_root),
                                    "Problem applying verified block: {}", e
                                ),
                            }
                        }
                        Err(e) => warn!(
                            block_root = %format!("0x{:x}", block_root),
                            "Block verify failed: {}", e
                        ),
                    }
                }
                Some((agg_slot, maybe_agg)) = async {
                    aggregator.as_mut().unwrap().recv().await
                }, if aggregator.is_some() => {
                    if let Some((aggregations, consumed_data_roots)) = maybe_agg {
                        let mut to_publish = Vec::with_capacity(aggregations.len());
                        {
                            let mut s = store.write();
                            for aggregation in aggregations {
                                let data_root = aggregation.data.hash_tree_root();
                                s.latest_new_aggregated_payloads
                                    .entry(data_root)
                                    .or_default()
                                    .push(aggregation.proof.clone());
                                to_publish.push(aggregation);
                            }
                            s.gossip_signatures.retain(|key, _| {
                                !consumed_data_roots.contains(&key.data_root)
                            });
                            METRICS.get().map(|m| {
                                m.lean_latest_new_aggregated_payloads
                                    .set(s.latest_new_aggregated_payloads.len() as i64);
                            });
                        }
                        for aggregation in to_publish {
                            if let Err(e) = chain_outbound_sender.send(
                                OutboundP2pRequest::GossipAggregation(aggregation)
                            ) {
                                warn!("Failed to gossip aggregation: {}", e);
                            }
                        }
                        info!(slot = agg_slot, "Aggregation phase - broadcast aggregated attestations");
                    } else {
                        info!("Aggregation phase - no aggregation duty or no attestations");
                    }
                }
                message = chain_message_receiver.recv() => {
                    let Some(message) = message else { break };
                    METRICS.get().map(|m| m.grandine_chain_message_channel_depth.dec());
                    // RAII timer: HistogramTimer records on Drop, so all `continue`
                    // exits inside the match below are captured automatically.
                    let _chain_message_timer = METRICS
                        .get()
                        .map(|m| m.lean_chain_task_chain_message_seconds.start_timer());
                    match message {
                        ChainMessage::ProcessBlock {
                            signed_block,
                            is_trusted,
                            should_gossip,
                            cached_post_state,
                        } => {
                            if should_gossip && !is_trusted && !sync_state.accepts_gossip() {
                                debug!(
                                    state = ?sync_state,
                                    slot = signed_block.block.slot.0,
                                    "Dropping gossip block: sync state does not accept gossip"
                                );
                                continue;
                            }

                            let block_slot = signed_block.block.slot;
                            let proposer = signed_block.block.proposer_index;
                            let block_root = signed_block.block.hash_tree_root();
                            let parent_root = signed_block.block.parent_root;

                            if store.read().blocks.contains_key(&block_root) {
                                continue;
                            }

                            info!(
                                slot = block_slot.0,
                                block_root = %format!("0x{:x}", block_root),
                                parent_root = %format!("0x{:x}", parent_root),
                                "Processing block built by Validator {}",
                                proposer
                            );

                            let now_millis = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                            on_tick(&mut *store.write(), now_millis, false);

                            // Store block immediately so we can serve it to peers via
                            // BlocksByRoot even if it can't be processed yet (e.g. parent
                            // missing).  This prevents STREAM_CLOSED errors when a peer
                            // requests a block we received but haven't incorporated yet.
                            {
                                let mut provider = signed_block_provider.write();
                                provider.insert(block_root, signed_block.clone());
                                // Hard cap: evict lowest-slot blocks if still over limit.
                                if provider.len() > MAX_BLOCK_CACHE_SIZE {
                                    let to_remove = provider.len() - MAX_BLOCK_CACHE_SIZE;
                                    let mut slots: Vec<(H256, u64)> = provider
                                        .iter()
                                        .map(|(root, b)| (*root, b.block.slot.0))
                                        .collect();
                                    slots.sort_by_key(|(_, slot)| *slot);
                                    for (root, _) in slots.into_iter().take(to_remove) {
                                        provider.remove(&root);
                                    }
                                }
                            }

                            // Snapshot parent state for the executor. If absent, treat as
                            // orphan and re-queue. Genesis (parent_root.is_zero()) is loaded
                            // at startup, so a None here for non-zero parents means the
                            // parent block hasn't been processed yet.
                            let parent_state = {
                                let s = store.read();
                                s.states.get(&parent_root).cloned()
                            };

                            let Some(parent_state) = parent_state else {
                                block_cache.add(
                                    signed_block.clone(),
                                    block_root,
                                    parent_root,
                                    block_slot,
                                    None,
                                    0,
                                );
                                block_cache.mark_orphan(block_root);
                                METRICS.get().map(|m| m.grandine_block_cache_size.set(block_cache.len() as i64));

                                store.write().pending_fetch_roots.insert(parent_root);

                                warn!(
                                    child_slot = block_slot.0,
                                    child_block_root = %format!("0x{:x}", block_root),
                                    missing_parent_root = %format!("0x{:x}", parent_root),
                                    "Block cached (proactive) - parent not found, requesting via BlocksByRoot"
                                );

                                let missing: Vec<H256> = store.write().pending_fetch_roots.drain().collect();
                                METRICS.get().map(|m| m.grandine_pending_fetch_roots.set(0));
                                let head_slot = { let s = store.read(); s.blocks.get(&s.head).map(|b| b.slot.0).unwrap_or(0) };
                                dispatch_backfill(
                                    missing,
                                    head_slot,
                                    block_cache.orphan_count(),
                                    &outbound_p2p_sender,
                                );

                                let nf = *network_finalized_slot.lock();
                                check_sync_trigger(&mut sync_state, head_slot, nf);
                                check_sync_complete(&mut sync_state, head_slot, block_cache.orphan_count(), nf);

                                continue;
                            };

                            // Phase 1: ship verify+state_transition to the cpu_normal executor.
                            // The chain task returns to the select! loop immediately and processes
                            // the verified outcome later via verify_result_rx (Phase 3).
                            // No store mutation happens here; gossip rebroadcast and post-apply
                            // bookkeeping are deferred to Phase 3 once we know the block applied.
                            // Self-built short-circuit: when this is our own freshly-produced block
                            // (`is_trusted = true` + cached post-state), skip the redundant STF —
                            // leanSpec's `build_block` already returned the post-state, no need to
                            // recompute it. Mirrors zeam's planned fix per their devnet5 chat.
                            let exec = cpu_verify_executor.clone();
                            let result_tx = verify_result_tx.clone();
                            let signed_block_for_verify = signed_block.clone();
                            let verify_signatures = !is_trusted;
                            METRICS
                                .get()
                                .map(|m| m.grandine_verify_result_channel_depth.inc());
                            tokio::spawn(async move {
                                let signed_block_for_send = signed_block_for_verify.clone();
                                let outcome = if is_trusted && cached_post_state.is_some() {
                                    Ok(cached_post_state.unwrap())
                                } else {
                                    let job = exec.spawn(async move {
                                        verify_and_transition(parent_state, signed_block_for_verify, verify_signatures)
                                    });
                                    job.await.unwrap_or_else(|e| {
                                        Err(anyhow::anyhow!("executor: {e}"))
                                    })
                                };
                                if result_tx
                                    .send((block_root, signed_block_for_send, should_gossip, outcome))
                                    .await
                                    .is_err()
                                {
                                    // Receiver gone (chain task exited): roll back the inc above
                                    // since this entry will never be drained.
                                    METRICS
                                        .get()
                                        .map(|m| m.grandine_verify_result_channel_depth.dec());
                                }
                            });
                        }
                        ChainMessage::ProcessAttestation {
                            signed_attestation,
                            is_trusted,
                            should_gossip,
                        } => {
                            if should_gossip && !is_trusted && !sync_state.accepts_gossip() {
                                debug!(
                                    state = ?sync_state,
                                    slot = signed_attestation.message.slot.0,
                                    "Dropping gossip attestation: sync state does not accept gossip"
                                );
                                continue;
                            }

                            let att_slot = signed_attestation.message.slot.0;
                            let source_slot = signed_attestation.message.source.slot.0;
                            let target_slot = signed_attestation.message.target.slot.0;
                            let validator_id = signed_attestation.validator_id;

                            info!(
                                slot = att_slot,
                                source_slot = source_slot,
                                target_slot = target_slot,
                                "Processing attestation by Validator {}",
                                validator_id
                            );

                            let result = if is_trusted {
                                on_attestation(&mut *store.write(), signed_attestation.clone(), false)
                            } else {
                                on_gossip_attestation(&mut *store.write(), signed_attestation.clone())
                            };
                            match result {
                                Ok(()) => {
                                    if should_gossip {
                                        let subnet_id = compute_subnet_id(validator_id, attestation_committee_count);
                                        if let Err(e) = outbound_p2p_sender.send(
                                            OutboundP2pRequest::GossipAttestation(signed_attestation, subnet_id)
                                        ) {
                                            warn!("Failed to gossip attestation: {}", e);
                                        } else {
                                            info!(slot = att_slot, subnet_id = subnet_id, "Broadcasted attestation to subnet");
                                        }
                                    }
                                }
                                Err(e) => warn!("Error processing attestation: {}", e),
                            }

                            let missing: Vec<H256> = store.write().pending_fetch_roots.drain().collect();
                            METRICS.get().map(|m| m.grandine_pending_fetch_roots.set(0));
                            let local_head_slot = {
                                let s = store.read();
                                s.blocks.get(&s.head).map(|b| b.slot.0).unwrap_or(0)
                            };
                            dispatch_backfill(
                                missing,
                                local_head_slot,
                                block_cache.orphan_count(),
                                &outbound_p2p_sender,
                            );
                        }
                        ChainMessage::ProcessAggregation {
                            signed_aggregated_attestation,
                            is_trusted,
                            should_gossip,
                        } => {
                            if !is_trusted && !sync_state.accepts_gossip() {
                                debug!(
                                    state = ?sync_state,
                                    slot = signed_aggregated_attestation.data.slot.0,
                                    "Dropping gossip aggregation: sync state does not accept gossip"
                                );
                                continue;
                            }

                            let agg_slot = signed_aggregated_attestation.data.slot.0;
                            let validator_count = signed_aggregated_attestation
                                .proof
                                .participants
                                .0
                                .iter()
                                .filter(|b| **b)
                                .count();

                            {
                                let exec = cpu_verify_executor.clone();
                                let store_for_verify = store.clone();
                                let signed_for_verify = signed_aggregated_attestation.clone();
                                tokio::spawn(async move {
                                    let job = exec.spawn(async move {
                                        on_aggregated_attestation_async(store_for_verify, signed_for_verify)
                                    });
                                    match job.await.unwrap_or_else(|e| Err(anyhow::anyhow!("executor: {e}"))) {
                                        Ok(_) => info!(
                                            slot = agg_slot,
                                            validators = validator_count,
                                            "Processed aggregated attestation for safe target"
                                        ),
                                        Err(e) => warn!(
                                            slot = agg_slot,
                                            error = %e,
                                            "Failed to process aggregated attestation"
                                        ),
                                    }
                                });
                            }

                            let missing: Vec<H256> = store.write().pending_fetch_roots.drain().collect();
                            METRICS.get().map(|m| m.grandine_pending_fetch_roots.set(0));
                            let local_head_slot = {
                                let s = store.read();
                                s.blocks.get(&s.head).map(|b| b.slot.0).unwrap_or(0)
                            };
                            dispatch_backfill(
                                missing,
                                local_head_slot,
                                block_cache.orphan_count(),
                                &outbound_p2p_sender,
                            );

                            // Gossip the aggregation if needed
                            if should_gossip {
                                if let Err(e) = outbound_p2p_sender.send(
                                    OutboundP2pRequest::GossipAggregation(signed_aggregated_attestation)
                                ) {
                                    warn!("Failed to gossip aggregation: {}", e);
                                } else {
                                    info!(slot = agg_slot, "Broadcasted aggregation");
                                }
                            }
                        }
                    }
                }
                v_message = validator_chain_receiver.recv() => {
                    let Some(v_message) = v_message else { break };
                    METRICS.get().map(|m| m.grandine_validator_chain_message_channel_depth.dec());
                    match v_message {
                        ValidatorChainMessage::ProduceBlock { slot, proposer_index, sender } => {
                            let block_build_start = Instant::now();
                            let prepare_result = {
                                let mut w = store.write();
                                prepare_block_production(&mut *w, slot, proposer_index, chain_log_inv_rate)
                            };

                            match prepare_result {
                                Err(e) => {
                                    METRICS.get().map(|m| m.lean_block_building_failures_total.inc());
                                    let _ = sender.send(Err(e));
                                }
                                Ok(inputs) => {
                                    let agg_payload_count = inputs.aggregated_payloads.len();
                                    let validators = inputs.head_state.validators.clone();
                                    let exec = cpu_normal_executor.clone();
                                    let exec_start = Instant::now();
                                    tokio::spawn(async move {
                                        let job = exec.spawn(async move {
                                            execute_block_production(inputs)
                                                .map(|(_, block, post_state, sigs)| (block, post_state, sigs))
                                        });
                                        let result = job
                                            .await
                                            .unwrap_or_else(|e| Err(anyhow::anyhow!("executor: {e}")))
                                            .map(|(block, post_state, sigs)| (block, sigs, validators, post_state));

                                        let exec_elapsed = exec_start.elapsed();
                                        let total_elapsed = block_build_start.elapsed();
                                        match &result {
                                            Ok((block, _sigs, _validators, post_state)) => {
                                                METRICS.get().map(|m| {
                                                    m.lean_block_building_success_total.inc();
                                                    m.lean_block_building_time_seconds
                                                        .observe(total_elapsed.as_secs_f64());
                                                    m.lean_block_building_payload_aggregation_time_seconds
                                                        .observe(exec_elapsed.as_secs_f64());
                                                    m.lean_block_aggregated_payloads
                                                        .observe(agg_payload_count as f64);
                                                });
                                                info!(
                                                    block_slot = block.slot.0,
                                                    state_slot = post_state.slot.0,
                                                    state_root = %post_state.hash_tree_root(),
                                                    slot_h = %post_state.slot.hash_tree_root(),
                                                    lbh = %post_state.latest_block_header.hash_tree_root(),
                                                    lj = %post_state.latest_justified.hash_tree_root(),
                                                    lf = %post_state.latest_finalized.hash_tree_root(),
                                                    hbh = %post_state.historical_block_hashes.hash_tree_root(),
                                                    js = %post_state.justified_slots.hash_tree_root(),
                                                    v = %post_state.validators.hash_tree_root(),
                                                    jr = %post_state.justifications_roots.hash_tree_root(),
                                                    jv = %post_state.justifications_validators.hash_tree_root(),
                                                    "proposer post-state per-field"
                                                );
                                            }
                                            Err(_) => {
                                                METRICS.get().map(|m| m.lean_block_building_failures_total.inc());
                                            }
                                        }
                                        let _ = sender.send(result);
                                    });
                                }
                            }
                        }
                        ValidatorChainMessage::BuildAttestationData { slot, sender } => {
                            let store_read = store.read();
                            if !store_read.justified_ever_updated {
                                warn!(
                                    slot = slot.0,
                                    "Skipping attestation: justified checkpoint has not yet \
                                     advanced from anchor — node is not ready to attest"
                                );
                                let _ = sender.send(Err(anyhow::anyhow!(
                                    "not ready: justified checkpoint has not advanced from anchor value"
                                )));
                            } else {
                                let result = store_read.produce_attestation_data(slot);
                                let _ = sender.send(result);
                            }
                        }
                    }
                }
            }
        }
    });

    let validator_handle = task::spawn(async move {
        let Some(vs) = vs_for_validator else {
            return;
        };
        let mut block_slot_rx = block_slot_rx;

        let mut v_tick_interval = interval_at(
            Instant::now() + genesis_tick_delay,
            Duration::from_millis(MILLIS_PER_INTERVAL),
        );
        v_tick_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_proposal_slot: Option<u64> = None;
        let mut last_attestation_slot: Option<u64> = None;
        let mut propose_handle: Option<tokio::task::JoinHandle<()>> = None;

        loop {
            v_tick_interval.tick().await;

            let now_millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let elapsed = now_millis.saturating_sub(genesis_millis);
            let tick_time = elapsed / MILLIS_PER_INTERVAL;
            let current_slot = tick_time / INTERVALS_PER_SLOT;
            let current_interval = tick_time % INTERVALS_PER_SLOT;

            match current_interval {
                0 => {
                    if last_proposal_slot != Some(current_slot) {
                        if current_slot > 0 {
                            if let Some(proposer_idx) = vs.get_proposer_for_slot(Slot(current_slot))
                            {
                                if let Some(prev) = propose_handle.take() {
                                    if !prev.is_finished() {
                                        prev.abort();
                                        info!(
                                            slot = current_slot,
                                            "Validator task: aborting prior in-flight propose"
                                        );
                                    }
                                }

                                info!(
                                    slot = current_slot,
                                    proposer = proposer_idx,
                                    "Validator task: proposing block"
                                );

                                let (tx, rx) = oneshot::channel();
                                let send_result = validator_chain_sender.send(
                                    ValidatorChainMessage::ProduceBlock {
                                        slot: Slot(current_slot),
                                        proposer_index: proposer_idx,
                                        sender: tx,
                                    },
                                );
                                if send_result.is_ok() {
                                    METRICS.get().map(|m| {
                                        m.grandine_validator_chain_message_channel_depth.inc()
                                    });
                                }
                                if send_result.is_err() {
                                    warn!("Validator task: chain channel closed, stopping");
                                    break;
                                }

                                let vs_for_spawn = vs.clone();
                                let chain_sender_for_spawn = chain_msg_sender_for_validator.clone();
                                let log_inv_rate = chain_log_inv_rate;
                                let propose_slot = current_slot;
                                let genesis_millis_for_spawn = genesis_millis;

                                propose_handle = Some(tokio::spawn(async move {
                                    let (block, signatures, validators, cached_post_state) =
                                        match rx.await {
                                            Ok(Ok(tuple)) => tuple,
                                            Ok(Err(e)) => {
                                                warn!(slot = propose_slot, error = %e, "Validator task: chain failed to produce block");
                                                return;
                                            }
                                            Err(_) => {
                                                warn!(
                                                    slot = propose_slot,
                                                    "Validator task: no response to ProduceBlock"
                                                );
                                                return;
                                            }
                                        };

                                    let now_millis = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64;
                                    let wall_slot = now_millis
                                        .saturating_sub(genesis_millis_for_spawn)
                                        / MILLIS_PER_INTERVAL
                                        / INTERVALS_PER_SLOT;
                                    if wall_slot > propose_slot {
                                        warn!(
                                            slot = propose_slot,
                                            wall_slot,
                                            lag_slots = wall_slot - propose_slot,
                                            "Late propose — publishing anyway",
                                        );
                                    }

                                    match vs_for_spawn
                                        .sign_block_with_data(
                                            block,
                                            proposer_idx,
                                            signatures,
                                            validators,
                                            log_inv_rate,
                                        )
                                        .await
                                    {
                                        Ok(signed_block) => {
                                            let block_root = signed_block.block.hash_tree_root();
                                            info!(
                                                slot = propose_slot,
                                                block_root = %format!("0x{:x}", block_root),
                                                "Validator task: block signed, sending to chain"
                                            );
                                            let send_result = chain_sender_for_spawn
                                                .send(ChainMessage::ProcessBlock {
                                                    signed_block,
                                                    is_trusted: true,
                                                    should_gossip: true,
                                                    cached_post_state: Some(cached_post_state),
                                                })
                                                .await;
                                            if send_result.is_ok() {
                                                METRICS.get().map(|m| {
                                                    m.grandine_chain_message_channel_depth.inc()
                                                });
                                            }
                                            if send_result.is_err() {
                                                warn!(
                                                    slot = propose_slot,
                                                    "Validator task: chain message channel closed"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            warn!(slot = propose_slot, error = %e, "Validator task: failed to sign block")
                                        }
                                    }
                                }));
                            }
                        }
                        last_proposal_slot = Some(current_slot);
                    }
                }
                1 => {
                    if last_attestation_slot != Some(current_slot) {
                        // Wait up to 400ms for the current slot's block to arrive before
                        // computing the attestation target. Mirrors leanSpec validator/service.py:323-336.
                        if tokio::time::timeout(
                            Duration::from_millis(400),
                            block_slot_rx.wait_for(|s| *s >= current_slot),
                        )
                        .await
                        .is_ok()
                        {
                            info!(
                                slot = current_slot,
                                "Block arrived, proceeding with attestation"
                            );
                        } else {
                            info!(
                                slot = current_slot,
                                "Block wait timed out, attesting with current head"
                            );
                        }

                        let (tx, rx) = oneshot::channel();
                        let send_result = validator_chain_sender.send(
                            ValidatorChainMessage::BuildAttestationData {
                                slot: Slot(current_slot),
                                sender: tx,
                            },
                        );
                        if send_result.is_ok() {
                            METRICS
                                .get()
                                .map(|m| m.grandine_validator_chain_message_channel_depth.inc());
                        }
                        if send_result.is_err() {
                            warn!("Validator task: chain channel closed, stopping");
                            break;
                        }

                        match rx.await {
                            Ok(Ok(attestation_data)) => {
                                let proposer_index = if vs.num_validators > 0 {
                                    current_slot % vs.num_validators
                                } else {
                                    u64::MAX
                                };
                                let attestations = vs
                                    .create_attestations_from_data(
                                        Slot(current_slot),
                                        attestation_data,
                                    )
                                    .await;
                                for signed_att in attestations {
                                    if signed_att.validator_id == proposer_index {
                                        continue;
                                    }
                                    let validator_id = signed_att.validator_id;
                                    let subnet_id = compute_subnet_id(
                                        validator_id,
                                        attestation_committee_count,
                                    );
                                    info!(
                                        slot = current_slot,
                                        validator = validator_id,
                                        subnet_id = subnet_id,
                                        "Validator task: broadcasting attestation"
                                    );
                                    let send_result = chain_msg_sender_for_validator
                                        .send(ChainMessage::ProcessAttestation {
                                            signed_attestation: signed_att,
                                            is_trusted: true,
                                            should_gossip: true,
                                        })
                                        .await;
                                    if send_result.is_ok() {
                                        METRICS
                                            .get()
                                            .map(|m| m.grandine_chain_message_channel_depth.inc());
                                    }
                                    if send_result.is_err() {
                                        warn!(
                                            "Validator task: chain message channel closed, stopping"
                                        );
                                        return;
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                warn!(slot = current_slot, error = %e, "Validator task: chain failed to build attestation data")
                            }
                            Err(_) => warn!(
                                slot = current_slot,
                                "Validator task: no response to BuildAttestationData"
                            ),
                        }
                        last_attestation_slot = Some(current_slot);
                    }
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = network_handle => {
            info!("Network service finished.");
        }
        _ = chain_handle => {
            info!("Chain service finished.");
        }
        _ = validator_handle => {
            info!("Validator task finished.");
        }
    }

    info!("Main async task exiting...");

    Ok(())
}
