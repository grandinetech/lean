use anyhow::{Context as _, Result};
use clap::Parser;
use containers::{
    Attestation, AttestationData, Block, BlockBody, BlockHeader, BlockSignatures,
    BlockWithAttestation, Checkpoint, Config, SignedBlockWithAttestation, Slot, State, Status,
    Validator,
};
use ethereum_types::H256;
use features::Feature;
use fork_choice::{
    handlers::{on_aggregated_attestation, on_attestation, on_block, on_tick},
    store::{INTERVALS_PER_SLOT, Store, get_forkchoice_store},
};
use http_api::HttpServerConfig;
use libp2p_identity::Keypair;
use metrics::{METRICS, Metrics, MetricsServerConfig};
use networking::gossipsub::config::GossipsubConfig;
use networking::gossipsub::topic::{compute_subnet_id, get_subscription_topics};
use networking::network::{NetworkService, NetworkServiceConfig};
use networking::types::{ChainMessage, OutboundP2pRequest, SignedBlockProvider, StatusProvider};
use parking_lot::RwLock;
use ssz::{PersistentList, SszHash, SszReadDefault as _};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io::IsTerminal, net::IpAddr};
use tokio::{
    sync::mpsc,
    task,
    time::{Duration, interval},
};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, warn};
use validator::{ValidatorConfig, ValidatorService};
use xmss::{PublicKey, Signature};

fn load_node_key(path: &str) -> Result<Keypair, Box<dyn std::error::Error>> {
    let hex_str = std::fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(&hex_str)?;
    let secret = libp2p_identity::secp256k1::SecretKey::try_from_bytes(bytes)?;
    let keypair = libp2p_identity::secp256k1::Keypair::from(secret);
    Ok(Keypair::from(keypair))
}

async fn download_checkpoint_state(url: &str) -> Result<State> {
    info!("Downloading checkpoint state from: {}", url);

    let client = reqwest::Client::new();
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
    //  Verify genesis time matches
    anyhow::ensure!(
        state.config.genesis_time == genesis_state.config.genesis_time,
        "Genesis time mismatch: checkpoint has {}, expected {}. Wrong network?",
        state.config.genesis_time,
        genesis_state.config.genesis_time
    );

    //  Verify validator count matches
    let state_validator_count = state.validators.len_u64();
    let expected_validator_count = genesis_state.validators.len_u64();

    anyhow::ensure!(
        state_validator_count == expected_validator_count,
        "Validator count mismatch: checkpoint has {}, genesis expects {}. Wrong network?",
        state_validator_count,
        expected_validator_count
    );

    //  Verify state has validators
    anyhow::ensure!(
        state_validator_count > 0,
        "Invalid checkpoint state: no validators in registry"
    );

    //  Verify each validator pubkey matches genesis
    for i in 0..state_validator_count {
        let state_pubkey = &state.validators.get(i).expect("validator exists").pubkey;
        let genesis_pubkey = &genesis_state
            .validators
            .get(i)
            .expect("validator exists")
            .pubkey;

        anyhow::ensure!(
            state_pubkey == genesis_pubkey,
            "Validator pubkey mismatch at index {}: checkpoint has different validator set. Wrong network?",
            i
        );
    }

    info!(
        "Checkpoint state verified: genesis_time={}, validators={}",
        state.config.genesis_time, state_validator_count
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

    /// Override attestation committee count (devnet-3)
    /// When set, uses this value instead of the hardcoded default
    #[arg(long = "attestation-committee-count")]
    attestation_committee_count: Option<u64>,

    #[arg(long)]
    checkpoint_sync_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

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

    // Record aggregator and network metrics on startup
    METRICS.get().map(|metrics| {
        metrics
            .lean_is_aggregator
            .set(if args.is_aggregator { 1 } else { 0 });
        // ATTESTATION_SUBNET_COUNT is 1 in current implementation
        metrics.lean_attestation_committee_count.set(1);
    });

    let (outbound_p2p_sender, outbound_p2p_receiver) =
        mpsc::unbounded_channel::<OutboundP2pRequest>();
    let (chain_message_sender, mut chain_message_receiver) =
        mpsc::unbounded_channel::<ChainMessage>();

    let (genesis_time, validators) = if let Some(genesis_path) = &args.genesis {
        let genesis_config = containers::GenesisConfig::load_from_file(genesis_path)
            .expect("Failed to load genesis config");

        let validators: Vec<Validator> = genesis_config
            .genesis_validators
            .iter()
            .enumerate()
            .map(|(i, v_str)| {
                let pubkey: PublicKey = v_str.parse().expect("Invalid genesis validator pubkey");
                Validator {
                    pubkey,
                    index: i as u64,
                }
            })
            .collect();

        (genesis_config.genesis_time, validators)
    } else {
        let num_validators = 3;
        let validators = (0..num_validators)
            .map(|i| Validator {
                pubkey: PublicKey::default(),
                index: i as u64,
            })
            .collect();
        (1763757427, validators)
    };

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

    let genesis_proposer_attestation = Attestation {
        validator_id: 0,
        data: AttestationData {
            slot: Slot(0),
            head: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            target: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            source: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
        },
    };
    let genesis_signed_block = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: genesis_block,
            proposer_attestation: genesis_proposer_attestation,
        },
        signature: BlockSignatures {
            attestation_signatures: PersistentList::default(),
            proposer_signature: Signature::default(),
        },
    };

    let config = Config { genesis_time };

    let (anchor_state, anchor_block) = if let Some(ref url) = args.checkpoint_sync_url {
        info!("Checkpoint sync enabled, downloading from: {}", url);

        match download_checkpoint_state(url).await {
            Ok(checkpoint_state) => {
                if let Err(e) = verify_checkpoint_state(&checkpoint_state, &genesis_state) {
                    error!("Checkpoint verification failed: {}. Refusing to start.", e);
                    return Err(e);
                }

                // Compute state root for the checkpoint state (like zeam's genStateBlockHeader)
                let checkpoint_state_root = checkpoint_state.hash_tree_root();

                // Reconstruct block header from state's latest_block_header with correct state_root
                // The state's latest_block_header already contains the correct body_root from the original block
                let checkpoint_block_header = BlockHeader {
                    slot: checkpoint_state.latest_block_header.slot,
                    proposer_index: checkpoint_state.latest_block_header.proposer_index,
                    parent_root: checkpoint_state.latest_block_header.parent_root,
                    state_root: checkpoint_state_root,
                    body_root: checkpoint_state.latest_block_header.body_root,
                };

                // Compute block root from the BlockHeader (NOT from a synthetic Block with empty body)
                let checkpoint_block_root = checkpoint_block_header.hash_tree_root();

                // Create a Block structure for the SignedBlockWithAttestation
                // Note: body is synthetic but block_root is computed correctly from header above
                let checkpoint_block = Block {
                    slot: checkpoint_block_header.slot,
                    proposer_index: checkpoint_block_header.proposer_index,
                    parent_root: checkpoint_block_header.parent_root,
                    state_root: checkpoint_state_root,
                    body: BlockBody {
                        attestations: Default::default(),
                    },
                };

                let checkpoint_proposer_attestation = Attestation {
                    validator_id: checkpoint_state.latest_block_header.proposer_index,
                    data: AttestationData {
                        slot: checkpoint_state.slot,
                        head: Checkpoint {
                            root: checkpoint_block_root,
                            slot: checkpoint_state.slot,
                        },
                        target: checkpoint_state.latest_finalized.clone(),
                        source: checkpoint_state.latest_justified.clone(),
                    },
                };

                let checkpoint_signed_block = SignedBlockWithAttestation {
                    message: BlockWithAttestation {
                        block: checkpoint_block,
                        proposer_attestation: checkpoint_proposer_attestation,
                    },
                    signature: BlockSignatures {
                        attestation_signatures: PersistentList::default(),
                        proposer_signature: Signature::default(),
                    },
                };

                info!(
                    slot = checkpoint_state.slot.0,
                    finalized = checkpoint_state.latest_finalized.slot.0,
                    justified = checkpoint_state.latest_justified.slot.0,
                    block_root = %format!("0x{:x}", checkpoint_block_root),
                    state_root = %format!("0x{:x}", checkpoint_state_root),
                    "Checkpoint sync successful"
                );

                (checkpoint_state, checkpoint_signed_block)
            }
            Err(e) => {
                warn!("Checkpoint sync failed: {}. Falling back to genesis.", e);
                (genesis_state.clone(), genesis_signed_block)
            }
        }
    } else {
        (genesis_state.clone(), genesis_signed_block)
    };

    // Clone anchor block for seeding the shared block provider later
    let anchor_block_for_provider = anchor_block.clone();
    // Compute block root from BlockHeader (NOT from Block with potentially empty body)
    // Must match the computation in get_forkchoice_store
    let anchor_block_header = BlockHeader {
        slot: anchor_state.latest_block_header.slot,
        proposer_index: anchor_state.latest_block_header.proposer_index,
        parent_root: anchor_state.latest_block_header.parent_root,
        state_root: anchor_state.hash_tree_root(),
        body_root: anchor_state.latest_block_header.body_root,
    };
    let anchor_block_root = anchor_block_header.hash_tree_root();

    let store = Arc::new(RwLock::new(get_forkchoice_store(
        anchor_state.clone(),
        anchor_block,
        config,
    )));

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

    // Extract first validator ID for subnet subscription and metrics
    let first_validator_id: Option<u64> = validator_service
        .as_ref()
        .and_then(|service| service.config.validator_indices.first().copied());

    // Record validator subnet metric if validator is configured
    if let Some(validator_id) = first_validator_id {
        let subnet_id = compute_subnet_id(validator_id);
        METRICS.get().map(|metrics| {
            metrics
                .lean_attestation_committee_subnet
                .set(subnet_id as i64);
        });
    }

    let fork = "devnet0".to_string();
    // Subscribe to topics based on validator role:
    // - Aggregators: all attestation subnets
    // - Non-aggregator validators: only their own subnet
    // - Non-validators: all subnets for general sync
    let gossipsub_topics = get_subscription_topics(fork, first_validator_id, args.is_aggregator);
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

    // Create shared block provider for BlocksByRoot requests (checkpoint sync backfill)
    // Seed with anchor block so we can serve it to peers doing checkpoint sync
    let mut initial_blocks = HashMap::new();
    initial_blocks.insert(anchor_block_root, anchor_block_for_provider.clone());

    let signed_block_provider: SignedBlockProvider = Arc::new(RwLock::new(initial_blocks));
    let signed_block_provider_for_network = signed_block_provider.clone();

    let initial_status = {
        let s = store.read();
        Status::new(
            s.latest_finalized.clone(),
            Checkpoint {
                root: s.head,
                slot: s.blocks.get(&s.head).map(|b| b.slot).unwrap_or(Slot(0)),
            },
        )
    };
    let status_provider: StatusProvider = Arc::new(RwLock::new(initial_status));
    let status_provider_for_network = status_provider.clone();

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
        )
        .await
        .expect("Failed to create network service")
    };

    let network_handle = task::spawn(async move {
        if let Err(err) = network_service.start().await {
            panic!("Network service exited with error: {err}");
        }
    });

    let chain_outbound_sender = outbound_p2p_sender.clone();

    let http_store = store.clone();
    task::spawn(async move {
        if let Err(err) = http_api::run_server(args.http_config, http_store).await {
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

    let chain_handle = task::spawn(async move {
        let mut tick_interval = interval(Duration::from_millis(800));
        let mut last_logged_slot = 0u64;
        let mut last_status_slot: Option<u64> = None;
        let mut last_proposal_slot: Option<u64> = None;
        let mut last_attestation_slot: Option<u64> = None;

        let peer_count = peer_count_for_status;

        loop {
            tokio::select! {
                _ = tick_interval.tick() => {
                    let now_millis = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    on_tick(&mut *store.write(), now_millis, false);

                    let (current_slot, current_interval) = {
                        let s = store.read();
                        (s.time / INTERVALS_PER_SLOT, s.time % INTERVALS_PER_SLOT)
                    };

                    if last_status_slot != Some(current_slot) {
                        let peers = peer_count.load(Ordering::Relaxed);
                        print_chain_status(&*store.read(), peers);
                        last_status_slot = Some(current_slot);
                    }

                    match current_interval {
                        0 => {
                            if let Some(ref vs) = validator_service {
                                if last_proposal_slot != Some(current_slot) {
                                    if let Some(proposer_idx) = vs.get_proposer_for_slot(Slot(current_slot)) {
                                        info!(
                                            slot = current_slot,
                                            proposer = proposer_idx,
                                            "Our turn to propose block!"
                                        );

                                        let result = {vs.build_block_proposal(&mut *store.write(), Slot(current_slot), proposer_idx)};
                                        match result {
                                            Ok(signed_block) => {
                                                let block_root = signed_block.message.block.hash_tree_root();
                                                info!(
                                                    slot = current_slot,
                                                    block_root = %format!("0x{:x}", block_root),
                                                    "Built block, processing and gossiping"
                                                );

                                                let now_millis = SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap()
                                                    .as_millis() as u64;
                                                on_tick(&mut *store.write(), now_millis, false);

                                                match on_block(&mut *store.write(), signed_block.clone()) {
                                                    Ok(()) => {
                                                        info!("Own block processed successfully");
                                                        // GOSSIP TO NETWORK
                                                        if let Err(e) = chain_outbound_sender.send(
                                                            OutboundP2pRequest::GossipBlockWithAttestation(signed_block)
                                                        ) {
                                                            warn!("Failed to gossip our block: {}", e);
                                                        }
                                                    }
                                                    Err(e) => warn!("Failed to process our own block: {}", e),
                                                }
                                            }
                                            Err(e) => warn!("Failed to build block proposal: {}", e),
                                        }
                                        last_proposal_slot = Some(current_slot);
                                    }
                                }
                            }
                        }
                        1 => {
                            if let Some(ref vs) = validator_service {
                                if last_attestation_slot != Some(current_slot) {
                                    let attestations = vs.create_attestations(&*store.read(), Slot(current_slot));
                                    for signed_att in attestations {
                                        let validator_id = signed_att.validator_id;
                                        let subnet_id = compute_subnet_id(validator_id);
                                        info!(
                                            slot = current_slot,
                                            validator = validator_id,
                                            subnet_id = subnet_id,
                                            "Broadcasting attestation to subnet"
                                        );

                                        match on_attestation(&mut *store.write(), signed_att.clone(), false) {
                                            Ok(()) => {
                                                if let Err(e) = chain_outbound_sender.send(
                                                    OutboundP2pRequest::GossipAttestation(signed_att, subnet_id)
                                                ) {
                                                    warn!("Failed to gossip attestation: {}", e);
                                                }
                                            }
                                            Err(e) => warn!("Error processing own attestation: {}", e),
                                        }
                                    }
                                    last_attestation_slot = Some(current_slot);
                                }
                            }
                        }
                        2 => {
                            if let Some(ref vs) = validator_service {
                                if let Some(aggregations) = vs.maybe_aggregate(&*store.read(), Slot(current_slot)) {
                                    for aggregation in aggregations {
                                        if let Err(e) = chain_outbound_sender.send(
                                            OutboundP2pRequest::GossipAggregation(aggregation)
                                        ) {
                                            warn!("Failed to gossip aggregation: {}", e);
                                        }
                                    }
                                    info!(slot = current_slot, tick = store.read().time, "Aggregation phase - broadcast aggregated attestations");
                                } else {
                                    info!(slot = current_slot, tick = store.read().time, "Aggregation phase - no aggregation duty or no attestations");
                                }
                            }
                        }
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
                            store.read().blocks_queue.values().map(|v| v.len()).sum::<usize>()
                        );
                        last_logged_slot = current_slot;
                    }
                }
                message = chain_message_receiver.recv() => {
                    let Some(message) = message else { break };
                    match message {
                        ChainMessage::ProcessBlock {
                            signed_block_with_attestation,
                            should_gossip,
                            ..
                        } => {
                            let block_slot = signed_block_with_attestation.message.block.slot;
                            let proposer = signed_block_with_attestation.message.block.proposer_index;
                            let block_root = signed_block_with_attestation.message.block.hash_tree_root();
                            let parent_root = signed_block_with_attestation.message.block.parent_root;

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

                            // Proactive parent check: verify parent exists BEFORE calling on_block.
                            // This avoids unnecessary state transition attempts and is more efficient
                            // than catching the "Block queued" error after the fact.
                            let parent_exists = {
                                let s = store.read();
                                parent_root.is_zero() || s.states.contains_key(&parent_root)
                            };

                            if !parent_exists {
                                // Queue the block and request parent without calling on_block
                                {
                                    let mut s = store.write();
                                    s.blocks_queue
                                        .entry(parent_root)
                                        .or_insert_with(Vec::new)
                                        .push(signed_block_with_attestation.clone());
                                }

                                warn!(
                                    child_slot = block_slot.0,
                                    child_block_root = %format!("0x{:x}", block_root),
                                    missing_parent_root = %format!("0x{:x}", parent_root),
                                    "Block queued (proactive) - parent not found, requesting via BlocksByRoot"
                                );

                                if let Err(req_err) = outbound_p2p_sender.send(
                                    OutboundP2pRequest::RequestBlocksByRoot(vec![parent_root])
                                ) {
                                    warn!("Failed to request missing parent block: {}", req_err);
                                }
                                continue;
                            }
                            
                            let result = {on_block(&mut *store.write(), signed_block_with_attestation.clone())};
                            match result {
                                Ok(()) => {
                                    info!("Block processed successfully");

                                    signed_block_provider.write().insert(block_root, signed_block_with_attestation.clone());

                                    {
                                        let s = store.read();
                                        let mut status = status_provider.write();
                                        status.finalized = s.latest_finalized.clone();
                                        status.head = Checkpoint {
                                            root: s.head,
                                            slot: s.blocks.get(&s.head).map(|b| b.slot).unwrap_or(Slot(0)),
                                        };
                                    }

                                    if should_gossip {
                                        if let Err(e) = outbound_p2p_sender.send(
                                            OutboundP2pRequest::GossipBlockWithAttestation(signed_block_with_attestation)
                                        ) {
                                            warn!("Failed to gossip block: {}", e);
                                        } else {
                                            info!(slot = block_slot.0, "Broadcasted block");
                                        }
                                    }
                                }
                                Err(e) if format!("{e:?}").starts_with("Err: (Fork-choice::Handlers::OnBlock) Block queued") => {
                                    // This path should be rare now due to proactive check,
                                    // but handle it for edge cases (e.g., parent pruned between check and call)
                                    warn!(
                                        child_slot = block_slot.0,
                                        child_block_root = %format!("0x{:x}", block_root),
                                        missing_parent_root = %format!("0x{:x}", parent_root),
                                        "Block queued (fallback) - parent not found, requesting via BlocksByRoot"
                                    );

                                    if !parent_root.is_zero() {
                                        if let Err(req_err) = outbound_p2p_sender.send(
                                            OutboundP2pRequest::RequestBlocksByRoot(vec![parent_root])
                                        ) {
                                            warn!("Failed to request missing parent block: {}", req_err);
                                        }
                                    }
                                }
                                Err(e) => warn!("Problem processing block: {}", e),
                            }
                        }
                        ChainMessage::ProcessAttestation {
                            signed_attestation,
                            should_gossip,
                            ..
                        } => {
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

                            match on_attestation(&mut *store.write(), signed_attestation.clone(), false) {
                                Ok(()) => {
                                    if should_gossip {
                                        let subnet_id = compute_subnet_id(validator_id);
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
                        }
                        ChainMessage::ProcessAggregation {
                            signed_aggregated_attestation,
                            should_gossip,
                            ..
                        } => {
                            let agg_slot = signed_aggregated_attestation.data.slot.0;
                            let validator_count = signed_aggregated_attestation
                                .proof
                                .participants
                                .0
                                .iter()
                                .filter(|b| **b)
                                .count();

                            match on_aggregated_attestation(&mut *store.write(), signed_aggregated_attestation.clone()) {
                                Ok(_) => {
                                    info!(
                                        slot = agg_slot,
                                        validators = validator_count,
                                        "Processed aggregated attestation for safe target"
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        slot = agg_slot,
                                        error = %e,
                                        "Failed to process aggregated attestation"
                                    );
                                }
                            }

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
    }

    info!("Main async task exiting...");

    Ok(())
}
