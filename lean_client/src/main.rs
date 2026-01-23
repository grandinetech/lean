use clap::Parser;
use containers::block::BlockSignatures;
use containers::ssz::{PersistentList, SszHash};
use containers::{
    attestation::{Attestation, AttestationData},
    block::{Block, BlockBody, BlockWithAttestation, SignedBlockWithAttestation},
    checkpoint::Checkpoint,
    config::Config,
    ssz,
    state::State,
    types::{Bytes32, Uint64, ValidatorIndex},
    Signature, Slot,
};
use fork_choice::{
    handlers::{on_attestation, on_block, on_tick},
    store::{get_forkchoice_store, Store, INTERVALS_PER_SLOT},
};
use libp2p_identity::Keypair;
use networking::gossipsub::config::GossipsubConfig;
use networking::gossipsub::topic::get_topics;
use networking::network::{NetworkService, NetworkServiceConfig};
use networking::types::{ChainMessage, OutboundP2pRequest};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::{
    sync::mpsc,
    task,
    time::{interval, Duration},
};
use tracing::level_filters::LevelFilter;
use tracing::{debug, info, warn};
use validator::{ValidatorConfig, ValidatorService};

fn load_node_key(path: &str) -> Result<Keypair, Box<dyn std::error::Error>> {
    let hex_str = std::fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(&hex_str)?;
    let secret = libp2p_identity::secp256k1::SecretKey::try_from_bytes(bytes)?;
    let keypair = libp2p_identity::secp256k1::Keypair::from(secret);
    Ok(Keypair::from(keypair))
}

fn print_chain_status(store: &Store, connected_peers: u64) {
    let current_slot = store.time / INTERVALS_PER_SLOT;

    let head_slot = store
        .blocks
        .get(&store.head)
        .map(|b| b.message.block.slot.0)
        .unwrap_or(0);

    let behind = if current_slot > head_slot {
        current_slot - head_slot
    } else {
        0
    };

    let (head_root, parent_root, state_root) = if let Some(block) = store.blocks.get(&store.head) {
        let head_root = store.head;
        let parent_root = block.message.block.parent_root;
        let state_root = block.message.block.state_root;
        (head_root, parent_root, state_root)
    } else {
        (
            Bytes32(ssz::H256::zero()),
            Bytes32(ssz::H256::zero()),
            Bytes32(ssz::H256::zero()),
        )
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
    println!("  Head Block Root:    0x{:x}", head_root.0);
    println!("  Parent Block Root:  0x{:x}", parent_root.0);
    println!("  State Root:         0x{:x}", state_root.0);
    println!(
        "  Timely:             {}",
        if timely { "YES" } else { "NO" }
    );
    println!("+---------------------------------------------------------------+");
    println!(
        "  Latest Justified:   Slot {:>5} | Root: 0x{:x}",
        justified.slot.0, justified.root.0
    );
    println!(
        "  Latest Finalized:   Slot {:>5} | Root: 0x{:x}",
        finalized.slot.0, finalized.root.0
    );
    println!("+===============================================================+\n");
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    address: IpAddr,

    #[arg(short, long, default_value_t = 8083)]
    port: u16,

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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let (outbound_p2p_sender, outbound_p2p_receiver) =
        mpsc::unbounded_channel::<OutboundP2pRequest>();
    let (chain_message_sender, mut chain_message_receiver) =
        mpsc::unbounded_channel::<ChainMessage>();

    let (genesis_time, validators) = if let Some(genesis_path) = &args.genesis {
        let genesis_config = containers::GenesisConfig::load_from_file(genesis_path)
            .expect("Failed to load genesis config");

        let validators: Vec<containers::validator::Validator> = genesis_config
            .genesis_validators
            .iter()
            .enumerate()
            .map(|(i, v_str)| {
                let pubkey = containers::public_key::PublicKey::from_hex(v_str)
                    .expect("Invalid genesis validator pubkey");
                containers::validator::Validator {
                    pubkey,
                    index: Uint64(i as u64),
                }
            })
            .collect();

        (genesis_config.genesis_time, validators)
    } else {
        let num_validators = 3;
        let validators = (0..num_validators)
            .map(|i| containers::validator::Validator {
                pubkey: containers::public_key::PublicKey::default(),
                index: Uint64(i as u64),
            })
            .collect();
        (1763757427, validators)
    };

    let genesis_state = State::generate_genesis_with_validators(Uint64(genesis_time), validators);

    let genesis_block = Block {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Bytes32(ssz::H256::zero()),
        state_root: Bytes32(genesis_state.hash_tree_root()),
        body: BlockBody {
            attestations: Default::default(),
        },
    };

    let genesis_proposer_attestation = Attestation {
        validator_id: Uint64(0),
        data: AttestationData {
            slot: Slot(0),
            head: Checkpoint {
                root: Bytes32(ssz::H256::zero()),
                slot: Slot(0),
            },
            target: Checkpoint {
                root: Bytes32(ssz::H256::zero()),
                slot: Slot(0),
            },
            source: Checkpoint {
                root: Bytes32(ssz::H256::zero()),
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
    let store = get_forkchoice_store(genesis_state.clone(), genesis_signed_block, config);

    let num_validators = genesis_state.validators.len_u64();
    info!(num_validators = num_validators, "Genesis state loaded");

    let validator_service = if let (Some(node_id), Some(registry_path)) =
        (&args.node_id, &args.validator_registry_path)
    {
        match ValidatorConfig::load_from_file(registry_path, node_id) {
            Ok(config) => {
                // Use explicit hash-sig-key-dir if provided
                if let Some(ref keys_dir) = args.hash_sig_key_dir {
                    let keys_path = std::path::Path::new(keys_dir);
                    if keys_path.exists() {
                        match ValidatorService::new_with_keys(
                            config.clone(),
                            num_validators,
                            keys_path,
                        ) {
                            Ok(service) => {
                                info!(
                                    node_id = %node_id,
                                    indices = ?config.validator_indices,
                                    keys_dir = ?keys_path,
                                    "Validator mode enabled with XMSS signing"
                                );
                                Some(service)
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to load XMSS keys: {}, falling back to zero signatures",
                                    e
                                );
                                Some(ValidatorService::new(config, num_validators))
                            }
                        }
                    } else {
                        warn!(
                            "Hash-sig key directory not found: {:?}, using zero signatures",
                            keys_path
                        );
                        Some(ValidatorService::new(config, num_validators))
                    }
                } else {
                    info!(
                        node_id = %node_id,
                        indices = ?config.validator_indices,
                        "Validator mode enabled (no --hash-sig-key-dir specified - using zero signatures)"
                    );
                    Some(ValidatorService::new(config, num_validators))
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

    let fork = "devnet0".to_string();
    let gossipsub_topics = get_topics(fork);
    let mut gossipsub_config = GossipsubConfig::new();
    gossipsub_config.set_topics(gossipsub_topics);

    let network_service_config = Arc::new(NetworkServiceConfig::new(
        gossipsub_config,
        args.address,
        args.port,
        args.bootnodes,
    ));

    let peer_count = Arc::new(AtomicU64::new(0));
    let peer_count_for_status = peer_count.clone();

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

    let chain_handle = task::spawn(async move {
        let mut tick_interval = interval(Duration::from_millis(1000));
        let mut last_logged_slot = 0u64;
        let mut last_status_slot: Option<u64> = None;
        let mut last_proposal_slot: Option<u64> = None;
        let mut last_attestation_slot: Option<u64> = None;

        let peer_count = peer_count_for_status;
        let mut store = store;

        loop {
            tokio::select! {
                _ = tick_interval.tick() => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    on_tick(&mut store, now, false);

                    let current_slot = store.time / INTERVALS_PER_SLOT;
                    let current_interval = store.time % INTERVALS_PER_SLOT;

                    if last_status_slot != Some(current_slot) {
                        let peers = peer_count.load(Ordering::Relaxed);
                        print_chain_status(&store, peers);
                        last_status_slot = Some(current_slot);
                    }

                    match current_interval {
                        0 => {
                            if let Some(ref vs) = validator_service {
                                if last_proposal_slot != Some(current_slot) {
                                    if let Some(proposer_idx) = vs.get_proposer_for_slot(Slot(current_slot)) {
                                        info!(
                                            slot = current_slot,
                                            proposer = proposer_idx.0,
                                            "Our turn to propose block!"
                                        );

                                        match vs.build_block_proposal(&mut store, Slot(current_slot), proposer_idx) {
                                            Ok(signed_block) => {
                                                let block_root = Bytes32(signed_block.message.block.hash_tree_root());
                                                info!(
                                                    slot = current_slot,
                                                    block_root = %format!("0x{:x}", block_root.0),
                                                    "Built block, processing and gossiping"
                                                );

                                                // Synchronize store time with wall clock before processing own block
                                                let now = SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap()
                                                    .as_secs();
                                                on_tick(&mut store, now, false);

                                                match on_block(&mut store, signed_block.clone()) {
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
                                    let attestations = vs.create_attestations(&store, Slot(current_slot));
                                    for signed_att in attestations {
                                        let validator_id = signed_att.validator_id;
                                        info!(
                                            slot = current_slot,
                                            validator = validator_id,
                                            "Broadcasting attestation"
                                        );

                                        match on_attestation(&mut store, signed_att.clone(), false) {
                                            Ok(()) => {
                                                if let Err(e) = chain_outbound_sender.send(
                                                    OutboundP2pRequest::GossipAttestation(signed_att)
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
                            info!(slot = current_slot, tick = store.time, "Computing safe target");
                        }
                        3 => {
                            info!(slot = current_slot, tick = store.time, "Accepting new attestations");
                        }
                        _ => {}
                    }

                    if current_slot != last_logged_slot && current_slot % 10 == 0 {
                        debug!("(Okay)Store time updated : slot {}, pending blocks: {}",
                            current_slot,
                            store.blocks_queue.values().map(|v| v.len()).sum::<usize>()
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
                            let block_slot = signed_block_with_attestation.message.block.slot.0;
                            let proposer = signed_block_with_attestation.message.block.proposer_index.0;
                            let block_root = Bytes32(signed_block_with_attestation.message.block.hash_tree_root());
                            let parent_root = signed_block_with_attestation.message.block.parent_root;

                            info!(
                                slot = block_slot,
                                block_root = %format!("0x{:x}", block_root.0),
                                "Processing block built by Validator {}",
                                proposer
                            );

                            // Synchronize store time with wall clock before processing block
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            on_tick(&mut store, now, false);

                            match on_block(&mut store, signed_block_with_attestation.clone()) {
                                Ok(()) => {
                                    info!("Block processed successfully");

                                    if should_gossip {
                                        if let Err(e) = outbound_p2p_sender.send(
                                            OutboundP2pRequest::GossipBlockWithAttestation(signed_block_with_attestation)
                                        ) {
                                            warn!("Failed to gossip block: {}", e);
                                        } else {
                                            info!(slot = block_slot, "Broadcasted block");
                                        }
                                    }
                                }
                                Err(e) if e.starts_with("Err: (Fork-choice::Handlers::OnBlock) Block queued") => {
                                    debug!("Block queued, requesting missing parent: {}", e);

                                    // Request missing parent block from peers
                                    if !parent_root.0.is_zero() {
                                        if let Err(req_err) = outbound_p2p_sender.send(
                                            OutboundP2pRequest::RequestBlocksByRoot(vec![parent_root])
                                        ) {
                                            warn!("Failed to request missing parent block: {}", req_err);
                                        } else {
                                            debug!("Requested missing parent block: 0x{:x}", parent_root.0);
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

                            match on_attestation(&mut store, signed_attestation.clone(), false) {
                                Ok(()) => {
                                    if should_gossip {
                                        if let Err(e) = outbound_p2p_sender.send(
                                            OutboundP2pRequest::GossipAttestation(signed_attestation)
                                        ) {
                                            warn!("Failed to gossip attestation: {}", e);
                                        } else {
                                            info!(slot = att_slot, "Broadcasted attestation");
                                        }
                                    }
                                }
                                Err(e) => warn!("Error processing attestation: {}", e),
                            }
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = network_handle => {
            println!("Network service finished.");
        }
        _ = chain_handle => {
            println!("Chain service finished.");
        }
    }

    println!("Main async task exiting...");
}
