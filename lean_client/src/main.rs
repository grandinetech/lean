use clap::Parser;
use tokio::{
    sync::{mpsc, Mutex},
    task,
};
use networking::network::{NetworkService, NetworkServiceConfig};
use networking::gossipsub::config::GossipsubConfig;
use networking::gossipsub::topic::get_topics;
use networking::types::{ChainMessage, OutboundP2pRequest};
use containers::{
    attestation::{Attestation, AttestationData, BlockSignatures},
    block::{Block, BlockBody, BlockWithAttestation, SignedBlockWithAttestation},
    checkpoint::Checkpoint,
    config::Config,
    ssz,
    state::State,
    types::{Bytes32, Uint64, ValidatorIndex},
    Slot,
};
use fork_choice::{
    handlers::{on_attestation, on_block},
    store::{get_block_root, get_forkchoice_store},
};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::{sync::mpsc, task};
use tracing::{info, warn};
use containers::ssz::SszHash;

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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let (_outbound_p2p_sender, outbound_p2p_receiver) =
        mpsc::unbounded_channel::<OutboundP2pRequest>();
    let (chain_message_sender, chain_message_receiver) =
        mpsc::unbounded_channel::<ChainMessage>();

    // Initialize Fork Choice Store
    let (genesis_time, validators) = if let Some(genesis_path) = args.genesis {
        let genesis_config = containers::GenesisConfig::load_from_file(genesis_path)
            .expect("Failed to load genesis config");

        let validators: Vec<containers::validator::Validator> = genesis_config
            .genesis_validators
            .iter()
            .map(|v_str| {
                let pubkey = containers::validator::BlsPublicKey::from_hex(v_str)
                    .expect("Invalid genesis validator pubkey");
                containers::validator::Validator { pubkey }
            })
            .collect();

        (genesis_config.genesis_time, validators)
    } else {
        let num_validators = 3;
        let validators = (0..num_validators)
            .map(|_| containers::validator::Validator::default())
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
        signature: BlockSignatures::default(),
    };

    let config = Config { genesis_time };
    let store = Arc::new(Mutex::new(get_forkchoice_store(genesis_state, genesis_signed_block, config)));

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
    let mut network_service = NetworkService::new(
        network_service_config.clone(),
        outbound_p2p_receiver,
        chain_message_sender,
    )
    .await
    .expect("Failed to create network service");

    let network_handle = task::spawn(async move {
        if let Err(err) = network_service.start().await {
            panic!("Network service exited with error: {err}");
        }
    });

    let chain_store = Arc::clone(&store);
    let chain_handle = task::spawn(async move {
        let mut receiver = chain_message_receiver;
        while let Some(message) = receiver.recv().await {
            info!(message = %message, "Chain message received");
            match message {
                ChainMessage::ProcessBlock { signed_block_with_attestation, .. } => {
                    let slot = signed_block_with_attestation.message.block.slot.0;
                    let proposer_index = signed_block_with_attestation.message.block.proposer_index.0;
                    let block = signed_block_with_attestation.message.block.clone();
                    let proposer_attestation =
                        signed_block_with_attestation.message.proposer_attestation.clone();
                    let signed_block_with_attestation = SignedBlockWithAttestation {
                        message: BlockWithAttestation {
                            block,
                            proposer_attestation,
                        },
                        signature: BlockSignatures::default(),
                    };
                    let block_root = get_block_root(&signed_block_with_attestation);

                    let mut store = chain_store.lock().await;
                    info!(
                        slot,
                        proposer = proposer_index,
                        root = %block_root,
                        "Processing block from gossip"
                    );
                    let _ = on_block(&mut store, signed_block_with_attestation);
                    info!(
                        slot,
                        head = %store.head,
                        finalized_slot = store.latest_finalized.slot.0,
                        "Fork-choice head updated"
                    );
                }
                ChainMessage::ProcessAttestation { signed_attestation, .. } => {
                    let slot = signed_attestation.message.data.slot.0;
                    let validator = signed_attestation.message.validator_id.0;
                    let target_root = signed_attestation.message.data.target.root;
                    let attestation = signed_attestation.message.clone();

                    let mut store = chain_store.lock().await;
                    info!(
                        slot,
                        validator,
                        target = %target_root,
                        "Processing attestation from gossip"
                    );
                    let _ = on_attestation(&mut store, attestation, false);
                    info!(
                        slot,
                        validator,
                        head = %store.head,
                        "Fork-choice votes updated"
                    );
                }
            }
        }
        info!("Chain message stream closed");
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
