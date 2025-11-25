use clap::Parser;
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
    store::get_forkchoice_store,
};
use networking::gossipsub::config::GossipsubConfig;
use networking::gossipsub::topic::get_topics;
use networking::network::{NetworkService, NetworkServiceConfig};
use networking::types::{ChainMessage, OutboundP2pRequest};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::{sync::mpsc, task};
use tracing::{info, warn};

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
    let (chain_message_sender, mut chain_message_receiver) =
        mpsc::unbounded_channel::<ChainMessage>();

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
        state_root: Bytes32(ssz::H256::zero()),
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
    let mut store = get_forkchoice_store(genesis_state, genesis_signed_block, config);

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

    let chain_handle = task::spawn(async move {
        while let Some(message) = chain_message_receiver.recv().await {
            info!("Received chain message: {}", message);
            match message {
                ChainMessage::ProcessBlock {
                    signed_block_with_attestation,
                    ..
                } => {
                    if let Err(e) = on_block(&mut store, signed_block_with_attestation) {
                        warn!("Error processing block: {}", e);
                    }
                    else {
                        info!("Block processed successfully.");
                    }
                }
                ChainMessage::ProcessAttestation {
                    signed_attestation, ..
                } => {
                    if let Err(e) = on_attestation(&mut store, signed_attestation.message, false) {
                        warn!("Error processing attestation: {}", e);
                    }
                    else {
                        info!("Attestation processed successfully.");
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
