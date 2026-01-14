use containers::block::BlockSignatures;
use containers::{
    block::{hash_tree_root, Block, BlockBody, BlockHeader},
    checkpoint::Checkpoint,
    slot::Slot,
    state::State,
    types::{Bytes32, ValidatorIndex},
    AggregatedAttestation, Attestation, Attestations, BlockWithAttestation, Config, Signature,
    SignedBlockWithAttestation, Validators,
};
use ssz::PersistentList;
use typenum::U4096;

pub const DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT: usize = 1 << 12; // 4096
pub const TEST_VALIDATOR_COUNT: usize = 4; // Actual validator count used in tests

// Compile-time assertion: ensure test validator count does not exceed the registry limit.
const _: [(); DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT - TEST_VALIDATOR_COUNT] =
    [(); DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT - TEST_VALIDATOR_COUNT];

pub fn create_block(
    slot: u64,
    parent_header: &mut BlockHeader,
    attestations: Option<Attestations>,
) -> SignedBlockWithAttestation {
    #[cfg(feature = "devnet1")]
    let body = BlockBody {
        attestations: attestations.unwrap_or_else(PersistentList::default),
    };
    #[cfg(feature = "devnet2")]
    let body = BlockBody {
        attestations: {
            let attestations_vec = attestations.unwrap_or_default();

            // Convert PersistentList into a Vec
            let attestations_vec: Vec<Attestation> =
                attestations_vec.into_iter().cloned().collect();

            let aggregated: Vec<AggregatedAttestation> =
                AggregatedAttestation::aggregate_by_data(&attestations_vec);

            let aggregated: Vec<AggregatedAttestation> =
                AggregatedAttestation::aggregate_by_data(&attestations_vec);

            // Create a new empty PersistentList
            let mut persistent_list: PersistentList<AggregatedAttestation, U4096> =
                PersistentList::default();

            // Push each aggregated attestation
            for agg in aggregated {
                persistent_list
                    .push(agg)
                    .expect("PersistentList capacity exceeded");
            }

            persistent_list
        },
        // other BlockBody fields...
    };

    let block_message = Block {
        slot: Slot(slot),
        proposer_index: ValidatorIndex(slot % 10),
        parent_root: hash_tree_root(parent_header),
        state_root: Bytes32(ssz::H256::zero()),
        body: body,
    };

    #[cfg(feature = "devnet1")]
    let return_value = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: block_message,
            proposer_attestation: Attestation::default(),
        },
        signature: PersistentList::default(),
    };

    #[cfg(feature = "devnet2")]
    let return_value = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: block_message,
            proposer_attestation: Attestation::default(),
        },
        signature: BlockSignatures {
            attestation_signatures: PersistentList::default(),
            proposer_signature: Signature::default(),
        },
    };

    return_value
}

pub fn create_attestations(indices: &[usize]) -> Vec<bool> {
    let mut attestations = vec![false; TEST_VALIDATOR_COUNT];
    for &index in indices {
        if index < attestations.len() {
            attestations[index] = true;
        }
    }
    attestations
}

pub fn sample_block_header() -> BlockHeader {
    BlockHeader {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Bytes32(ssz::H256::zero()),
        state_root: Bytes32(ssz::H256::zero()),
        body_root: Bytes32(ssz::H256::zero()),
    }
}

pub fn sample_checkpoint() -> Checkpoint {
    Checkpoint {
        root: Bytes32(ssz::H256::zero()),
        slot: Slot(0),
    }
}

pub fn base_state(config: Config) -> State {
    base_state_with_validators(config, TEST_VALIDATOR_COUNT)
}

pub fn base_state_with_validators(config: Config, num_validators: usize) -> State {
    use containers::{
        validator::Validator, HistoricalBlockHashes, JustificationRoots, JustificationsValidators,
        JustifiedSlots, Uint64,
    };

    // Create validators list with the specified number of validators
    let mut validators = Validators::default();
    for i in 0..num_validators {
        let validator = Validator {
            pubkey: Default::default(),
            index: Uint64(i as u64),
        };
        validators.push(validator).expect("within limit");
    }

    State {
        config,
        slot: Slot(0),
        latest_block_header: sample_block_header(),
        latest_justified: sample_checkpoint(),
        latest_finalized: sample_checkpoint(),
        historical_block_hashes: HistoricalBlockHashes::default(),
        justified_slots: JustifiedSlots::default(),
        validators,
        justifications_roots: JustificationRoots::default(),
        justifications_validators: JustificationsValidators::default(),
    }
}

pub fn sample_config() -> Config {
    Config { genesis_time: 0 }
}
