use containers::{
    Attestation, Attestations, BlockSignatures, BlockWithAttestation, Config, SignedBlockWithAttestation, block::{Block, BlockBody, BlockHeader, SignedBlock, hash_tree_root}, checkpoint::Checkpoint, slot::Slot, state::State, types::{Bytes32, ValidatorIndex}
};
use ssz::PersistentList as List;
use typenum::U4096;

pub const DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT: usize = 1 << 12; // 4096

pub fn create_block(slot: u64, parent_header: &mut BlockHeader, attestations: Option<Attestations>) -> SignedBlockWithAttestation {
    let body = BlockBody {
        attestations: attestations.unwrap_or_else(List::default),
    };

    let block_message = Block {
        slot: Slot(slot),
        proposer_index: ValidatorIndex(slot % 10),
        parent_root: hash_tree_root(parent_header),
        state_root: Bytes32(ssz::H256::zero()),
        body: body,
    };

    SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: block_message,
            proposer_attestation: Attestation::default(),
        },
        signature: BlockSignatures::default(),
    }
}

pub fn create_attestations(indices: &[usize]) -> Vec<bool> {
    let mut attestations = vec![false; DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT];
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
    use containers::{HistoricalBlockHashes, JustificationRoots, JustifiedSlots, JustificationsValidators};
    State {
        config,
        slot: Slot(0),
        latest_block_header: sample_block_header(),
        latest_justified: sample_checkpoint(),
        latest_finalized: sample_checkpoint(),
        historical_block_hashes: HistoricalBlockHashes::default(),
        justified_slots: JustifiedSlots::default(),
        validators: List::default(),
        justifications_roots: JustificationRoots::default(),
        justifications_validators: JustificationsValidators::default(),
    }
}

pub fn sample_config() -> Config {
    Config {
        genesis_time: 0,
    }
}