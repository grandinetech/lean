//! Common test utilities and helper functions for fork choice tests

use std::collections::HashMap;
use containers::*;
use containers::block::hash_tree_root;
use containers::config::Config;

/// Helper function to create a zero hash
pub fn zero_hash() -> Bytes32 {
    Bytes32(ssz::H256::zero())
}

/// Create a simple test configuration
pub fn test_config() -> Config {
    Config {
        genesis_time: 1000,
        num_validators: 100,
    }
}

/// Create sample blocks for testing
pub fn create_sample_blocks() -> HashMap<Bytes32, Block> {
    let genesis = Block {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: zero_hash(),
        state_root: Bytes32(ssz::H256::from_slice(b"genesis\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")),
        body: BlockBody {
            attestations: ssz::PersistentList::default(),
        },
    };
    let genesis_hash = hash_tree_root(&genesis);

    let block_a = Block {
        slot: Slot(1),
        proposer_index: ValidatorIndex(1),
        parent_root: genesis_hash,
        state_root: Bytes32(ssz::H256::from_slice(b"block_a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")),
        body: BlockBody {
            attestations: ssz::PersistentList::default(),
        },
    };
    let block_a_hash = hash_tree_root(&block_a);

    let block_b = Block {
        slot: Slot(2),
        proposer_index: ValidatorIndex(2),
        parent_root: block_a_hash,
        state_root: Bytes32(ssz::H256::from_slice(b"block_b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")),
        body: BlockBody {
            attestations: ssz::PersistentList::default(),
        },
    };
    let block_b_hash = hash_tree_root(&block_b);

    HashMap::from([
        (genesis_hash, genesis),
        (block_a_hash, block_a),
        (block_b_hash, block_b),
    ])
}

/// Create a block with the specified parameters
pub fn create_block(
    slot: u64,
    proposer_index: u64,
    parent_root: Bytes32,
    state_data: &[u8; 32],
) -> Block {
    Block {
        slot: Slot(slot),
        proposer_index: ValidatorIndex(proposer_index),
        parent_root,
        state_root: Bytes32(ssz::H256::from_slice(state_data)),
        body: BlockBody {
            attestations: ssz::PersistentList::default(),
        },
    }
}

/// Create a checkpoint with the specified root and slot
pub fn create_checkpoint(root: Bytes32, slot: u64) -> Checkpoint {
    Checkpoint {
        root,
        slot: Slot(slot),
    }
}