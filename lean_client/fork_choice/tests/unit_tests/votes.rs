//! Vote/attestation unit tests for devnet2
//!
//! Tests for vote processing and fork choice weight calculations
//! using the devnet2 SignedAttestation structure.

use super::common::create_test_store;
use containers::{
    attestation::{AttestationData, SignedAttestation},
    block::{Block, BlockBody, BlockWithAttestation, SignedBlockWithAttestation},
    checkpoint::Checkpoint,
    Bytes32, Slot, ValidatorIndex,
};
use fork_choice::store::get_fork_choice_head;
use ssz::SszHash;
use std::collections::HashMap;

/// Helper to create a SignedAttestation for devnet2
fn create_signed_attestation(
    validator_id: u64,
    slot: u64,
    head_root: Bytes32,
    head_slot: u64,
    target_root: Bytes32,
    target_slot: u64,
    source_root: Bytes32,
    source_slot: u64,
) -> SignedAttestation {
    SignedAttestation {
        validator_id,
        message: AttestationData {
            slot: Slot(slot),
            head: Checkpoint {
                root: head_root,
                slot: Slot(head_slot),
            },
            target: Checkpoint {
                root: target_root,
                slot: Slot(target_slot),
            },
            source: Checkpoint {
                root: source_root,
                slot: Slot(source_slot),
            },
        },
        signature: Default::default(),
    }
}

#[test]
fn test_single_vote_updates_head() {
    let store = create_test_store();
    let genesis_root = store.head;

    // Create attestation pointing to genesis
    let attestation = create_signed_attestation(
        0,            // validator_id
        1,            // slot
        genesis_root, // head_root
        0,            // head_slot
        genesis_root, // target_root
        0,            // target_slot
        genesis_root, // source_root
        0,            // source_slot
    );

    let mut attestations = HashMap::new();
    attestations.insert(ValidatorIndex(0), attestation);

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);

    // With only one block, head should still be genesis
    assert_eq!(head, genesis_root);
}

#[test]
fn test_multiple_votes_same_block() {
    let store = create_test_store();
    let genesis_root = store.head;

    // Multiple validators vote for same block
    let mut attestations = HashMap::new();
    for i in 0..5 {
        let attestation =
            create_signed_attestation(i, 1, genesis_root, 0, genesis_root, 0, genesis_root, 0);
        attestations.insert(ValidatorIndex(i), attestation);
    }

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);

    // All votes on same block, head unchanged
    assert_eq!(head, genesis_root);
}

#[test]
fn test_competing_votes_different_blocks() {
    let mut store = create_test_store();
    let genesis_root = store.head;

    // Create two competing blocks at slot 1
    let block_a = Block {
        slot: Slot(1),
        proposer_index: ValidatorIndex(0),
        parent_root: genesis_root,
        state_root: Bytes32::default(),
        body: BlockBody::default(),
    };
    let block_a_root = Bytes32(block_a.hash_tree_root());

    let mut block_b = block_a.clone();
    block_b.proposer_index = ValidatorIndex(1); // Different proposer to get different root
    let block_b_root = Bytes32(block_b.hash_tree_root());

    store.blocks.insert(
        block_a_root,
        SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block: block_a,
                proposer_attestation: Default::default(),
            },
            signature: Default::default(),
        },
    );

    store.blocks.insert(
        block_b_root,
        SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block: block_b,
                proposer_attestation: Default::default(),
            },
            signature: Default::default(),
        },
    );

    // 3 votes for block_a, 2 votes for block_b
    let mut attestations = HashMap::new();
    for i in 0..3 {
        attestations.insert(
            ValidatorIndex(i),
            create_signed_attestation(i, 1, block_a_root, 1, genesis_root, 0, genesis_root, 0),
        );
    }
    for i in 3..5 {
        attestations.insert(
            ValidatorIndex(i),
            create_signed_attestation(i, 1, block_b_root, 1, genesis_root, 0, genesis_root, 0),
        );
    }

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);

    // Block A should win with more votes
    assert_eq!(head, block_a_root);
}

#[test]
fn test_vote_weight_accumulation() {
    let mut store = create_test_store();
    let genesis_root = store.head;

    // Create a chain: genesis -> block1 -> block2
    let block1 = Block {
        slot: Slot(1),
        proposer_index: ValidatorIndex(0),
        parent_root: genesis_root,
        state_root: Bytes32::default(),
        body: BlockBody::default(),
    };
    let block1_root = Bytes32(block1.hash_tree_root());

    let block2 = Block {
        slot: Slot(2),
        proposer_index: ValidatorIndex(0),
        parent_root: block1_root,
        state_root: Bytes32::default(),
        body: BlockBody::default(),
    };
    let block2_root = Bytes32(block2.hash_tree_root());

    store.blocks.insert(
        block1_root,
        SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block: block1,
                proposer_attestation: Default::default(),
            },
            signature: Default::default(),
        },
    );
    store.blocks.insert(
        block2_root,
        SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block: block2,
                proposer_attestation: Default::default(),
            },
            signature: Default::default(),
        },
    );

    // Vote for block2 - should accumulate to block1 as well
    let mut attestations = HashMap::new();
    attestations.insert(
        ValidatorIndex(0),
        create_signed_attestation(0, 2, block2_root, 2, genesis_root, 0, genesis_root, 0),
    );

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);

    // Head should be block2 (the one with votes)
    assert_eq!(head, block2_root);
}

#[test]
fn test_duplicate_vote_uses_latest() {
    let store = create_test_store();
    let genesis_root = store.head;

    // Same validator can only have one vote in the map (latest wins)
    let mut attestations = HashMap::new();

    // Insert a vote
    attestations.insert(
        ValidatorIndex(0),
        create_signed_attestation(0, 1, genesis_root, 0, genesis_root, 0, genesis_root, 0),
    );

    // "Update" with same validator - only latest is kept
    attestations.insert(
        ValidatorIndex(0),
        create_signed_attestation(0, 2, genesis_root, 0, genesis_root, 0, genesis_root, 0),
    );

    // Should only have 1 attestation
    assert_eq!(attestations.len(), 1);

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);
    assert_eq!(head, genesis_root);
}

#[test]
fn test_vote_for_unknown_block_ignored() {
    let store = create_test_store();
    let genesis_root = store.head;
    let unknown_root = Bytes32(ssz::H256::from_slice(&[0xff; 32]));

    // Vote for block that doesn't exist
    let mut attestations = HashMap::new();
    attestations.insert(
        ValidatorIndex(0),
        create_signed_attestation(0, 1, unknown_root, 1, genesis_root, 0, genesis_root, 0),
    );

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);

    // Should still return genesis since unknown block is skipped
    assert_eq!(head, genesis_root);
}
