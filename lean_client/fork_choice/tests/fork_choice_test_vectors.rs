//! Fork choice test vectors for devnet2
//!
//! Integration tests for fork choice rule implementation
//! using devnet2 data structures.

use containers::{
    attestation::{AttestationData, SignedAttestation},
    block::{Block, BlockBody, BlockWithAttestation, SignedBlockWithAttestation},
    checkpoint::Checkpoint,
    config::Config,
    state::State,
    validator::Validator,
    Bytes32, Slot, Uint64, ValidatorIndex,
};
use fork_choice::store::{get_fork_choice_head, get_forkchoice_store, Store};
use ssz::SszHash;
use std::collections::HashMap;

/// Helper to create a genesis store for testing
fn create_genesis_store() -> Store {
    let config = Config { genesis_time: 0 };
    let validators = vec![Validator::default(); 10];
    let state = State::generate_genesis_with_validators(Uint64(0), validators);

    let block = Block {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Bytes32::default(),
        state_root: Bytes32(state.hash_tree_root()),
        body: BlockBody::default(),
    };

    let signed_block = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation: Default::default(),
        },
        signature: Default::default(),
    };

    get_forkchoice_store(state, signed_block, config)
}

/// Helper to create a signed attestation
fn create_attestation(
    validator_id: u64,
    slot: u64,
    head: Checkpoint,
    target: Checkpoint,
    source: Checkpoint,
) -> SignedAttestation {
    SignedAttestation {
        validator_id,
        message: AttestationData {
            slot: Slot(slot),
            head,
            target,
            source,
        },
        signature: Default::default(),
    }
}

/// Helper to add a block to the store
fn add_block(store: &mut Store, slot: u64, parent_root: Bytes32, proposer: u64) -> Bytes32 {
    let block = Block {
        slot: Slot(slot),
        proposer_index: ValidatorIndex(proposer),
        parent_root,
        state_root: Bytes32::default(),
        body: BlockBody::default(),
    };
    let block_root = Bytes32(block.hash_tree_root());

    store.blocks.insert(
        block_root,
        SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation: Default::default(),
            },
            signature: Default::default(),
        },
    );

    block_root
}

#[test]
fn test_genesis_state_transition() {
    let store = create_genesis_store();

    // Verify genesis state is properly initialized
    assert!(!store.head.0.is_zero());
    assert_eq!(store.blocks.len(), 1);
    assert_eq!(store.states.len(), 1);

    // Genesis should be both justified and finalized
    assert_eq!(store.latest_justified.slot, Slot(0));
    assert_eq!(store.latest_finalized.slot, Slot(0));
}

#[test]
fn test_basic_slot_transition() {
    let mut store = create_genesis_store();
    let genesis_root = store.head;

    // Add blocks at slots 1, 2, 3
    let block1_root = add_block(&mut store, 1, genesis_root, 0);
    let block2_root = add_block(&mut store, 2, block1_root, 0);
    let block3_root = add_block(&mut store, 3, block2_root, 0);

    assert_eq!(store.blocks.len(), 4);

    // Without attestations and min_votes=1, head should stay at genesis
    // (no blocks have enough votes to be considered)
    let empty_attestations = HashMap::new();
    let head = get_fork_choice_head(&store, genesis_root, &empty_attestations, 1);
    assert_eq!(head, genesis_root);

    // With attestation for block3 and min_votes=1, head should follow the voted chain
    let mut attestations = HashMap::new();
    let checkpoint = Checkpoint {
        root: block3_root,
        slot: Slot(3),
    };
    let genesis_checkpoint = Checkpoint {
        root: genesis_root,
        slot: Slot(0),
    };

    attestations.insert(
        ValidatorIndex(0),
        create_attestation(
            0,
            3,
            checkpoint.clone(),
            checkpoint.clone(),
            genesis_checkpoint.clone(),
        ),
    );

    // The fork choice should follow the chain with votes to find the heaviest head
    let head = get_fork_choice_head(&store, genesis_root, &attestations, 1);

    // With 1 vote on block3, the entire chain block1->block2->block3 gets 1 vote each
    // So head should be block3 (the tip of the voted chain)
    assert_eq!(head, block3_root);
}

#[test]
fn test_attestation_processing() {
    let mut store = create_genesis_store();
    let genesis_root = store.head;
    let genesis_checkpoint = Checkpoint {
        root: genesis_root,
        slot: Slot(0),
    };

    // Create a block
    let block1_root = add_block(&mut store, 1, genesis_root, 0);
    let block1_checkpoint = Checkpoint {
        root: block1_root,
        slot: Slot(1),
    };

    // Process attestations from multiple validators
    let mut attestations = HashMap::new();
    for i in 0..5 {
        attestations.insert(
            ValidatorIndex(i),
            create_attestation(
                i,
                1,
                block1_checkpoint.clone(),
                block1_checkpoint.clone(),
                genesis_checkpoint.clone(),
            ),
        );
    }

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);
    assert_eq!(head, block1_root);
}

#[test]
fn test_multiple_attestations() {
    let mut store = create_genesis_store();
    let genesis_root = store.head;
    let genesis_checkpoint = Checkpoint {
        root: genesis_root,
        slot: Slot(0),
    };

    // Create a chain of blocks
    let block1_root = add_block(&mut store, 1, genesis_root, 0);
    let block2_root = add_block(&mut store, 2, block1_root, 0);
    let block3_root = add_block(&mut store, 3, block2_root, 0);

    let block3_checkpoint = Checkpoint {
        root: block3_root,
        slot: Slot(3),
    };

    // All validators attest to block3
    let mut attestations = HashMap::new();
    for i in 0..10 {
        attestations.insert(
            ValidatorIndex(i),
            create_attestation(
                i,
                3,
                block3_checkpoint.clone(),
                block3_checkpoint.clone(),
                genesis_checkpoint.clone(),
            ),
        );
    }

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);
    assert_eq!(head, block3_root);
}

#[test]
fn test_fork_choice_with_competing_blocks() {
    let mut store = create_genesis_store();
    let genesis_root = store.head;
    let genesis_checkpoint = Checkpoint {
        root: genesis_root,
        slot: Slot(0),
    };

    // Create two competing forks at slot 1
    let fork_a_root = add_block(&mut store, 1, genesis_root, 0);
    let fork_b_root = add_block(&mut store, 1, genesis_root, 1); // Different proposer

    let fork_a_checkpoint = Checkpoint {
        root: fork_a_root,
        slot: Slot(1),
    };
    let fork_b_checkpoint = Checkpoint {
        root: fork_b_root,
        slot: Slot(1),
    };

    // 6 validators vote for fork A
    let mut attestations = HashMap::new();
    for i in 0..6 {
        attestations.insert(
            ValidatorIndex(i),
            create_attestation(
                i,
                1,
                fork_a_checkpoint.clone(),
                fork_a_checkpoint.clone(),
                genesis_checkpoint.clone(),
            ),
        );
    }

    // 4 validators vote for fork B
    for i in 6..10 {
        attestations.insert(
            ValidatorIndex(i),
            create_attestation(
                i,
                1,
                fork_b_checkpoint.clone(),
                fork_b_checkpoint.clone(),
                genesis_checkpoint.clone(),
            ),
        );
    }

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);

    // Fork A should win with more votes
    assert_eq!(head, fork_a_root);
}

#[test]
fn test_finality_prevents_reorg() {
    let mut store = create_genesis_store();
    let genesis_root = store.head;
    let genesis_checkpoint = Checkpoint {
        root: genesis_root,
        slot: Slot(0),
    };

    // Create a finalized chain
    let block1_root = add_block(&mut store, 1, genesis_root, 0);
    let block2_root = add_block(&mut store, 2, block1_root, 0);

    // Update finalized checkpoint
    store.latest_finalized = Checkpoint {
        root: block1_root,
        slot: Slot(1),
    };

    // Create competing fork from genesis (should not be chosen due to finality)
    let competing_root = add_block(&mut store, 1, genesis_root, 1);

    let block2_checkpoint = Checkpoint {
        root: block2_root,
        slot: Slot(2),
    };
    let competing_checkpoint = Checkpoint {
        root: competing_root,
        slot: Slot(1),
    };

    // More votes for competing fork
    let mut attestations = HashMap::new();
    for i in 0..7 {
        attestations.insert(
            ValidatorIndex(i),
            create_attestation(
                i,
                1,
                competing_checkpoint.clone(),
                competing_checkpoint.clone(),
                genesis_checkpoint.clone(),
            ),
        );
    }
    for i in 7..10 {
        attestations.insert(
            ValidatorIndex(i),
            create_attestation(
                i,
                2,
                block2_checkpoint.clone(),
                block2_checkpoint.clone(),
                genesis_checkpoint.clone(),
            ),
        );
    }

    // Start from finalized block1
    let head = get_fork_choice_head(&store, block1_root, &attestations, 0);

    // Should follow the chain from block1, not competing fork
    assert_eq!(head, block2_root);
}

#[test]
fn test_attestation_from_future_slot() {
    let mut store = create_genesis_store();
    let genesis_root = store.head;
    let genesis_checkpoint = Checkpoint {
        root: genesis_root,
        slot: Slot(0),
    };

    // Create block at slot 1
    let block1_root = add_block(&mut store, 1, genesis_root, 0);
    let block1_checkpoint = Checkpoint {
        root: block1_root,
        slot: Slot(1),
    };

    // Attestation claims to be from slot 100 (future)
    // The fork choice still processes it based on what block it points to
    let mut attestations = HashMap::new();
    attestations.insert(
        ValidatorIndex(0),
        create_attestation(
            0,
            100,
            block1_checkpoint.clone(),
            block1_checkpoint.clone(),
            genesis_checkpoint.clone(),
        ),
    );

    let head = get_fork_choice_head(&store, genesis_root, &attestations, 0);

    // Should still follow the attestation to block1
    assert_eq!(head, block1_root);
}

#[test]
fn test_empty_attestations_returns_root() {
    let store = create_genesis_store();
    let genesis_root = store.head;

    let empty_attestations = HashMap::new();
    let head = get_fork_choice_head(&store, genesis_root, &empty_attestations, 0);

    // With no attestations, should return the provided root
    assert_eq!(head, genesis_root);
}
