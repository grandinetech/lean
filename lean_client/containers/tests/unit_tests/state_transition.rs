//! State transition tests
//!
//! Tests for full state transitions including signature validation
//! and state root verification.

// tests/state_transition.rs
use containers::{
    Attestation, Block, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation, Slot,
    State,
};
use pretty_assertions::assert_eq;
use rstest::fixture;
use ssz::{H256, PersistentList, SszHash};

#[path = "common.rs"]
mod common;
use common::{create_block, sample_config};
use xmss::Signature;

#[fixture]
fn genesis_state() -> State {
    let config = sample_config();
    State::generate_genesis(config.genesis_time, 4)
}

#[test]
fn test_state_transition_full() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    let signed_block_with_attestation =
        create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let block = signed_block_with_attestation.message.block.clone();

    // Use process_block_header + process_operations to avoid state root validation during setup
    let state_after_header = state_at_slot_1.process_block_header(&block).unwrap();

    let expected_state = state_after_header
        .process_attestations(&block.body.attestations)
        .unwrap();

    let block_with_correct_root = Block {
        state_root: expected_state.hash_tree_root(),
        ..block
    };

    let final_signed_block_with_attestation = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: block_with_correct_root,
            proposer_attestation: signed_block_with_attestation.message.proposer_attestation,
        },
        signature: signed_block_with_attestation.signature,
    };

    let final_state = state
        .state_transition(final_signed_block_with_attestation, true)
        .unwrap();

    assert_eq!(
        final_state.hash_tree_root(),
        expected_state.hash_tree_root()
    );
}

#[test]
fn test_state_transition_invalid_signatures() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    let signed_block_with_attestation =
        create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let block = signed_block_with_attestation.message.block.clone();

    // Use process_block_header + process_operations to avoid state root validation during setup
    let state_after_header = state_at_slot_1.process_block_header(&block).unwrap();

    let expected_state = state_after_header
        .process_attestations(&block.body.attestations)
        .unwrap();

    let block_with_correct_root = Block {
        state_root: expected_state.hash_tree_root(),
        ..block
    };

    let final_signed_block_with_attestation = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: block_with_correct_root,
            proposer_attestation: signed_block_with_attestation.message.proposer_attestation,
        },
        signature: signed_block_with_attestation.signature,
    };

    let result = state.state_transition(final_signed_block_with_attestation, false);
    assert!(result.is_err());
}

// Test with bad state root using devnet2 BlockSignatures structure
#[test]
fn test_state_transition_bad_state_root() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    let signed_block_with_attestation =
        create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let mut block = signed_block_with_attestation.message.block.clone();

    block.state_root = H256::zero();

    let final_signed_block_with_attestation = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation: Attestation::default(),
        },
        signature: BlockSignatures {
            attestation_signatures: PersistentList::default(),
            proposer_signature: Signature::default(),
        },
    };

    let result = state.state_transition(final_signed_block_with_attestation, true);
    assert!(result.is_err());
}

#[test]
fn test_state_transition_devnet2() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    // Create a block with attestations for devnet2
    let signed_block_with_attestation =
        create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let block = signed_block_with_attestation.message.block.clone();

    // Process the block header and attestations
    let state_after_header = state_at_slot_1.process_block_header(&block).unwrap();

    let expected_state = state_after_header
        .process_attestations(&block.body.attestations)
        .unwrap();

    // Ensure the state root matches the expected state
    let block_with_correct_root = Block {
        state_root: expected_state.hash_tree_root(),
        ..block
    };

    let final_signed_block_with_attestation = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: block_with_correct_root,
            proposer_attestation: signed_block_with_attestation.message.proposer_attestation,
        },
        signature: signed_block_with_attestation.signature,
    };

    // Perform the state transition and validate the result
    let final_state = state
        .state_transition(final_signed_block_with_attestation, true)
        .unwrap();

    assert_eq!(
        final_state.hash_tree_root(),
        expected_state.hash_tree_root()
    );
}
