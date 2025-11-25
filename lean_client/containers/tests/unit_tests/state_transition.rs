// tests/state_transition.rs
use containers::{
    block::{Block, SignedBlockWithAttestation, BlockWithAttestation, hash_tree_root},
    state::State,
    types::{Bytes32, Uint64},
    Slot, Attestation, BlockSignatures
};
use pretty_assertions::assert_eq;
use rstest::fixture;

#[path = "common.rs"]
mod common;
use common::{create_block, sample_config};

#[fixture]
fn genesis_state() -> State {
    let config = sample_config();
    State::generate_genesis(Uint64(config.genesis_time), Uint64(4))
}

#[test]
fn test_state_transition_full() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    let signed_block_with_attestation = create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let block = signed_block_with_attestation.message.block.clone();

    // Use process_block_header + process_operations to avoid state root validation during setup
    let state_after_header = state_at_slot_1.process_block_header(&block).unwrap();
    let expected_state = state_after_header.process_attestations(&block.body.attestations);

    let block_with_correct_root = Block {
        state_root: hash_tree_root(&expected_state),
        ..block
    };

    let final_signed_block_with_attestation = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: block_with_correct_root,
            proposer_attestation: signed_block_with_attestation.message.proposer_attestation,
        },
        signature: signed_block_with_attestation.signature,
    };

    let final_state = state.state_transition(final_signed_block_with_attestation, true).unwrap();

    assert_eq!(final_state, expected_state);
}

#[test]
fn test_state_transition_invalid_signatures() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    let signed_block_with_attestation = create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let block = signed_block_with_attestation.message.block.clone();

    // Use process_block_header + process_operations to avoid state root validation during setup
    let state_after_header = state_at_slot_1.process_block_header(&block).unwrap();
    let expected_state = state_after_header.process_attestations(&block.body.attestations);

    let block_with_correct_root = Block {
        state_root: hash_tree_root(&expected_state),
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
    assert_eq!(result.unwrap_err(), "Block signatures must be valid");
}

#[test]
fn test_state_transition_bad_state_root() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();

    let signed_block_with_attestation = create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let mut block = signed_block_with_attestation.message.block.clone();

    block.state_root = Bytes32(ssz::H256::zero());

    let final_signed_block_with_attestation = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation: Attestation::default(),
        },
        signature: BlockSignatures::default(),
    };

    let result = state.state_transition(final_signed_block_with_attestation, true);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Invalid block state root");
}