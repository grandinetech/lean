// tests/state_transition.rs
use containers::{block::{Block, SignedBlock, hash_tree_root}, state::State, types::{Bytes32, Uint64}, Slot};
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
    let mut state_at_slot_1 = state.process_slots(Slot(1));

    let signed_block = create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let block = signed_block.message.clone();

    // Use process_block_header + process_operations to avoid state root validation during setup
    let state_after_header = state_at_slot_1.process_block_header(&block);
    let expected_state = state_after_header.process_attestations(&block.body.attestations);

    let block_with_correct_root = Block {
        state_root: hash_tree_root(&expected_state),
        ..block
    };

    let final_signed_block = SignedBlock {
        message: block_with_correct_root,
        signature: signed_block.signature,
    };

    let final_state = state.state_transition(final_signed_block, true);

    assert_eq!(final_state, expected_state);
}

#[test]
#[should_panic(expected = "Block signatures must be valid")]
fn test_state_transition_invalid_signatures() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1));

    let signed_block = create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let block = signed_block.message.clone();

    // Use process_block_header + process_operations to avoid state root validation during setup
    let state_after_header = state_at_slot_1.process_block_header(&block);
    let expected_state = state_after_header.process_attestations(&block.body.attestations);

    let block_with_correct_root = Block {
        state_root: hash_tree_root(&expected_state),
        ..block
    };

    let final_signed_block = SignedBlock {
        message: block_with_correct_root,
        signature: signed_block.signature,
    };

    state.state_transition(final_signed_block, false);
}

#[test]
#[should_panic(expected = "Invalid block state root")]
fn test_state_transition_bad_state_root() {
    let state = genesis_state();
    let mut state_at_slot_1 = state.process_slots(Slot(1));

    let signed_block = create_block(1, &mut state_at_slot_1.latest_block_header, None);
    let mut block = signed_block.message.clone();

    block.state_root = Bytes32(ssz::H256::zero());

    let final_signed_block = SignedBlock {
        message: block,
        signature: signed_block.signature,
    };

    state.state_transition(final_signed_block, true);
}