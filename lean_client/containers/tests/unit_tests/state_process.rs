// tests/state_process.rs
use containers::{
    block::{hash_tree_root, Block, BlockBody},
    checkpoint::Checkpoint,
    slot::Slot,
    state::State,
    types::{Bytes32, Uint64, ValidatorIndex},
    Attestation, AttestationData,
};
use pretty_assertions::assert_eq;
use rstest::{fixture, rstest};
use ssz::PersistentList as List;
use typenum::U4096;

#[path = "common.rs"]
mod common;
use common::{create_block, sample_config};

#[fixture]
pub fn genesis_state() -> State {
    let config = sample_config();
    State::generate_genesis(Uint64(config.genesis_time), Uint64(10))
}

#[test]
fn test_process_slot() {
    let genesis_state = genesis_state();

    assert_eq!(
        genesis_state.latest_block_header.state_root,
        Bytes32(ssz::H256::zero())
    );

    let state_after_slot = genesis_state.process_slot();
    let expected_root = hash_tree_root(&genesis_state);

    assert_eq!(
        state_after_slot.latest_block_header.state_root,
        expected_root
    );

    let state_after_second_slot = state_after_slot.process_slot();
    assert_eq!(
        state_after_second_slot.latest_block_header.state_root,
        expected_root
    );
}

#[test]
fn test_process_slots() {
    let genesis_state = genesis_state();
    let target_slot = Slot(5);

    let new_state = genesis_state.process_slots(target_slot).unwrap();

    assert_eq!(new_state.slot, target_slot);
    assert_eq!(
        new_state.latest_block_header.state_root,
        hash_tree_root(&genesis_state)
    );
}

#[test]
fn test_process_slots_backwards() {
    let genesis_state = genesis_state();
    let advanced_state = genesis_state.process_slots(Slot(5)).unwrap();

    let result = advanced_state.process_slots(Slot(4));
    assert!(result.is_err());
}

#[test]
fn test_process_block_header_valid() {
    let genesis_state = genesis_state();
    let mut state_at_slot_1 = genesis_state.process_slots(Slot(1)).unwrap();
    let genesis_header_root = hash_tree_root(&state_at_slot_1.latest_block_header);

    let block = create_block(1, &mut state_at_slot_1.latest_block_header, None).message;
    let new_state = state_at_slot_1.process_block_header(&block.block).unwrap();

    assert_eq!(new_state.latest_finalized.root, genesis_header_root);
    assert_eq!(new_state.latest_justified.root, genesis_header_root);
    assert_eq!(
        new_state.historical_block_hashes.get(0).ok(),
        Some(&genesis_header_root)
    );
    // After processing just the block header (no attestations), justified_slots 
    // uses relative indexing (slot X maps to index X - finalized_slot - 1).
    // With finalized_slot = 0 and no attestations to justify slot 1, 
    // justified_slots should be empty or all false.
    let justified_slot_1_relative = new_state
        .justified_slots
        .get(0) // relative index 0 = slot 1
        .map(|b| *b)
        .unwrap_or(false);
    // Slot 1 is NOT justified yet (no attestations have been processed)
    assert_eq!(justified_slot_1_relative, false);
    assert_eq!(new_state.latest_block_header.slot, Slot(1));
    assert_eq!(
        new_state.latest_block_header.state_root,
        Bytes32(ssz::H256::zero())
    );
}

#[rstest]
#[case(2, 1, None, "Block slot mismatch")]
#[case(1, 2, None, "Incorrect block proposer")]
#[case(1, 1, Some(Bytes32(ssz::H256::from_slice(&[0xde; 32]))), "Block parent root mismatch")]
fn test_process_block_header_invalid(
    #[case] bad_slot: u64,
    #[case] bad_proposer: u64,
    #[case] bad_parent_root: Option<Bytes32>,
    #[case] expected_error: &str,
) {
    let genesis_state = genesis_state();
    let state_at_slot_1 = genesis_state.process_slots(Slot(1)).unwrap();
    let parent_header = &state_at_slot_1.latest_block_header;
    let parent_root = hash_tree_root(parent_header);

    let block = Block {
        slot: Slot(bad_slot),
        proposer_index: ValidatorIndex(bad_proposer),
        parent_root: bad_parent_root.unwrap_or(parent_root),
        state_root: Bytes32(ssz::H256::zero()),
        body: BlockBody {
            attestations: List::default(),
        },
    };

    let result = state_at_slot_1.process_block_header(&block);

    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains(expected_error));
}
