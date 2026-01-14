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
    let justified_slot_0 = new_state
        .justified_slots
        .get(0)
        .map(|b| *b)
        .unwrap_or(false);
    assert_eq!(justified_slot_0, true);
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

// This test verifies that attestations correctly justify and finalize slots
#[cfg(feature = "devnet1")]
#[test]
fn test_process_attestations_justification_and_finalization() {
    let mut state = genesis_state();

    // Process slot 1 and block
    let mut state_at_slot_1 = state.process_slots(Slot(1)).unwrap();
    let block1 = create_block(1, &mut state_at_slot_1.latest_block_header, None);
    // Use process_block_header and process_operations separately to avoid state root validation
    let state_after_header1 = state_at_slot_1
        .process_block_header(&block1.message.block)
        .unwrap();
    state = state_after_header1.process_attestations(&block1.message.block.body.attestations);

    // Process slot 4 and block
    let mut state_at_slot_4 = state.process_slots(Slot(4)).unwrap();
    let block4 = create_block(4, &mut state_at_slot_4.latest_block_header, None);
    let state_after_header4 = state_at_slot_4
        .process_block_header(&block4.message.block)
        .unwrap();
    state = state_after_header4.process_attestations(&block4.message.block.body.attestations);

    // Advance to slot 5
    state = state.process_slots(Slot(5)).unwrap();

    let genesis_checkpoint = Checkpoint {
        root: *state.historical_block_hashes.get(0).unwrap(),
        slot: Slot(0),
    };

    let checkpoint4 = Checkpoint {
        root: hash_tree_root(&state.latest_block_header),
        slot: Slot(4),
    };

    let attestations_for_4: Vec<Attestation> = (0..7)
        .map(|i| Attestation {
            validator_id: Uint64(i),
            data: AttestationData {
                slot: Slot(4),
                head: checkpoint4.clone(),
                target: checkpoint4.clone(),
                source: genesis_checkpoint.clone(),
            },
        })
        .collect();

    // Convert Vec to PersistentList
    let mut attestations_list: List<_, U4096> = List::default();
    for a in attestations_for_4 {
        attestations_list.push(a).unwrap();
    }

    let new_state = state.process_attestations(&attestations_list);

    assert_eq!(new_state.latest_justified, checkpoint4);
    let justified_slot_4 = new_state
        .justified_slots
        .get(4)
        .map(|b| *b)
        .unwrap_or(false);
    assert_eq!(justified_slot_4, true);
    assert_eq!(new_state.latest_finalized, genesis_checkpoint);
    assert!(!new_state
        .get_justifications()
        .contains_key(&checkpoint4.root));
}
