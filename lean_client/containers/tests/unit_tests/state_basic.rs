//! State basic tests for devnet2 format
//!
//! Tests for genesis generation, proposer selection, slot rules, and hash tree root.

// tests/state_basic.rs
use containers::{
    block::{hash_tree_root, BlockBody},
    state::State,
    types::Uint64,
    ValidatorIndex,
};
use pretty_assertions::assert_eq;

#[path = "common.rs"]
mod common;
use common::sample_config;

#[test]
fn test_generate_genesis() {
    let config = sample_config();
    let state = State::generate_genesis(Uint64(config.genesis_time), Uint64(4));

    assert_eq!(state.config, config);
    assert_eq!(state.slot.0, 0);

    let empty_body = BlockBody {
        attestations: ssz::PersistentList::default(),
    };
    assert_eq!(
        state.latest_block_header.body_root,
        hash_tree_root(&empty_body)
    );

    // Check that collections are empty by trying to get the first element
    assert!(state.historical_block_hashes.get(0).is_err());
    assert!(state.justified_slots.get(0).is_none());
    assert!(state.justifications_roots.get(0).is_err());
    assert!(state.justifications_validators.get(0).is_none());
}

#[test]
fn test_proposer_round_robin() {
    let state = State::generate_genesis(Uint64(0), Uint64(4));
    assert!(state.is_proposer(containers::types::ValidatorIndex(0)));
}

#[test]
fn test_slot_justifiability_rules() {
    use containers::slot::Slot;

    assert!(Slot(1).is_justifiable_after(Slot(0)));
    assert!(Slot(9).is_justifiable_after(Slot(0))); // perfect square
    assert!(Slot(6).is_justifiable_after(Slot(0))); // pronic (2*3)
}

#[test]
fn test_hash_tree_root() {
    let body = BlockBody {
        attestations: ssz::PersistentList::default(),
    };
    let block = containers::block::Block {
        slot: containers::slot::Slot(1),
        proposer_index: ValidatorIndex(0),
        parent_root: containers::types::Bytes32(ssz::H256::zero()),
        state_root: containers::types::Bytes32(ssz::H256::zero()),
        body,
    };

    let root = hash_tree_root(&block);
    assert_ne!(root, containers::types::Bytes32(ssz::H256::zero()));
}
