//! State basic tests for devnet2 format
//!
//! Tests for genesis generation, proposer selection, slot rules, and hash tree root.

use containers::{Block, BlockBody, Slot, State};
// tests/state_basic.rs
use pretty_assertions::assert_eq;

#[path = "common.rs"]
mod common;
use common::sample_config;
use ssz::{H256, SszHash};

#[test]
fn test_generate_genesis() {
    let config = sample_config();
    let state = State::generate_genesis(config.genesis_time, 4);

    assert_eq!(state.config, config);
    assert_eq!(state.slot.0, 0);

    let empty_body = BlockBody {
        attestations: ssz::PersistentList::default(),
    };
    assert_eq!(
        state.latest_block_header.body_root,
        empty_body.hash_tree_root()
    );

    // Check that collections are empty by trying to get the first element
    assert!(state.historical_block_hashes.get(0).is_err());
    assert!(state.justified_slots.get(0).is_none());
    assert!(state.justifications_roots.get(0).is_err());
    assert!(state.justifications_validators.get(0).is_none());
}

#[test]
fn test_proposer_round_robin() {
    let state = State::generate_genesis(0, 4);
    assert!(state.is_proposer(0));
}

#[test]
fn test_slot_justifiability_rules() {
    assert!(Slot(1).is_justifiable_after(Slot(0)));
    assert!(Slot(9).is_justifiable_after(Slot(0))); // perfect square
    assert!(Slot(6).is_justifiable_after(Slot(0))); // pronic (2*3)
}

#[test]
fn test_hash_tree_root() {
    let body = BlockBody {
        attestations: ssz::PersistentList::default(),
    };
    let block = Block {
        slot: Slot(1),
        proposer_index: 0,
        parent_root: H256::zero(),
        state_root: H256::zero(),
        body,
    };

    let root = block.hash_tree_root();
    assert_ne!(root, H256::zero());
}
