use fork_choice::helpers::{get_fork_choice_head, Store};
use ssz::H256;

use containers::{
    block::{hash_tree_root, Block, SignedBlock},
    checkpoint::Checkpoint,
    ssz,
    vote::SignedVote,
    Config, Root, Slot, ValidatorIndex,
};
use ssz_rs::prelude::*;
use std::collections::HashMap;

fn create_test_block(slot: u64, parent_root: Root, text: &str) -> (Root, SignedBlock) {
    let mut state_root_bytes = [0u8; 32];
    state_root_bytes[..text.len()].copy_from_slice(text.as_bytes());

    let block = Block {
        slot: Slot(slot),
        parent_root,
        state_root: Root(H256::from_slice(&state_root_bytes)),
        ..Default::default()
    };
    let root = hash_tree_root(&block);
    let signed_block = SignedBlock {
        message: block,
        ..Default::default()
    };
    (root, signed_block)
}

#[test]
fn test_fork_choice_single_vote() {
    let (genesis_root, genesis_block) = create_test_block(0, Root::default(), "genesis");
    let (block_a_root, block_a) = create_test_block(1, genesis_root, "block_a");
    let (block_b_root, block_b) = create_test_block(2, block_a_root, "block_b");

    let store = Store {
        blocks: HashMap::from([
            (genesis_root, genesis_block),
            (block_a_root, block_a),
            (block_b_root, block_b),
        ]),
        ..Default::default()
    };

    let votes = HashMap::from([(
        ValidatorIndex(0),
        Checkpoint {
            root: block_b_root,
            slot: Slot(2),
        },
    )]);

    let head = get_fork_choice_head(&store, genesis_root, &votes, 0);
    assert_eq!(head, block_b_root);
}

#[test]
fn test_fork_choice_with_multiple_forks() {
    let (genesis_root, genesis_block) = create_test_block(0, Root::default(), "genesis");
    let (block_a_root, block_a) = create_test_block(1, genesis_root, "block_a");
    let (block_b_root, block_b) = create_test_block(2, block_a_root, "block_b");
    let (block_c_root, block_c) = create_test_block(1, genesis_root, "block_c");
    let (block_d_root, block_d) = create_test_block(2, block_c_root, "block_d");

    let store = Store {
        blocks: HashMap::from([
            (genesis_root, genesis_block),
            (block_a_root, block_a),
            (block_b_root, block_b),
            (block_c_root, block_c),
            (block_d_root, block_d),
        ]),
        ..Default::default()
    };

    let votes = HashMap::from([
        (ValidatorIndex(0), Checkpoint { root: block_d_root, slot: Slot(2) }),
        (ValidatorIndex(1), Checkpoint { root: block_d_root, slot: Slot(2) }),
        (ValidatorIndex(2), Checkpoint { root: block_b_root, slot: Slot(2) }),
    ]);

    let head = get_fork_choice_head(&store, genesis_root, &votes, 0);
    assert_eq!(head, block_d_root);
}