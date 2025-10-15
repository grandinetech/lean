//! Fork choice tests with multiple competing chains

use std::collections::HashMap;
use containers::*;
use containers::block::hash_tree_root;
use fork_choice::*;
use fork_choice::ValidatorId;
use pretty_assertions::assert_eq;

mod common;
use common::*;

/// Test fork choice algorithm with competing forks
#[test]
fn test_fork_choice_with_multiple_forks() {
    // Create a fork structure: genesis -> A -> B
    //                                  -> C -> D
    let genesis = create_block(
        0, 0, zero_hash(),
        b"genesis\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let genesis_hash = hash_tree_root(&genesis);

    // Fork 1: A -> B
    let block_a = create_block(
        1, 1, genesis_hash,
        b"block_a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_a_hash = hash_tree_root(&block_a);

    let block_b = create_block(
        2, 2, block_a_hash,
        b"block_b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_b_hash = hash_tree_root(&block_b);

    // Fork 2: C -> D
    let block_c = create_block(
        1, 3, genesis_hash,
        b"block_c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_c_hash = hash_tree_root(&block_c);

    let block_d = create_block(
        2, 4, block_c_hash,
        b"block_d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_d_hash = hash_tree_root(&block_d);

    let blocks = HashMap::from([
        (genesis_hash, genesis),
        (block_a_hash, block_a),
        (block_b_hash, block_b),
        (block_c_hash, block_c),
        (block_d_hash, block_d),
    ]);

    // More votes for fork 2 (C->D)
    let mut votes = HashMap::new();
    votes.insert(ValidatorId(ValidatorIndex(0)), create_checkpoint(block_d_hash, 2));
    votes.insert(ValidatorId(ValidatorIndex(1)), create_checkpoint(block_d_hash, 2));
    votes.insert(ValidatorId(ValidatorIndex(2)), create_checkpoint(block_b_hash, 2)); // Single vote for fork 1

    let head = get_fork_choice_head(&blocks, genesis_hash, &votes, 0);

    // Fork 2 should win with 2 votes vs 1
    assert_eq!(head, block_d_hash);
}

/// Test that votes for ancestors are properly counted
#[test]
fn test_fork_choice_ancestor_votes() {
    // Create chain: genesis -> A -> B -> C
    let genesis = create_block(
        0, 0, zero_hash(),
        b"genesis\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let genesis_hash = hash_tree_root(&genesis);

    let block_a = create_block(
        1, 1, genesis_hash,
        b"block_a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_a_hash = hash_tree_root(&block_a);

    let block_b = create_block(
        2, 2, block_a_hash,
        b"block_b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_b_hash = hash_tree_root(&block_b);

    let block_c = create_block(
        3, 3, block_b_hash,
        b"block_c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_c_hash = hash_tree_root(&block_c);

    let blocks = HashMap::from([
        (genesis_hash, genesis),
        (block_a_hash, block_a),
        (block_b_hash, block_b),
        (block_c_hash, block_c),
    ]);

    // Vote for ancestor should still find the head
    let mut votes = HashMap::new();
    votes.insert(ValidatorId(ValidatorIndex(0)), create_checkpoint(block_a_hash, 1));

    let head = get_fork_choice_head(&blocks, genesis_hash, &votes, 0);

    // Should follow chain to the end
    assert_eq!(head, block_c_hash);
}

/// Test fork choice algorithm with a deeper chain
#[test]
fn test_fork_choice_deep_chain() {
    let mut blocks = HashMap::new();
    let mut prev_hash = zero_hash();

    // Create a 10-block chain
    for i in 0..10 {
        let state_data = format!("block{}", i);
        let mut state_bytes = [0u8; 32];
        let state_data_bytes = state_data.as_bytes();
        let len = state_data_bytes.len().min(32);
        state_bytes[..len].copy_from_slice(&state_data_bytes[..len]);

        let block = create_block(i, i, prev_hash, &state_bytes);
        let block_hash = hash_tree_root(&block);
        blocks.insert(block_hash, block);
        prev_hash = block_hash;
    }

    // Vote for the head block
    let head_hash = prev_hash;
    let mut votes = HashMap::new();
    votes.insert(ValidatorId(ValidatorIndex(0)), create_checkpoint(head_hash, 9));

    // Should find the head
    let genesis_hash = *blocks
        .iter()
        .min_by_key(|(_, block)| block.slot.0)
        .map(|(hash, _)| hash)
        .unwrap();

    let result = get_fork_choice_head(&blocks, genesis_hash, &votes, 0);

    assert_eq!(result, head_hash);
}