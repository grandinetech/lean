//! Basic LMD-GHOST fork choice algorithm tests

use std::collections::HashMap;
use containers::*;
use containers::block::hash_tree_root;
use fork_choice::*;
use fork_choice::ValidatorId;
use pretty_assertions::assert_eq;

mod common;
use common::*;

/// Test fork choice algorithm with no votes
#[test]
fn test_fork_choice_no_votes() {
    let sample_blocks = create_sample_blocks();
    // Find the genesis block (slot 0)
    let (genesis_hash, _) = sample_blocks.iter()
        .find(|(_, block)| block.slot.0 == 0)
        .unwrap();
    let root_hash = *genesis_hash;

    let head = get_fork_choice_head(
        &sample_blocks,
        root_hash,
        &HashMap::new(), // No votes
        0,
    );

    // With no votes, we expect the algorithm to follow the longest chain
    // Since genesis -> block_a -> block_b is the longest, it should return block_b
    let (expected_head, _) = sample_blocks.iter()
        .max_by_key(|(_, block)| block.slot.0)
        .unwrap();
    assert_eq!(head, *expected_head);
}

/// Test fork choice algorithm with a single vote
#[test]
fn test_fork_choice_single_vote() {
    let sample_blocks = create_sample_blocks();
    // Find the genesis block (slot 0) and block at slot 2
    let (genesis_hash, _) = sample_blocks.iter()
        .find(|(_, block)| block.slot.0 == 0)
        .unwrap();
    let (target_hash, _) = sample_blocks.iter()
        .find(|(_, block)| block.slot.0 == 2)
        .unwrap();
    
    let root_hash = *genesis_hash;
    let target_hash = *target_hash;

    let mut votes = HashMap::new();
    votes.insert(
        ValidatorId(ValidatorIndex(0)),
        create_checkpoint(target_hash, 2),
    );

    let head = get_fork_choice_head(&sample_blocks, root_hash, &votes, 0);

    assert_eq!(head, target_hash);
}

/// Test fork choice algorithm tie-breaking mechanism
#[test]
fn test_fork_choice_tie_breaking() {
    let genesis = create_block(
        0, 0, zero_hash(), 
        b"genesis\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let genesis_hash = hash_tree_root(&genesis);

    // Create two competing blocks at same slot
    let block_a = create_block(
        1, 1, genesis_hash,
        b"block_a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_a_hash = hash_tree_root(&block_a);

    let block_b = create_block(
        1, 2, genesis_hash,
        b"block_b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_b_hash = hash_tree_root(&block_b);

    let blocks = HashMap::from([
        (genesis_hash, genesis),
        (block_a_hash, block_a),
        (block_b_hash, block_b),
    ]);

    // No votes - algorithm should pick one of the children consistently
    let head = get_fork_choice_head(&blocks, genesis_hash, &HashMap::new(), 0);

    // Should return one of the child blocks (not genesis) since both are at the same slot
    assert!(head == block_a_hash || head == block_b_hash);
    
    // Test determinism - should always return the same choice
    let head2 = get_fork_choice_head(&blocks, genesis_hash, &HashMap::new(), 0);
    assert_eq!(head, head2);
}

/// Test fork choice algorithm with competing votes
#[test]
fn test_fork_choice_competing_votes() {
    // Create simple fork: genesis -> A
    //                             -> B
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
        1, 2, genesis_hash,
        b"block_b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let block_b_hash = hash_tree_root(&block_b);

    let blocks = HashMap::from([
        (genesis_hash, genesis),
        (block_a_hash, block_a),
        (block_b_hash, block_b),
    ]);

    // Equal votes for both forks
    let mut votes = HashMap::new();
    votes.insert(ValidatorId(ValidatorIndex(0)), create_checkpoint(block_a_hash, 1));
    votes.insert(ValidatorId(ValidatorIndex(1)), create_checkpoint(block_b_hash, 1));

    let head = get_fork_choice_head(&blocks, genesis_hash, &votes, 0);

    // Should choose one consistently (lexicographically by hash)
    assert!(head == block_a_hash || head == block_b_hash);
}

/// Test fork choice algorithm with minimum score threshold
#[test]
fn test_fork_choice_with_min_score() {
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

    let blocks = HashMap::from([
        (genesis_hash, genesis),
        (block_a_hash, block_a),
    ]);

    // Single vote shouldn't meet min_score of 2
    let mut votes = HashMap::new();
    votes.insert(ValidatorId(ValidatorIndex(0)), create_checkpoint(block_a_hash, 1));

    let head = get_fork_choice_head(
        &blocks,
        genesis_hash,
        &votes,
        2, // Require at least 2 votes
    );

    // Should fall back to root when min_score not met
    assert_eq!(head, genesis_hash);
}