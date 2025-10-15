//! Store integration tests for fork choice

use containers::*;
use containers::block::hash_tree_root;
use fork_choice::*;
use fork_choice::store::ValidatorId;
use pretty_assertions::assert_eq;

mod common;
use common::*;

/// Test Store.get_proposal_head with no votes
#[test]
fn test_store_fork_choice_no_votes() {
    let config = test_config();

    let genesis_block = create_block(
        0, 0, zero_hash(),
        b"genesis\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let genesis_hash = hash_tree_root(&genesis_block);

    let finalized = create_checkpoint(genesis_hash, 0);

    let mut genesis_state = State::generate_genesis(Uint64(1000), Uint64(100));
    genesis_state.latest_justified = finalized.clone();
    genesis_state.latest_finalized = finalized.clone();

    let mut store = Store::new(genesis_state, genesis_block, config);

    // Get proposal head for slot 0
    let head = store.get_proposal_head(Slot(0));

    // Should return current head
    assert_eq!(head, store.head);
}

/// Test Store with block processing
#[test]
fn test_store_block_processing() {
    let config = test_config();

    let genesis_block = create_block(
        0, 0, zero_hash(),
        b"genesis\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let genesis_hash = hash_tree_root(&genesis_block);

    let finalized = create_checkpoint(genesis_hash, 0);
    let mut genesis_state = State::generate_genesis(Uint64(1000), Uint64(100));
    genesis_state.latest_justified = finalized.clone();
    genesis_state.latest_finalized = finalized.clone();

    let mut store = Store::new(genesis_state.clone(), genesis_block, config);

    // Create a new block
    let new_block = create_block(
        1, 1, genesis_hash,
        b"block_1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let new_block_hash = hash_tree_root(&new_block);

    // Process the new block
    crate::handlers::on_block(&mut store, new_block);

    // Verify the block was added
    assert!(store.blocks.contains_key(&new_block_hash));
    assert!(store.states.contains_key(&new_block_hash));

    // The head should now be the new block (longest chain)
    assert_eq!(store.head, new_block_hash);
}

/// Test Store with attestation processing
#[test]
fn test_store_attestation_processing() {
    let config = test_config();

    let genesis_block = create_block(
        0, 0, zero_hash(),
        b"genesis\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let genesis_hash = hash_tree_root(&genesis_block);

    let finalized = create_checkpoint(genesis_hash, 0);
    let mut genesis_state = State::generate_genesis(Uint64(1000), Uint64(100));
    genesis_state.latest_justified = finalized.clone();
    genesis_state.latest_finalized = finalized.clone();

    let mut store = Store::new(genesis_state, genesis_block, config);

    // Create a new block at slot 1 to serve as target
    let mut block1_bytes = [0u8; 32];
    let label = b"block1"; // 6 bytes
    block1_bytes[..label.len()].copy_from_slice(label);
    let block1 = create_block(
        1, 1, genesis_hash,
        &block1_bytes
    );
    let block1_hash = hash_tree_root(&block1);
    store.blocks.insert(block1_hash, block1.clone());
    // mimic having processed state for block1
    store.states.insert(block1_hash, store.states.get(&genesis_hash).unwrap().clone());

    // Advance time to slot 1 so the vote is timely
    let slot1_time = store.config.genesis_time + store.config.seconds_per_slot; // slot 1 start
    crate::handlers::on_tick(&mut store, slot1_time, false);

    // Create a vote/attestation referencing the new block
    let vote_data = Vote {
        validator_id: Uint64(0),
        slot: Slot(1),
        head: create_checkpoint(block1_hash, 1),
        target: create_checkpoint(block1_hash, 1),
        source: create_checkpoint(genesis_hash, 0),
    };

    let signed_vote = SignedVote {
        data: vote_data,
        signature: zero_hash(),
    };

    // Process the attestation from gossip (should be valid now)
    crate::handlers::on_attestation(&mut store, signed_vote, false);

    // Verify the vote was added to new votes
    assert!(store.latest_new_votes.contains_key(&ValidatorId(ValidatorIndex(0))));
}

/// Test Store timing and intervals
#[test]
fn test_store_timing() {
    let config = test_config();

    let genesis_block = create_block(
        0, 0, zero_hash(),
        b"genesis\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    let genesis_hash = hash_tree_root(&genesis_block);

    let finalized = create_checkpoint(genesis_hash, 0);
    let mut genesis_state = State::generate_genesis(Uint64(1000), Uint64(100));
    genesis_state.latest_justified = finalized.clone();
    genesis_state.latest_finalized = finalized.clone();

    let mut store = Store::new(genesis_state, genesis_block, config);

    let initial_time = store.time;

    // Advance time by calling on_tick - time is in absolute seconds since genesis
    let new_time = store.config.genesis_time + 12; // 12 seconds after genesis
    crate::handlers::on_tick(&mut store, new_time, false);

    // Time should have advanced
    assert!(store.time > initial_time);
}