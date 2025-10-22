/*
 * AI Slop tests
 *
 */

mod test_functions;
use test_functions::*;

use fork_choice::{
    handlers::{on_attestation, on_block, on_tick},
    helpers::{get_forkchoice_store, SECONDS_PER_SLOT},
};

use containers::{
    block::{hash_tree_root, BlockHeader},
    vote::{SignedVote, Vote},
    Root, State, Uint64, ValidatorIndex,
};

#[test]
fn test_store_block_processing_updates_head() {
    let config = config_with_validators(10);
    let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");

    let mut genesis_state = State::default();
    genesis_state.config = config.clone();
    genesis_state.latest_block_header = BlockHeader {
        slot: genesis_block.message.slot,
        proposer_index: genesis_block.message.proposer_index,
        parent_root: genesis_block.message.parent_root,
        state_root: genesis_block.message.state_root,
        body_root: hash_tree_root(&genesis_block.message.body),
    };
    genesis_state.latest_finalized = build_checkpoint(genesis_root, 0);
    genesis_state.latest_justified = build_checkpoint(genesis_root, 0);

    let mut store = get_forkchoice_store(genesis_state.clone(), genesis_block, config);

    let (new_block_root, new_block) = build_valid_test_block(
        1,
        genesis_root,
        &genesis_state,
        ValidatorIndex(1),
        "block_1",
    );
    on_block(&mut store, new_block);

    assert!(store.blocks.contains_key(&new_block_root));
    assert!(store.states.contains_key(&new_block_root));
    assert_eq!(store.head, new_block_root);
}

#[test]
fn test_store_attestation_processing() {
    let config = config_with_validators(10);
    let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");
    let mut genesis_state = State::default();
    genesis_state.config = config.clone();
    genesis_state.latest_block_header = BlockHeader {
        slot: genesis_block.message.slot,
        proposer_index: genesis_block.message.proposer_index,
        parent_root: genesis_block.message.parent_root,
        state_root: genesis_block.message.state_root,
        body_root: hash_tree_root(&genesis_block.message.body),
    };
    genesis_state.latest_finalized = build_checkpoint(genesis_root, 0);
    genesis_state.latest_justified = build_checkpoint(genesis_root, 0);

    let mut store = get_forkchoice_store(genesis_state, genesis_block.clone(), config);

    // 1 VOTE
    let (block1_root, block1) = build_test_block(1, genesis_root, "block_1");
    store.blocks.insert(block1_root, block1);

    store.states.insert(
        block1_root,
        store.states.get(&genesis_root).unwrap().clone(),
    );

    let slot1_time_seconds = store.config.genesis_time + SECONDS_PER_SLOT;
    on_tick(&mut store, slot1_time_seconds, false);

    let vote_data = Vote {
        validator_id: Uint64(0),
        target: build_checkpoint(block1_root, 1),
        ..Default::default()
    };
    let signed_vote = SignedVote {
        data: vote_data,
        ..Default::default()
    };
    on_attestation(&mut store, signed_vote, false);

    assert!(store.latest_new_votes.contains_key(&ValidatorIndex(0)));
}

#[test]
fn test_store_timing_advances() {
    let config = config_with_validators(10);
    let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");
    let mut genesis_state = State::default();
    genesis_state.config = config.clone();
    genesis_state.latest_block_header = BlockHeader {
        slot: genesis_block.message.slot,
        proposer_index: genesis_block.message.proposer_index,
        parent_root: genesis_block.message.parent_root,
        state_root: genesis_block.message.state_root,
        body_root: hash_tree_root(&genesis_block.message.body),
    };
    genesis_state.latest_finalized = build_checkpoint(genesis_root, 0);
    genesis_state.latest_justified = build_checkpoint(genesis_root, 0);

    let mut store = get_forkchoice_store(genesis_state, genesis_block, config);
    let initial_time = store.time;

    let new_time_seconds = store.config.genesis_time + 12;
    on_tick(&mut store, new_time_seconds, false);

    assert!(store.time > initial_time);
    assert_eq!(store.time, 8);
}
