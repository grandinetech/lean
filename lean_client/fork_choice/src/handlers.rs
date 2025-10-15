use std::collections::HashMap;
use containers::{Block, SignedVote, ValidatorIndex, Checkpoint};
use containers::block::hash_tree_root;
use crate::helpers::*;
use crate::store::{Store, ValidatorId};

/// Handle time progression in the protocol
pub fn on_tick(store: &mut Store, time: u64, has_proposal: bool) {
    let elapsed_intervals = time.saturating_sub(store.config.genesis_time)
        * store.config.intervals_per_slot / store.config.seconds_per_slot;

    while store.time < elapsed_intervals {
        let next_has_proposal = has_proposal && (store.time + 1 == elapsed_intervals);
        tick_interval(store, next_has_proposal);
    }
}

/// Process a new attestation/vote with validation
pub fn on_attestation(store: &mut Store, attestation: SignedVote, is_from_block: bool) {
    let validator_id = ValidatorId(ValidatorIndex(attestation.data.validator_id.0));
    // Clone the target checkpoint to avoid moving out of attestation
    let vote = attestation.data.target.clone();

    // Validate the attestation
    if !is_valid_attestation(store, &attestation) {
        return; // Ignore invalid attestations
    }

    if is_from_block {
        // Vote came from a block - update known votes immediately
        if should_update_vote(&store.latest_known_votes, &validator_id, &vote) {
            store.latest_known_votes.insert(validator_id, vote.clone());
        }

        // Remove from new votes if this is newer
        if let Some(existing) = store.latest_new_votes.get(&validator_id) {
            if existing.slot.0 < vote.slot.0 {
                store.latest_new_votes.remove(&validator_id);
            }
        }
    } else {
        // Vote came from gossip - validate timing
        let curr_slot = store.time / store.config.intervals_per_slot;

        // Reject votes that are too far in the future or past
        if vote.slot.0 > curr_slot || curr_slot.saturating_sub(vote.slot.0) > 32 {
            return;
        }

        // Reject votes for blocks we don't know about
        if !store.blocks.contains_key(&vote.root) {
            return;
        }

        if should_update_vote(&store.latest_new_votes, &validator_id, &vote) {
            store.latest_new_votes.insert(validator_id, vote);
        }
    }
}

/// Validate an attestation
fn is_valid_attestation(store: &Store, attestation: &SignedVote) -> bool {
    let vote_data = &attestation.data;

    // Check if validator ID is in valid range
    if vote_data.validator_id.0 >= store.config.num_validators {
        return false;
    }

    // Check if target block exists
    if !store.blocks.contains_key(&vote_data.target.root) {
        return false;
    }

    // Check if source is justified
    if vote_data.source.slot.0 > store.latest_justified.slot.0 {
        return false;
    }

    // Check slot consistency
    if let Some(target_block) = store.blocks.get(&vote_data.target.root) {
        if target_block.slot != vote_data.target.slot {
            return false;
        }
    }

    // Check that target comes after source
    if vote_data.target.slot.0 <= vote_data.source.slot.0 {
        return false;
    }

    true
}

/// Check if we should update a vote (newer or first vote)
fn should_update_vote(
    votes: &HashMap<ValidatorId, Checkpoint>,
    validator_id: &ValidatorId,
    new_vote: &Checkpoint
) -> bool {
    votes.get(validator_id)
        .map_or(true, |existing| existing.slot.0 < new_vote.slot.0)
}

/// Process a new block
pub fn on_block(store: &mut Store, block: Block) {
    let block_root = hash_tree_root(&block);

    // Skip if we already have this block
    if store.blocks.contains_key(&block_root) {
        return;
    }

    // Ensure we have the parent state
    assert!(
        store.states.contains_key(&block.parent_root),
        "Missing parent state for block"
    );

    let parent_state = store.states.get(&block.parent_root).unwrap().clone();
    let new_state = process_block(parent_state, &block);

    // Process attestations in the block
    let mut i: u64 = 0;
    loop {
        match block.body.attestations.get(i) {
            Ok(attestation) => {
                on_attestation(store, attestation.clone(), true);
                i += 1;
            },
            Err(_) => break,
        }
    }

    // Add block and state to store
    store.blocks.insert(block_root, block);
    store.states.insert(block_root, new_state);

    // Update the chain head
    update_head(store);
}