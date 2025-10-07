use crate::helpers::*;
use containers::{
    block::{hash_tree_root, SignedBlock},
    vote::SignedVote,
    ValidatorIndex,
};

pub fn on_tick(store: &mut Store, time: u64, _has_proposal: bool) {
    let elapsed_intervals =
        time.saturating_sub(store.config.genesis_time) * INTERVALS_PER_SLOT / SECONDS_PER_SLOT;
    if store.time < elapsed_intervals {
        store.time = elapsed_intervals;
    }
}

pub fn on_attestation(store: &mut Store, attestation: SignedVote, is_from_block: bool) {
    let validator_id_uint64 = attestation.data.validator_id;
    let validator_key = ValidatorIndex(validator_id_uint64.0);
    let vote = attestation.data.target;

    let curr_slot = store.time / INTERVALS_PER_SLOT;
    if vote.slot.0 > curr_slot {
        return;
    }

    if is_from_block {
        if store
            .latest_known_votes
            .get(&validator_key)
            .map_or(true, |v| v.slot < vote.slot)
        {
            store.latest_known_votes.insert(validator_key, vote);
        }
    } else {
        if store
            .latest_new_votes
            .get(&validator_key)
            .map_or(true, |v| v.slot < vote.slot)
        {
            store.latest_new_votes.insert(validator_key, vote); 
        }
    }
}

pub fn on_block(store: &mut Store, signed_block: SignedBlock) {
    let block_root = hash_tree_root(&signed_block.message);
    if store.blocks.contains_key(&block_root) {
        return;
    }
    let parent_root = signed_block.message.parent_root;

    let parent_state = match store.states.get(&parent_root) {
        Some(state) => state,
        None => {
            panic!("Err: No parents, for block (can't process)");
        }
    };

    let new_state = parent_state.state_transition(signed_block.clone(), true);

    let attestations = &signed_block.message.body.attestations;
    let mut i = 0;
    loop {
        match attestations.get(i) {
            Ok(attestation) => {
                on_attestation(store, attestation.clone(), true);
                i += 1;
            }
            Err(_) => {
                break;
            }
        }
    }

    store.blocks.insert(block_root, signed_block);
    store.states.insert(block_root, new_state);

    update_head(store);
}
