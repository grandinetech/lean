use crate::store::*;
use containers::{attestation::Attestation, block::SignedBlockWithAttestation, ValidatorIndex};

#[inline]
pub fn on_tick(store: &mut Store, time: u64, _has_proposal: bool) {
    let elapsed_intervals =
        time.saturating_sub(store.config.genesis_time) * INTERVALS_PER_SLOT / SECONDS_PER_SLOT;
    if store.time < elapsed_intervals {
        store.time = elapsed_intervals;
    }
}

#[inline]
pub fn on_attestation(store: &mut Store, attestation: Attestation, is_from_block: bool) -> Result<(), String> {
    let key_vald = ValidatorIndex(attestation.validator_id.0);
    let vote = attestation.data.target;

    let curr_slot = store.time / INTERVALS_PER_SLOT;
    if vote.slot.0 > curr_slot {
        return Err(format!(
            "Attestation slot {} is in the future (current slot {})",
            vote.slot.0, curr_slot
        ));
    }

    if is_from_block {
        if store
            .latest_known_votes
            .get(&key_vald)
            .map_or(true, |v| v.slot < vote.slot)
        {
            store.latest_known_votes.insert(key_vald, vote);
        }
    } else {
        if store
            .latest_new_votes
            .get(&key_vald)
            .map_or(true, |v| v.slot < vote.slot)
        {
            store.latest_new_votes.insert(key_vald, vote);
        }
    }
    Ok(())
}

//update
pub fn on_block(store: &mut Store, signed_block: SignedBlockWithAttestation) -> Result<(), String> {
    let block_root = get_block_root(&signed_block);
    if store.blocks.contains_key(&block_root) {
        return Ok(());
    }
    let block = &signed_block.message.block;
    let root = block.parent_root;

    let block_time = block.slot.0 * INTERVALS_PER_SLOT;
    if store.time < block_time {
        store.time = block_time;
    }

    accept_new_votes(store);

    let attest = &block.body.attestations;
    for i in 0.. {
        match attest.get(i) {
            Ok(attest) => {
                on_attestation(store, attest.clone(), true)?;
            }
            Err(_) => break,
        }
    }

    on_attestation(
        store,
        signed_block.message.proposer_attestation.clone(),
        true,
    )?;

    // naujas
    let state = match store.states.get(&root) {
        Some(state) => state,
        None => {
            return Err("Err: (Fork-choice::Handlers::OnBlock)no parent state.".to_string());
        }
    };

    let mut new_state = state.state_transition_with_validation(signed_block.clone(), true, false)?;

    use containers::block::hash_tree_root as hash_root;
    let body_root = hash_root(&block.body);
    new_state.latest_block_header = containers::block::BlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root,
    };

    store.blocks.insert(block_root, signed_block.clone());
    store.states.insert(block_root, new_state);

    use containers::checkpoint::Checkpoint;
    let proposer_vote = Checkpoint {
        root: block_root,
        slot: block.slot,
    };
    let proposer_idx = block.proposer_index;

    if store
        .latest_new_votes
        .get(&proposer_idx)
        .map_or(true, |v| v.slot < proposer_vote.slot)
    {
        store.latest_new_votes.insert(proposer_idx, proposer_vote);
    }

    update_head(store);
    Ok(())
}
