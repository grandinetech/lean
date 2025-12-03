use crate::store::*;
use containers::{
    attestation::Attestation, block::SignedBlockWithAttestation, Bytes32, ValidatorIndex,
};
use ssz::SszHash;

#[inline]
pub fn on_tick(store: &mut Store, time: u64, _has_proposal: bool) {
    let elapsed_intervals =
        time.saturating_sub(store.config.genesis_time) * INTERVALS_PER_SLOT / SECONDS_PER_SLOT;
    if store.time < elapsed_intervals {
        store.time = elapsed_intervals;
    }
}

#[inline]
pub fn on_attestation(
    store: &mut Store,
    attestation: Attestation,
    is_from_block: bool,
) -> Result<(), String> {
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

pub fn on_block(store: &mut Store, signed_block: SignedBlockWithAttestation) -> Result<(), String> {
    let block_root = Bytes32(signed_block.message.block.hash_tree_root());

    if store.blocks.contains_key(&block_root) {
        return Ok(());
    }

    let parent_root = signed_block.message.block.parent_root;

    if !store.states.contains_key(&parent_root) && !parent_root.0.is_zero() {
        store
            .blocks_queue
            .entry(parent_root)
            .or_insert_with(Vec::new)
            .push(signed_block);
        return Err(format!(
            "Err: (Fork-choice::Handlers::OnBlock) Block queued: parent {:?} not yet available (pending: {} blocks)",
            &parent_root.0.as_bytes()[..4],
            store.blocks_queue.values().map(|v| v.len()).sum::<usize>()
        ));
    }

    process_block_internal(store, signed_block, block_root)?;
    process_pending_blocks(store, vec![block_root]);

    Ok(())
}

fn process_block_internal(
    store: &mut Store,
    signed_block: SignedBlockWithAttestation,
    block_root: Bytes32,
) -> Result<(), String> {
    let block = &signed_block.message.block;

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

    let state = match store.states.get(&block.parent_root) {
        Some(state) => state,
        None => {
            return Err(
                "Err: (Fork-choice::Handlers::ProcesBlockInternal)No parent state.".to_string(),
            );
        }
    };

    let mut new_state =
        state.state_transition_with_validation(signed_block.clone(), true, false)?;

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

fn process_pending_blocks(store: &mut Store, mut roots: Vec<Bytes32>) {
    while let Some(parent_root) = roots.pop() {
        if let Some(purgatory) = store.blocks_queue.remove(&parent_root) {
            for block in purgatory {
                let block_origins = Bytes32(block.message.block.hash_tree_root());
                if let Ok(()) = process_block_internal(store, block, block_origins) {
                    roots.push(block_origins);
                }
            }
        }
    }
}
