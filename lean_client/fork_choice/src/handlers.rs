use crate::store::*;
use containers::SignatureKey;
use containers::{
    attestation::SignedAttestation, block::SignedBlockWithAttestation, Bytes32, ValidatorIndex,
};
use ssz::SszHash;

#[inline]
pub fn on_tick(store: &mut Store, time: u64, has_proposal: bool) {
    // Calculate target time in intervals
    let tick_interval_time = time.saturating_sub(store.config.genesis_time) / SECONDS_PER_INTERVAL;

    // Tick forward one interval at a time
    while store.time < tick_interval_time {
        // Check if proposal should be signaled for next interval
        let should_signal_proposal = has_proposal && (store.time + 1) == tick_interval_time;

        // Advance by one interval with appropriate signaling
        tick_interval(store, should_signal_proposal);
    }
}

#[inline]
pub fn on_attestation(
    store: &mut Store,
    signed_attestation: SignedAttestation,
    is_from_block: bool,
) -> Result<(), String> {
    let validator_id = ValidatorIndex(signed_attestation.validator_id);
    let attestation_slot = signed_attestation.message.slot;
    let source_slot = signed_attestation.message.source.slot;
    let target_slot = signed_attestation.message.target.slot;

    // Validate attestation is not from future
    let curr_slot = store.time / INTERVALS_PER_SLOT;
    if attestation_slot.0 > curr_slot {
        return Err(format!(
            "Err: (Fork-choice::Handlers::OnAttestation) Attestation for slot {} has not yet occurred, out of sync. (CURRENT SLOT NUMBER: {})",
            attestation_slot.0, curr_slot
        ));
    }

    // Validate source slot does not exceed target slot (per leanSpec validate_attestation)
    if source_slot > target_slot {
        return Err(format!(
            "Err: (Fork-choice::Handlers::OnAttestation) Source slot {} exceeds target slot {}",
            source_slot.0, target_slot.0
        ));
    }

    if is_from_block {
        // On-chain attestation processing - immediately becomes "known"
        if store
            .latest_known_attestations
            .get(&validator_id)
            .map_or(true, |existing| existing.message.slot < attestation_slot)
        {
            store
                .latest_known_attestations
                .insert(validator_id, signed_attestation.clone());
        }

        // Remove from new attestations if superseded
        if let Some(existing_new) = store.latest_new_attestations.get(&validator_id) {
            if existing_new.message.slot <= attestation_slot {
                store.latest_new_attestations.remove(&validator_id);
            }
        }
    } else {
        // Network gossip attestation processing - goes to "new" stage
        // Store signature for later aggregation during block building
        let data_root = signed_attestation.message.data_root_bytes();
        let sig_key = SignatureKey::new(signed_attestation.validator_id, data_root);
        store
            .gossip_signatures
            .insert(sig_key, signed_attestation.signature.clone());

        // Track attestation for fork choice
        if store
            .latest_new_attestations
            .get(&validator_id)
            .map_or(true, |existing| existing.message.slot < attestation_slot)
        {
            store
                .latest_new_attestations
                .insert(validator_id, signed_attestation);
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

    // Get parent state for validation
    let state = match store.states.get(&block.parent_root) {
        Some(state) => state,
        None => {
            return Err(
                "Err: (Fork-choice::Handlers::ProcessBlockInternal) No parent state.".to_string(),
            );
        }
    };

    // Execute state transition to get post-state
    let new_state = state.state_transition_with_validation(signed_block.clone(), true, true)?;

    // Store block and state
    store.blocks.insert(block_root, signed_block.clone());
    store.states.insert(block_root, new_state.clone());

    if new_state.latest_justified.slot > store.latest_justified.slot {
        store.latest_justified = new_state.latest_justified.clone();
    }
    if new_state.latest_finalized.slot > store.latest_finalized.slot {
        store.latest_finalized = new_state.latest_finalized.clone();
    }

    // Process block body attestations as on-chain (is_from_block=true)
    let signatures = &signed_block.signature;

    let aggregated_attestations = &signed_block.message.block.body.attestations;
    let proposer_attestation = &signed_block.message.proposer_attestation;

    // Store aggregated proofs for future block building
    // Each attestation_signature proof is indexed by (validator_id, data_root) for each participating validator
    for (att_idx, aggregated_attestation) in aggregated_attestations.into_iter().enumerate() {
        let data_root = aggregated_attestation.data.data_root_bytes();

        // Get the corresponding proof from attestation_signatures
        if let Ok(proof_data) = signatures.attestation_signatures.get(att_idx as u64) {
            // Store proof for each validator in the aggregation
            for (bit_idx, bit) in aggregated_attestation.aggregation_bits.0.iter().enumerate() {
                if *bit {
                    let validator_id = bit_idx as u64;
                    let sig_key = SignatureKey::new(validator_id, data_root);
                    store
                        .aggregated_payloads
                        .entry(sig_key)
                        .or_insert_with(Vec::new)
                        .push(proof_data.clone());
                }
            }
        }
    }

    // Process each aggregated attestation's validators for fork choice
    // Note: Signature verification is done in verify_signatures() before on_block()
    for aggregated_attestation in aggregated_attestations.into_iter() {
        let validator_ids: Vec<u64> = aggregated_attestation
            .aggregation_bits
            .0
            .iter()
            .enumerate()
            .filter(|(_, bit)| **bit)
            .map(|(index, _)| index as u64)
            .collect();

        // Each validator in the aggregation votes for this attestation data
        for validator_id in validator_ids {
            on_attestation(
                store,
                SignedAttestation {
                    validator_id,
                    message: aggregated_attestation.data.clone(),
                    // Use a default signature since verification already happened
                    signature: containers::Signature::default(),
                },
                true,
            )?;
        }
    }

    // Update head BEFORE processing proposer attestation
    update_head(store);

    let proposer_signed_attestation = SignedAttestation {
        validator_id: proposer_attestation.validator_id.0,
        message: proposer_attestation.data.clone(),
        signature: signed_block.signature.proposer_signature,
    };

    // Process proposer attestation as if received via gossip (is_from_block=false)
    // This ensures it goes to "new" attestations and doesn't immediately affect fork choice
    on_attestation(store, proposer_signed_attestation, false)?;

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
