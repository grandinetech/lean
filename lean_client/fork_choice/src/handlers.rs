use anyhow::{Result, anyhow, bail, ensure};
use containers::{AttestationData, SignatureKey, SignedAttestation, SignedBlockWithAttestation};
use ssz::{H256, SszHash};

use crate::store::{INTERVALS_PER_SLOT, SECONDS_PER_INTERVAL, Store, tick_interval, update_head};

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

/// 1. The blocks voted for must exist in our store.
/// 2. A vote cannot span backwards in time (source > target).
/// 3. A vote cannot be for a future slot.
/// 4. Checkpoint slots must match block slots.
fn validate_attestation_data(store: &Store, data: &AttestationData) -> Result<()> {
    // Cannot count a vote if we haven't seen the blocks involved
    ensure!(
        store.blocks.contains_key(&data.source.root),
        "Unknown source block: {:?}",
        data.source.root
    );

    ensure!(
        store.blocks.contains_key(&data.target.root),
        "Unknown target block: {:?}",
        &data.target.root
    );

    ensure!(
        store.blocks.contains_key(&data.head.root),
        "Unknown head block: {:?}",
        &data.head.root
    );

    // Source must be older than Target.
    ensure!(
        data.source.slot <= data.target.slot,
        "Source checkpoint slot {} must not exceed target slot {}",
        data.source.slot.0,
        data.target.slot.0
    );

    // Validate checkpoint slots match block slots
    // Per devnet-2, store.blocks now contains Block (not SignedBlockWithAttestation)
    let source_block = &store.blocks[&data.source.root];
    let target_block = &store.blocks[&data.target.root];

    ensure!(
        source_block.slot == data.source.slot,
        "Source checkpoint slot mismatch: checkpoint {} vs block {}",
        data.source.slot.0,
        source_block.slot.0
    );

    ensure!(
        target_block.slot == data.target.slot,
        "Target checkpoint slot mismatch: checkpoint {} vs block {}",
        data.target.slot.0,
        target_block.slot.0
    );

    // Validate attestation is not too far in the future
    // We allow a small margin for clock disparity (1 slot), but no further.
    let current_slot = store.time / INTERVALS_PER_SLOT;

    ensure!(
        data.slot.0 <= current_slot + 1,
        "Attestation too far in future: attestation slot {} > current slot {} + 1",
        data.slot.0,
        current_slot
    );

    Ok(())
}

/// Process a signed attestation received via gossip network
///
/// 1. Validates the attestation data
/// 2. Stores the signature in the gossip signature map
/// 3. Processes the attestation data via on_attestation
///
#[inline]
pub fn on_gossip_attestation(
    store: &mut Store,
    signed_attestation: SignedAttestation,
) -> Result<()> {
    let validator_id = signed_attestation.validator_id;
    let attestation_data = signed_attestation.message.clone();

    // Validate the attestation data first
    validate_attestation_data(store, &attestation_data)?;

    // Store signature for later lookup during block building
    let data_root = attestation_data.hash_tree_root();
    let sig_key = SignatureKey::new(signed_attestation.validator_id, data_root);
    store
        .gossip_signatures
        .insert(sig_key, signed_attestation.signature);

    // Process the attestation data (not from block)
    on_attestation_internal(store, validator_id, attestation_data, false)
}

/// Process an attestation and place it into the correct attestation stage
///
/// Attestation processing logic that updates the attestation
/// maps used for fork choice. Per devnet-2, we store AttestationData only (not signatures).
///
/// Attestations can come from:
/// - a block body (on-chain, `is_from_block=True`), or
/// - the gossip network (off-chain, `is_from_block=False`).
#[inline]
pub fn on_attestation(
    store: &mut Store,
    signed_attestation: SignedAttestation,
    is_from_block: bool,
) -> Result<()> {
    let validator_id = signed_attestation.validator_id;
    let attestation_data = signed_attestation.message.clone();

    // Validate attestation data
    validate_attestation_data(store, &attestation_data)?;

    if !is_from_block {
        // Store signature for later aggregation during block building
        let data_root = attestation_data.hash_tree_root();
        let sig_key = SignatureKey::new(signed_attestation.validator_id, data_root);
        store
            .gossip_signatures
            .insert(sig_key, signed_attestation.signature);
    }

    on_attestation_internal(store, validator_id, attestation_data, is_from_block)
}

/// Internal attestation processing - stores AttestationData
fn on_attestation_internal(
    store: &mut Store,
    validator_id: u64,
    attestation_data: AttestationData,
    is_from_block: bool,
) -> Result<()> {
    let attestation_slot = attestation_data.slot;

    if is_from_block {
        // On-chain attestation processing
        if store
            .latest_known_attestations
            .get(&validator_id)
            .map_or(true, |existing| existing.slot < attestation_slot)
        {
            store
                .latest_known_attestations
                .insert(validator_id, attestation_data);
        }

        // Remove from new attestations if superseded
        if let Some(existing_new) = store.latest_new_attestations.get(&validator_id) {
            if existing_new.slot <= attestation_slot {
                store.latest_new_attestations.remove(&validator_id);
            }
        }
    } else {
        // Network gossip attestation processing - goes to "new" stage
        if store
            .latest_new_attestations
            .get(&validator_id)
            .map_or(true, |existing| existing.slot < attestation_slot)
        {
            store
                .latest_new_attestations
                .insert(validator_id, attestation_data);
        }
    }
    Ok(())
}

/// Process a new block and update the forkchoice state
///
/// 1. Validating the block's parent exists
/// 2. Computing the post-state via the state transition function
/// 3. Processing attestations included in the block body (on-chain)
/// 4. Updating the forkchoice head
/// 5. Processing the proposer's attestation (as if gossiped)
pub fn on_block(store: &mut Store, signed_block: SignedBlockWithAttestation) -> Result<()> {
    let block_root = signed_block.message.block.hash_tree_root();

    if store.blocks.contains_key(&block_root) {
        return Ok(());
    }

    let parent_root = signed_block.message.block.parent_root;

    if !store.states.contains_key(&parent_root) && !parent_root.is_zero() {
        store
            .blocks_queue
            .entry(parent_root)
            .or_insert_with(Vec::new)
            .push(signed_block);
        bail!(
            "Err: (Fork-choice::Handlers::OnBlock) Block queued: parent {:?} not yet available (pending: {} blocks)",
            &parent_root.as_bytes()[..4],
            store.blocks_queue.values().map(|v| v.len()).sum::<usize>()
        );
    }

    process_block_internal(store, signed_block, block_root)?;
    process_pending_blocks(store, vec![block_root]);

    Ok(())
}

fn process_block_internal(
    store: &mut Store,
    signed_block: SignedBlockWithAttestation,
    block_root: H256,
) -> Result<()> {
    let block = signed_block.message.block.clone();
    let attestations_count = block.body.attestations.len_u64();

    // Get parent state for validation
    let state = store
        .states
        .get(&block.parent_root)
        .ok_or(anyhow!("no parent state"))?;

    // Debug: Log parent state checkpoints before transition
    tracing::debug!(
        block_slot = block.slot.0,
        attestations_in_block = attestations_count,
        parent_justified_slot = state.latest_justified.slot.0,
        parent_finalized_slot = state.latest_finalized.slot.0,
        justified_slots_len = state.justified_slots.len(),
        "Processing block - parent state info"
    );

    // Execute state transition to get post-state
    let new_state = state.state_transition_with_validation(signed_block.clone(), true, true)?;

    // Debug: Log new state checkpoints after transition
    tracing::debug!(
        block_slot = block.slot.0,
        new_justified_slot = new_state.latest_justified.slot.0,
        new_finalized_slot = new_state.latest_finalized.slot.0,
        new_justified_slots_len = new_state.justified_slots.len(),
        "Block processed - new state info"
    );

    // Store block and state, store the plain Block (not SignedBlockWithAttestation)
    store.blocks.insert(block_root, block.clone());
    store.states.insert(block_root, new_state.clone());

    let justified_updated = new_state.latest_justified.slot > store.latest_justified.slot;
    let finalized_updated = new_state.latest_finalized.slot > store.latest_finalized.slot;

    if justified_updated {
        tracing::info!(
            old_justified = store.latest_justified.slot.0,
            new_justified = new_state.latest_justified.slot.0,
            "Store justified checkpoint updated!"
        );
        store.latest_justified = new_state.latest_justified.clone();
    }
    if finalized_updated {
        tracing::info!(
            old_finalized = store.latest_finalized.slot.0,
            new_finalized = new_state.latest_finalized.slot.0,
            "Store finalized checkpoint updated!"
        );
        store.latest_finalized = new_state.latest_finalized.clone();
    }

    if !justified_updated && !finalized_updated {
        tracing::debug!(
            block_slot = block.slot.0,
            store_justified = store.latest_justified.slot.0,
            store_finalized = store.latest_finalized.slot.0,
            state_justified = new_state.latest_justified.slot.0,
            state_finalized = new_state.latest_finalized.slot.0,
            "No checkpoint updates from this block"
        );
    }

    // Process block body attestations as on-chain (is_from_block=true)
    let signatures = &signed_block.signature;
    let aggregated_attestations = &block.body.attestations;
    let proposer_attestation = &signed_block.message.proposer_attestation;

    // Store aggregated proofs for future block building
    // Each attestation_signature proof is indexed by (validator_id, data_root) for each participating validator
    for (att_idx, aggregated_attestation) in aggregated_attestations.into_iter().enumerate() {
        let data_root = aggregated_attestation.data.hash_tree_root();

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
    // Signature verification is done in verify_signatures() before on_block()
    // Per Devnet-2, we process attestation data directly (not SignedAttestation)
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
            on_attestation_internal(
                store,
                validator_id,
                aggregated_attestation.data.clone(),
                true, // is_from_block
            )?;
        }
    }

    // Update head BEFORE processing proposer attestation
    update_head(store);

    // Store proposer's signature for later block building
    let proposer_data_root = proposer_attestation.data.hash_tree_root();
    let proposer_sig_key = SignatureKey::new(proposer_attestation.validator_id, proposer_data_root);
    store
        .gossip_signatures
        .insert(proposer_sig_key, signed_block.signature.proposer_signature);

    // Process proposer attestation as if received via gossip (is_from_block=false)
    // This ensures it goes to "new" attestations and doesn't immediately affect fork choice
    on_attestation_internal(
        store,
        proposer_attestation.validator_id,
        proposer_attestation.data.clone(),
        false, // is_from_block
    )?;

    Ok(())
}

fn process_pending_blocks(store: &mut Store, mut roots: Vec<H256>) {
    while let Some(parent_root) = roots.pop() {
        if let Some(purgatory) = store.blocks_queue.remove(&parent_root) {
            for block in purgatory {
                let block_origins = block.message.block.hash_tree_root();
                if let Ok(()) = process_block_internal(store, block, block_origins) {
                    roots.push(block_origins);
                }
            }
        }
    }
}
