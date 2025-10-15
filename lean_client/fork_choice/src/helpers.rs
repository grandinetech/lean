use std::collections::HashMap;
use containers::{Bytes32, Block, State, Checkpoint, ValidatorIndex, Slot};
use crate::store::{Store, ValidatorId};

/// The zero hash constant
pub const ZERO_HASH: Bytes32 = Bytes32(ssz::H256::zero());

/// Process a block to get the new state
/// This processes attestations and updates justification based on votes
pub fn process_block(mut parent_state: State, block: &Block) -> State {
    // Update the slot to the block's slot
    parent_state.slot = block.slot;

    // Process attestations from the block
    let mut vote_count = 0;
    let mut i: u64 = 0;

    // Count valid attestations
    loop {
        match block.body.attestations.get(i) {
            Ok(attestation) => {
                // In a real implementation, we would validate the attestation
                // For now, we assume all attestations are valid
                if attestation.data.slot.0 <= block.slot.0 {
                    vote_count += 1;
                }
                i += 1;
            },
            Err(_) => break,
        }
    }

    // Update justification if we have enough votes
    // Simplified: if we have more than 1/3 of validators voting, justify this block
    let total_validators = parent_state.config.num_validators;
    let justification_threshold = total_validators / 3;

    if vote_count > justification_threshold {
        let block_hash = hash_tree_root(block);
        parent_state.latest_justified = Checkpoint {
            slot: block.slot,
            root: Bytes32(block_hash.0),
        };

        // If this justifies a block that is ahead of our previous finalized block
        // and we have a chain of justified blocks, we can finalize
        if block.slot.0 > parent_state.latest_finalized.slot.0 + 1 {
            parent_state.latest_finalized = parent_state.latest_justified.clone();
        }
    }

    parent_state
}

/// Hash tree root helper that returns our Bytes32 type
pub fn hash_tree_root(block: &Block) -> Bytes32 {
    use containers::block::hash_tree_root as container_hash;
    container_hash(block)
}

/// Check if a slot can be justified based on finalized slot
/// A slot is justified if it's after the finalized slot and follows the justification rules
fn is_justified_slot(finalized_slot: Slot, target_slot: Slot) -> bool {
    // A block can be justified if:
    // 1. It's after the finalized block
    // 2. It's not too far in the future (within reasonable bounds)
    target_slot.0 >= finalized_slot.0 && target_slot.0 <= finalized_slot.0 + 64
}


/// Core LMD-GHOST fork choice algorithm
/// Returns the head of the chain starting from the given root
pub fn get_fork_choice_head(
    blocks: &HashMap<Bytes32, Block>,
    mut root: Bytes32,
    latest_votes: &HashMap<ValidatorId, Checkpoint>,
    min_score: usize,
) -> Bytes32 {
    // If root is zero hash, find the genesis block (lowest slot)
    if root == ZERO_HASH {
        root = blocks
            .iter()
            .min_by_key(|(_, block)| block.slot.0)
            .map(|(r, _)| *r)
            .expect("Blocks cannot be empty");
    }

    // Count votes for each block - votes for descendants count toward ancestors
    let mut vote_weights: HashMap<Bytes32, usize> = HashMap::new();
    for vote in latest_votes.values() {
        if let Some(mut curr) = blocks.get(&vote.root).map(|_| vote.root) {
            // Walk up the chain from the vote target to the root
            while blocks.get(&curr).map_or(false, |block| block.slot.0 > blocks[&root].slot.0) {
                *vote_weights.entry(curr).or_insert(0) += 1;
                curr = blocks[&curr].parent_root;
            }
        }
    }

    // Build children map, only including blocks that meet the minimum score
    let mut children_map: HashMap<Bytes32, Vec<Bytes32>> = HashMap::new();
    for (block_hash, block) in blocks {
        if block.parent_root != ZERO_HASH {
            if vote_weights.get(block_hash).copied().unwrap_or(0) >= min_score {
                children_map.entry(block.parent_root).or_default().push(*block_hash);
            }
        }
    }

    // Follow the heaviest branch from root to leaf
    let mut curr = root;
    loop {
        let children = match children_map.get(&curr) {
            Some(list) if !list.is_empty() => list,
            _ => return curr, // Reached a leaf
        };

        // Choose the child with the most votes (breaking ties by slot, then by hash)
        curr = *children
            .iter()
            .max_by(|a, b| {
                let weight_a = vote_weights.get(a).copied().unwrap_or(0);
                let weight_b = vote_weights.get(b).copied().unwrap_or(0);
                weight_a.cmp(&weight_b)
                    .then_with(|| blocks[a].slot.0.cmp(&blocks[b].slot.0))
                    .then_with(|| a.cmp(b))
            })
            .unwrap();
    }
}

/// Find the latest justified checkpoint among all known states
pub fn get_latest_justified(states: &HashMap<Bytes32, State>) -> Option<Checkpoint> {
    states.values()
        .max_by_key(|state| state.latest_justified.slot.0)
        .map(|s| s.latest_justified.clone())
}

/// Update the head of the chain based on current votes and justification
pub fn update_head(store: &mut Store) {
    // Update latest justified checkpoint if we have newer information
    if let Some(latest_justified) = get_latest_justified(&store.states) {
        store.latest_justified = latest_justified;
    }

    // Run fork choice algorithm to find new head
    store.head = get_fork_choice_head(
        &store.blocks,
        store.latest_justified.root,
        &store.latest_known_votes,
        0
    );

    // Update finalized checkpoint based on the head state
    if let Some(state) = store.states.get(&store.head) {
        store.latest_finalized = state.latest_finalized.clone();
    }
}

/// Update the safe target that validators can vote on
pub fn update_safe_target(store: &mut Store) {
    let num_validators = store.config.num_validators as usize;
    let min_target_score = (num_validators * 2 + 2) / 3; // 2/3 threshold
    store.safe_target = get_fork_choice_head(
        &store.blocks,
        store.latest_justified.root,
        &store.latest_new_votes,
        min_target_score
    );
}

/// Accept new votes into the known votes and update head
pub fn accept_new_votes(store: &mut Store) {
    for (validator_id, vote) in store.latest_new_votes.drain() {
        store.latest_known_votes.insert(validator_id, vote);
    }
    update_head(store);
}

/// Advance one interval in the protocol timing
/// Implements the full protocol timing with different phases
pub fn tick_interval(store: &mut Store, has_proposal: bool) {
    store.time += 1;
    let curr_interval = store.time % store.config.intervals_per_slot;
    let curr_slot = store.time / store.config.intervals_per_slot;

    match curr_interval {
        0 => {
            // Start of slot - proposal phase
            if has_proposal {
                accept_new_votes(store);
                // Clean up old votes that are no longer relevant
                cleanup_old_votes(store, curr_slot);
            }
        },
        1 => {
            // Vote collection phase - don't process votes yet
            // This gives time for votes to propagate
        },
        2 => {
            // Safety update phase
            update_safe_target(store);
        },
        3 => {
            // Final vote processing phase
            accept_new_votes(store);
        },
        _ => {
            // Other intervals - normal vote processing
            accept_new_votes(store);
        }
    }
}

/// Clean up votes that are too old to be relevant
fn cleanup_old_votes(store: &mut Store, current_slot: u64) {
    let max_vote_age = 32; // Keep votes for last 32 slots

    store.latest_known_votes.retain(|_, checkpoint| {
        current_slot.saturating_sub(checkpoint.slot.0) <= max_vote_age
    });

    store.latest_new_votes.retain(|_, checkpoint| {
        current_slot.saturating_sub(checkpoint.slot.0) <= max_vote_age
    });
}

/// Get the target that a validator should vote for
/// This implements a more sophisticated targeting strategy
pub fn get_vote_target(store: &Store) -> Checkpoint {
    let mut target_root = store.head;

    // Don't vote for blocks that are too recent (safety mechanism)
    let current_slot = store.time / store.config.intervals_per_slot;
    let safety_margin = 2; // Don't vote for blocks less than 2 slots old

    // Walk back until we find a block that's old enough to be safe
    while let Some(block) = store.blocks.get(&target_root) {
        if block.slot.0 + safety_margin <= current_slot {
            break;
        }
        if block.parent_root == ZERO_HASH {
            break; // Don't go past genesis
        }
        target_root = block.parent_root;
    }

    // Ensure the target is on the safe target chain
    // Walk back until we reach something that's an ancestor of safe_target
    let mut candidate = target_root;
    while let Some(block) = store.blocks.get(&candidate) {
        // Check if this block is an ancestor of safe_target
        if is_ancestor_of(&store.blocks, candidate, store.safe_target) {
            target_root = candidate;
            break;
        }
        if block.parent_root == ZERO_HASH {
            break;
        }
        candidate = block.parent_root;
    }

    // Ensure the target is justified
    while let Some(block) = store.blocks.get(&target_root) {
        if is_justified_slot(store.latest_finalized.slot, block.slot) {
            break;
        }
        if block.parent_root == ZERO_HASH {
            break;
        }
        target_root = block.parent_root;
    }

    let target_block = &store.blocks[&target_root];
    Checkpoint {
        root: target_root,
        slot: target_block.slot,
    }
}

/// Check if block_a is an ancestor of block_b
fn is_ancestor_of(blocks: &HashMap<Bytes32, Block>, ancestor: Bytes32, descendant: Bytes32) -> bool {
    if ancestor == descendant {
        return true;
    }

    let mut current = descendant;
    for _ in 0..256 { // Limit iterations to prevent infinite loops
        if let Some(block) = blocks.get(&current) {
            if block.parent_root == ancestor {
                return true;
            }
            if block.parent_root == ZERO_HASH {
                return false;
            }
            current = block.parent_root;
        } else {
            return false;
        }
    }
    false
}