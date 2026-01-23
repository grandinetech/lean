use containers::{
    attestation::SignedAttestation, block::SignedBlockWithAttestation, checkpoint::Checkpoint,
    config::Config, state::State, Bytes32, Root, Slot, ValidatorIndex,
};
use containers::{AggregatedSignatureProof, Signature, SignatureKey};
use ssz::SszHash;
use std::collections::HashMap;
pub type Interval = u64;
pub const INTERVALS_PER_SLOT: Interval = 4;
pub const SECONDS_PER_SLOT: u64 = 4;
pub const SECONDS_PER_INTERVAL: u64 = SECONDS_PER_SLOT / INTERVALS_PER_SLOT;

#[derive(Debug, Clone, Default)]
pub struct Store {
    pub time: Interval,
    pub config: Config,
    pub head: Root,
    pub safe_target: Root,
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,
    pub blocks: HashMap<Root, SignedBlockWithAttestation>,
    pub states: HashMap<Root, State>,
    pub latest_known_attestations: HashMap<ValidatorIndex, SignedAttestation>,
    pub latest_new_attestations: HashMap<ValidatorIndex, SignedAttestation>,
    pub blocks_queue: HashMap<Root, Vec<SignedBlockWithAttestation>>,

    pub gossip_signatures: HashMap<SignatureKey, Signature>,

    pub aggregated_payloads: HashMap<SignatureKey, Vec<AggregatedSignatureProof>>,
}

pub fn get_forkchoice_store(
    anchor_state: State,
    anchor_block: SignedBlockWithAttestation,
    config: Config,
) -> Store {
    let block_root = Bytes32(anchor_block.message.block.hash_tree_root());
    let block_slot = anchor_block.message.block.slot;

    let latest_justified = if anchor_state.latest_justified.root.0.is_zero() {
        Checkpoint {
            root: block_root,
            slot: block_slot,
        }
    } else {
        anchor_state.latest_justified.clone()
    };

    let latest_finalized = if anchor_state.latest_finalized.root.0.is_zero() {
        Checkpoint {
            root: block_root,
            slot: block_slot,
        }
    } else {
        anchor_state.latest_finalized.clone()
    };

    Store {
        time: block_slot.0 * INTERVALS_PER_SLOT,
        config,
        head: block_root,
        safe_target: block_root,
        latest_justified,
        latest_finalized,
        blocks: [(block_root, anchor_block)].into(),
        states: [(block_root, anchor_state)].into(),
        latest_known_attestations: HashMap::new(),
        latest_new_attestations: HashMap::new(),
        blocks_queue: HashMap::new(),
        gossip_signatures: HashMap::new(),
        aggregated_payloads: HashMap::new(),
    }
}

pub fn get_fork_choice_head(
    store: &Store,
    mut root: Root,
    latest_attestations: &HashMap<ValidatorIndex, SignedAttestation>,
    min_votes: usize,
) -> Root {
    if root.0.is_zero() {
        root = store
            .blocks
            .iter()
            .min_by_key(|(_, block)| block.message.block.slot)
            .map(|(r, _)| *r)
            .expect("Error: Empty block.");
    }
    let mut vote_weights: HashMap<Root, usize> = HashMap::new();
    let root_slot = store.blocks[&root].message.block.slot;

    // stage 1: accumulate weights by walking up from each attestation's head
    for attestation in latest_attestations.values() {
        let mut curr = attestation.message.head.root;

        if let Some(block) = store.blocks.get(&curr) {
            let mut curr_slot = block.message.block.slot;

            while curr_slot > root_slot {
                *vote_weights.entry(curr).or_insert(0) += 1;

                if let Some(parent_block) = store.blocks.get(&curr) {
                    curr = parent_block.message.block.parent_root;
                    if curr.0.is_zero() {
                        break;
                    }
                    if let Some(next_block) = store.blocks.get(&curr) {
                        curr_slot = next_block.message.block.slot;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    // stage 2
    let mut child_map: HashMap<Root, Vec<Root>> = HashMap::new();
    for (block_hash, block) in &store.blocks {
        if !block.message.block.parent_root.0.is_zero() {
            if vote_weights.get(block_hash).copied().unwrap_or(0) >= min_votes {
                child_map
                    .entry(block.message.block.parent_root)
                    .or_default()
                    .push(*block_hash);
            }
        }
    }

    // stage 3: greedy walk choosing heaviest child at each fork
    let mut curr = root;
    loop {
        let children = match child_map.get(&curr) {
            Some(list) if !list.is_empty() => list,
            _ => return curr,
        };

        // Choose best child: most attestations, then lexicographically highest hash
        // This matches leanSpec: max(children, key=lambda x: (weights[x], x))
        curr = *children
            .iter()
            .max_by(|&&a, &&b| {
                let wa = vote_weights.get(&a).copied().unwrap_or(0);
                let wb = vote_weights.get(&b).copied().unwrap_or(0);
                wa.cmp(&wb).then_with(|| a.cmp(&b))
            })
            .unwrap();
    }
}

pub fn get_latest_justified(states: &HashMap<Root, State>) -> Option<&Checkpoint> {
    states
        .values()
        .map(|state| &state.latest_justified)
        .max_by_key(|checkpoint| checkpoint.slot)
}

pub fn update_head(store: &mut Store) {
    // Compute new head using LMD-GHOST from latest justified root
    let new_head = get_fork_choice_head(
        store,
        store.latest_justified.root,
        &store.latest_known_attestations,
        0,
    );
    store.head = new_head;
}

pub fn update_safe_target(store: &mut Store) {
    let n_validators = if let Some(state) = store.states.get(&store.head) {
        state.validators.len_usize()
    } else {
        0
    };

    let min_score = (n_validators * 2 + 2) / 3;
    let root = store.latest_justified.root;
    store.safe_target =
        get_fork_choice_head(store, root, &store.latest_new_attestations, min_score);
}

pub fn accept_new_attestations(store: &mut Store) {
    store
        .latest_known_attestations
        .extend(store.latest_new_attestations.drain());
    update_head(store);
}

pub fn tick_interval(store: &mut Store, has_proposal: bool) {
    store.time += 1;
    // Calculate current interval within slot: time % SECONDS_PER_SLOT % INTERVALS_PER_SLOT
    let curr_interval = (store.time % SECONDS_PER_SLOT) % INTERVALS_PER_SLOT;

    match curr_interval {
        0 if has_proposal => accept_new_attestations(store),
        2 => update_safe_target(store),
        3 => accept_new_attestations(store),
        _ => {}
    }
}

pub fn get_vote_target(store: &Store) -> Checkpoint {
    let mut target = store.head;
    let safe_slot = store.blocks[&store.safe_target].message.block.slot;
    let source_slot = store.latest_justified.slot;

    // Walk back toward safe target (up to 3 steps per leanSpec JUSTIFICATION_LOOKBACK_SLOTS)
    for _ in 0..3 {
        if store.blocks[&target].message.block.slot > safe_slot {
            let parent = store.blocks[&target].message.block.parent_root;
            // Don't walk back if it would make target <= source (invalid attestation)
            if let Some(parent_block) = store.blocks.get(&parent) {
                if parent_block.message.block.slot <= source_slot {
                    break;
                }
            }
            target = parent;
        } else {
            break;
        }
    }

    let final_slot = store.latest_finalized.slot;
    while !store.blocks[&target]
        .message
        .block
        .slot
        .is_justifiable_after(final_slot)
    {
        let parent = store.blocks[&target].message.block.parent_root;
        // Don't walk back if it would make target <= source (invalid attestation)
        if let Some(parent_block) = store.blocks.get(&parent) {
            if parent_block.message.block.slot <= source_slot {
                break;
            }
        }
        target = parent;
    }

    let block_target = &store.blocks[&target].message.block;
    Checkpoint {
        root: target,
        slot: block_target.slot,
    }
}

#[inline]
pub fn get_proposal_head(store: &mut Store, slot: Slot) -> Root {
    let slot_time = store.config.genesis_time + (slot.0 * SECONDS_PER_SLOT);

    crate::handlers::on_tick(store, slot_time, true);
    accept_new_attestations(store);
    store.head
}

/// Produce a block and aggregated signature proofs for the target slot.
///
/// The proposer returns the block and `MultisigAggregatedSignature` proofs aligned
/// with `block.body.attestations` so it can craft `SignedBlockWithAttestation`.
///
/// # Algorithm Overview
/// 1. **Get Proposal Head**: Retrieve current chain head as parent
/// 2. **Collect Attestations**: Convert known attestations to plain attestations
/// 3. **Build Block**: Use State.build_block with signature caches
/// 4. **Store Block**: Insert block and post-state into Store
///
/// # Arguments
/// * `store` - Mutable reference to the fork choice store
/// * `slot` - Target slot number for block production
/// * `validator_index` - Index of validator authorized to propose this block
///
/// # Returns
/// Tuple of (block root, finalized Block, attestation signature proofs)
pub fn produce_block_with_signatures(
    store: &mut Store,
    slot: Slot,
    validator_index: ValidatorIndex,
) -> Result<
    (
        Root,
        containers::block::Block,
        Vec<AggregatedSignatureProof>,
    ),
    String,
> {
    use containers::Attestation;

    // Get parent block head
    let head_root = get_proposal_head(store, slot);
    let head_state = store
        .states
        .get(&head_root)
        .ok_or_else(|| "Head state not found".to_string())?
        .clone();

    // Validate proposer authorization for this slot
    let num_validators = head_state.validators.len_u64();
    let expected_proposer = slot.0 % num_validators;
    if validator_index.0 != expected_proposer {
        return Err(format!(
            "Validator {} is not the proposer for slot {} (expected {})",
            validator_index.0, slot.0, expected_proposer
        ));
    }

    // Convert AttestationData to Attestation objects for build_block
    let available_attestations: Vec<Attestation> = store
        .latest_known_attestations
        .iter()
        .map(|(validator_idx, signed_att)| Attestation {
            validator_id: containers::Uint64(validator_idx.0),
            data: signed_att.message.clone(),
        })
        .collect();

    // Get known block roots for attestation validation
    let known_block_roots: std::collections::HashSet<Bytes32> =
        store.blocks.keys().copied().collect();

    // Build block with fixed-point attestation collection and signature aggregation
    let (final_block, final_post_state, _aggregated_attestations, signatures) = head_state
        .build_block(
            slot,
            validator_index,
            head_root,
            None, // initial_attestations - start with empty, let fixed-point collect
            Some(available_attestations),
            Some(&known_block_roots),
            Some(&store.gossip_signatures),
            Some(&store.aggregated_payloads),
        )?;

    // Compute block root
    let block_root = Bytes32(final_block.hash_tree_root());

    // Store block and state
    store.states.insert(block_root, final_post_state);

    Ok((block_root, final_block, signatures))
}
