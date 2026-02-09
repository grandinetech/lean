use std::collections::HashMap;

use anyhow::{Result, anyhow, ensure};
use containers::{
    AggregatedSignatureProof, Attestation, AttestationData, Block, Checkpoint, Config,
    SignatureKey, SignedBlockWithAttestation, Slot, State,
};
use metrics::set_gauge_u64;
use ssz::{H256, SszHash};
use xmss::Signature;

pub type Interval = u64;
pub const INTERVALS_PER_SLOT: Interval = 4;
pub const SECONDS_PER_SLOT: u64 = 4;
pub const SECONDS_PER_INTERVAL: u64 = SECONDS_PER_SLOT / INTERVALS_PER_SLOT;

/// Forkchoice store tracking chain state and validator attestations

#[derive(Debug, Clone, Default)]
pub struct Store {
    pub time: Interval,

    pub config: Config,

    pub head: H256,

    pub safe_target: H256,

    pub latest_justified: Checkpoint,

    pub latest_finalized: Checkpoint,

    pub blocks: HashMap<H256, Block>,

    pub states: HashMap<H256, State>,

    pub latest_known_attestations: HashMap<u64, AttestationData>,

    pub latest_new_attestations: HashMap<u64, AttestationData>,

    pub blocks_queue: HashMap<H256, Vec<SignedBlockWithAttestation>>,

    pub gossip_signatures: HashMap<SignatureKey, Signature>,

    pub aggregated_payloads: HashMap<SignatureKey, Vec<AggregatedSignatureProof>>,
}

const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

impl Store {
    pub fn produce_attestation_data(&self, slot: Slot) -> Result<AttestationData> {
        let head_checkpoint = Checkpoint {
            root: self.head,
            slot: self
                .blocks
                .get(&self.head)
                .ok_or(anyhow!("head block is not known"))?
                .slot,
        };

        let target_checkpoint = self.get_attestation_target();

        Ok(AttestationData {
            slot,
            head: head_checkpoint,
            target: target_checkpoint,
            source: self.latest_justified.clone(),
        })
    }

    pub fn get_attestation_target(&self) -> Checkpoint {
        let mut target = self.head;

        let safe_slot = self.blocks[&self.safe_target].slot;

        // Walk back toward safe target
        for _ in 0..JUSTIFICATION_LOOKBACK_SLOTS {
            if self.blocks[&target].slot > safe_slot {
                target = self.blocks[&target].parent_root;
            } else {
                break;
            }
        }

        let final_slot = self.latest_finalized.slot;
        while !self.blocks[&target].slot.is_justifiable_after(final_slot) {
            target = self.blocks[&target].parent_root;
        }

        let block_target = &self.blocks[&target];
        Checkpoint {
            root: target,
            slot: block_target.slot,
        }
    }
}

/// Initialize forkchoice store from an anchor state and block
pub fn get_forkchoice_store(
    anchor_state: State,
    anchor_block: SignedBlockWithAttestation,
    config: Config,
) -> Store {
    // Extract the plain Block from the signed block
    let block = anchor_block.message.block.clone();
    let block_slot = block.slot;

    // Compute block root using the header hash (canonical block root)
    let block_root = block.hash_tree_root();

    let latest_justified = if anchor_state.latest_justified.root.is_zero() {
        Checkpoint {
            root: block_root,
            slot: block_slot,
        }
    } else {
        anchor_state.latest_justified.clone()
    };

    let latest_finalized = if anchor_state.latest_finalized.root.is_zero() {
        Checkpoint {
            root: block_root,
            slot: block_slot,
        }
    } else {
        anchor_state.latest_finalized.clone()
    };

    // Store the original anchor_state - do NOT modify it
    // Modifying checkpoints would change its hash_tree_root(), breaking the
    // consistency with block.state_root
    Store {
        time: block_slot.0 * INTERVALS_PER_SLOT,
        config,
        head: block_root,
        safe_target: block_root,
        latest_justified,
        latest_finalized,
        blocks: [(block_root, block)].into(),
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
    mut root: H256,
    latest_attestations: &HashMap<u64, AttestationData>,
    min_votes: usize,
) -> H256 {
    if root.is_zero() {
        root = store
            .blocks
            .iter()
            .min_by_key(|(_, block)| block.slot)
            .map(|(r, _)| *r)
            .expect("Error: Empty block.");
    }
    let mut vote_weights: HashMap<H256, usize> = HashMap::new();
    let root_slot = store.blocks[&root].slot;

    // stage 1: accumulate weights by walking up from each attestation's head
    for attestation_data in latest_attestations.values() {
        let mut curr = attestation_data.head.root;

        if let Some(block) = store.blocks.get(&curr) {
            let mut curr_slot = block.slot;

            while curr_slot > root_slot {
                *vote_weights.entry(curr).or_insert(0) += 1;

                if let Some(parent_block) = store.blocks.get(&curr) {
                    curr = parent_block.parent_root;
                    if curr.is_zero() {
                        break;
                    }
                    if let Some(next_block) = store.blocks.get(&curr) {
                        curr_slot = next_block.slot;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    // stage 2: build adjacency tree (parent -> children)
    let mut child_map: HashMap<H256, Vec<H256>> = HashMap::new();
    for (block_hash, block) in &store.blocks {
        if !block.parent_root.is_zero() {
            if vote_weights.get(block_hash).copied().unwrap_or(0) >= min_votes {
                child_map
                    .entry(block.parent_root)
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

pub fn get_latest_justified(states: &HashMap<H256, State>) -> Option<&Checkpoint> {
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

    set_gauge_u64(
        |m| &m.lean_head_slot,
        || {
            let head = store
                .blocks
                .get(&new_head)
                .ok_or(anyhow!("failed to get head block"))?;

            Ok(head.slot.0)
        },
    );
}

pub fn update_safe_target(store: &mut Store) {
    let n_validators = if let Some(state) = store.states.get(&store.head) {
        state.validators.len_usize()
    } else {
        0
    };

    let min_score = (n_validators * 2 + 2) / 3;
    let root = store.latest_justified.root;
    let new_safe_target =
        get_fork_choice_head(store, root, &store.latest_new_attestations, min_score);
    store.safe_target = new_safe_target;

    set_gauge_u64(
        |metrics| &metrics.lean_safe_target_slot,
        || {
            let safe_target = store
                .blocks
                .get(&new_safe_target)
                .ok_or(anyhow!("failed to get safe target block"))?;

            Ok(safe_target.slot.0)
        },
    );
}

pub fn accept_new_attestations(store: &mut Store) {
    store
        .latest_known_attestations
        .extend(store.latest_new_attestations.drain());
    update_head(store);
}

pub fn tick_interval(store: &mut Store, has_proposal: bool) {
    store.time += 1;
    // Calculate current interval within slot: time % INTERVALS_PER_SLOT
    let curr_interval = store.time % INTERVALS_PER_SLOT;

    match curr_interval {
        0 if has_proposal => accept_new_attestations(store),
        2 => update_safe_target(store),
        3 => accept_new_attestations(store),
        _ => {}
    }
}

#[inline]
pub fn get_proposal_head(store: &mut Store, slot: Slot) -> H256 {
    let slot_time = store.config.genesis_time + (slot.0 * SECONDS_PER_SLOT);

    crate::handlers::on_tick(store, slot_time, true);
    accept_new_attestations(store);
    store.head
}

/// Produce a block and aggregated signature proofs for the target slot per devnet-2.
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
    validator_index: u64,
) -> Result<(H256, Block, Vec<AggregatedSignatureProof>)> {
    // Get parent block head
    let head_root = get_proposal_head(store, slot);
    let head_state = store
        .states
        .get(&head_root)
        .ok_or_else(|| anyhow!("Head state not found"))?
        .clone();

    // Validate proposer authorization for this slot
    let num_validators = head_state.validators.len_u64();
    let expected_proposer = slot.0 % num_validators;
    ensure!(
        validator_index == expected_proposer,
        "Validator {} is not the proposer for slot {} (expected {})",
        validator_index,
        slot.0,
        expected_proposer
    );

    // Convert AttestationData to Attestation objects for build_block
    // Per devnet-2, store now holds AttestationData directly
    let available_attestations: Vec<Attestation> = store
        .latest_known_attestations
        .iter()
        .map(|(validator_idx, attestation_data)| Attestation {
            validator_id: *validator_idx,
            data: attestation_data.clone(),
        })
        .collect();

    // Get known block roots for attestation validation
    let known_block_roots: std::collections::HashSet<H256> = store.blocks.keys().copied().collect();

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

    // Compute block root using the header hash (canonical block root)
    let block_root = final_block.hash_tree_root();

    // Store block and state (per devnet-2, we store the plain Block)
    store.blocks.insert(block_root, final_block.clone());
    store.states.insert(block_root, final_post_state);

    Ok((block_root, final_block, signatures))
}
