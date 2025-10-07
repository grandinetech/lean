use crate::extensions::JustifiableSlot;
use std::collections::HashMap;

use containers::{
    block::hash_tree_root, checkpoint::Checkpoint, config::Config, state::State,
    vote::SignedVote, Root, Slot, ValidatorIndex, SignedBlock,
};

pub type Interval = u64;
pub const INTERVALS_PER_SLOT: Interval = 8;
pub const SECONDS_PER_SLOT: u64 = 12;


#[derive(Debug, Clone, Default)]
pub struct Store {
    pub time: Interval,
    pub config: Config,
    pub head: Root,
    pub safe_target: Root,
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,
    pub blocks: HashMap<Root, SignedBlock>,
    pub states: HashMap<Root, State>,
    pub latest_known_votes: HashMap<ValidatorIndex, Checkpoint>,
    pub latest_new_votes: HashMap<ValidatorIndex, Checkpoint>,
}

pub fn get_forkchoice_store(
    anchor_state: State,
    anchor_block: SignedBlock,
    config: Config,
) -> Store {
    let block_root = hash_tree_root(&anchor_block.message);
    let time = anchor_block.message.slot.0 * INTERVALS_PER_SLOT;

    Store {
        time,
        config,
        head: block_root,
        safe_target: block_root,
        latest_justified: anchor_state.latest_justified.clone(),
        latest_finalized: anchor_state.latest_finalized.clone(),
        blocks: [(block_root, anchor_block)].into(),
        states: [(block_root, anchor_state)].into(),
        latest_known_votes: HashMap::new(),
        latest_new_votes: HashMap::new(),
    }
}

pub fn get_fork_choice_head(
    store: &Store,
    root: Root,
    votes: &HashMap<ValidatorIndex, Checkpoint>,
    min_score: usize,
) -> Root {
    let mut root = root;
    if root.0.is_zero() {
        root = store
            .blocks
            .iter()
            .min_by_key(|(_, block)| block.message.slot)
            .map(|(r, _)| *r)
            .expect("Err: blocks can't be empty");
    }
    let mut vote_weights: HashMap<Root, usize> = HashMap::new();
    let root_slot = store.blocks[&root].message.slot;

    for v in votes.values() {
        if store.blocks.contains_key(&v.root) {
            let mut curr = v.root;
            while store.blocks[&curr].message.slot > root_slot {
                *vote_weights.entry(curr).or_insert(0) += 1;
                curr = store.blocks[&curr].message.parent_root;
                if curr.0.is_zero() || !store.blocks.contains_key(&curr) {
                    break;
                }
            }
        }
    }

    let mut child_map: HashMap<Root, Vec<Root>> = HashMap::new();
    for (block_hash, block) in &store.blocks {
        if !block.message.parent_root.0.is_zero() {
            if vote_weights.get(block_hash).copied().unwrap_or(0) >= min_score {
                child_map
                    .entry(block.message.parent_root)
                    .or_default()
                    .push(*block_hash);
            }
        }
    }

    let mut curr = root;
    loop {
        let child = match child_map.get(&curr) {
            Some(list) if !list.is_empty() => list,
            _ => return curr,
        };

        curr = *child
            .iter()
            .max_by(|a, b| {
                let wa = vote_weights.get(a).copied().unwrap_or(0);
                let wb = vote_weights.get(b).copied().unwrap_or(0);
                wa.cmp(&wb)
                    .then_with(|| store.blocks[*a].message.slot.cmp(&store.blocks[*b].message.slot))
                    .then_with(|| (*a).cmp(b))
            })
            .unwrap();
    }
}

pub fn get_latest_justified(states: &HashMap<Root, State>) -> Option<Checkpoint> {
    states
        .values()
        .max_by_key(|state| state.latest_justified.slot)
        .map(|s| s.latest_justified.clone())
}

pub fn update_head(store: &mut Store) {
    if let Some(latest_justified) = get_latest_justified(&store.states) {
        store.latest_justified = latest_justified;
    }

    store.head =
        get_fork_choice_head(store, store.latest_justified.root, &store.latest_known_votes, 0);

    if let Some(state) = store.states.get(&store.head) {
        store.latest_finalized = state.latest_finalized.clone();
    }
}

pub fn update_safe_target(store: &mut Store) {
    let num_validators = store.config.num_validators as usize;
    let min_target_score = (num_validators * 2 + 2) / 3;
    store.safe_target = get_fork_choice_head(
        store,
        store.latest_justified.root,
        &store.latest_new_votes,
        min_target_score,
    );
}

pub fn accept_new_votes(store: &mut Store) {
    store
        .latest_known_votes
        .extend(store.latest_new_votes.drain());
    update_head(store);
}

pub fn tick_interval(store: &mut Store, has_proposal: bool) {
    store.time += 1;
    let curr_interval = store.time % INTERVALS_PER_SLOT;

    match curr_interval {
        0 if has_proposal => accept_new_votes(store),
        2 => update_safe_target(store),
        _ if curr_interval != 1 => accept_new_votes(store),
        _ => {}
    }
}

pub fn get_vote_target(store: &Store) -> Checkpoint {
    let mut target_root = store.head;

    for _ in 0..3 {
        if store.blocks[&target_root].message.slot > store.blocks[&store.safe_target].message.slot
        {
            target_root = store.blocks[&target_root].message.parent_root;
        } else {
            break;
        }
    }

    while !store.blocks[&target_root]
        .message
        .slot
        .is_justifiable_after(store.latest_finalized.slot)
    {
        target_root = store.blocks[&target_root].message.parent_root;
    }

    let target_block = &store.blocks[&target_root].message;
    Checkpoint {
        root: target_root,
        slot: target_block.slot,
    }
}

pub fn get_proposal_head(store: &mut Store, slot: Slot) -> Root {
    let slot_time = store.config.genesis_time + (slot.0 * SECONDS_PER_SLOT);

    crate::handlers::on_tick(store, slot_time, true);
    accept_new_votes(store);
    store.head
}
