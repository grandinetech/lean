use std::collections::HashMap;

use containers::{
    block::{hash_tree_root, BlockHeader, SignedBlockWithAttestation},
    checkpoint::Checkpoint,
    config::Config,
    state::State,
    Root, Slot, ValidatorIndex,
};

pub fn get_block_root(signed_block: &SignedBlockWithAttestation) -> Root {
    let block = &signed_block.message.block;
    let body_root = hash_tree_root(&block.body);
    let header = BlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root,
    };
    hash_tree_root(&header)
}

// CONSTS
pub type Interval = u64;
pub const INTERVALS_PER_SLOT: Interval = 8;
pub const SECONDS_PER_SLOT: u64 = 12;

// STORE
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
    pub latest_known_votes: HashMap<ValidatorIndex, Checkpoint>,
    pub latest_new_votes: HashMap<ValidatorIndex, Checkpoint>,
}

pub fn get_forkchoice_store(
    anchor_state: State,
    anchor_block: SignedBlockWithAttestation,
    config: Config,
) -> Store {
    let block = get_block_root(&anchor_block);

    Store {
        time: anchor_block.message.block.slot.0 * INTERVALS_PER_SLOT,
        config,
        head: block,
        safe_target: block,
        latest_justified: anchor_state.latest_justified.clone(),
        latest_finalized: anchor_state.latest_finalized.clone(),
        blocks: [(block, anchor_block)].into(),
        states: [(block, anchor_state)].into(),
        latest_known_votes: HashMap::new(),
        latest_new_votes: HashMap::new(),
    }
}

pub fn get_fork_choice_head(
    store: &Store,
    mut root: Root,
    latest_votes: &HashMap<ValidatorIndex, Checkpoint>,
    min_votes: usize,
) -> Root {
    // prep
    if root.0.is_zero() {
        root = store
            .blocks
            .iter()
            .min_by_key(|(_, block)| block.message.block.slot)
            .map(|(r, _)| *r)
            .expect("Err:(ForkChoice::get_fork_choice_head) blocks can't be empty");
    }
    let mut vote_weights: HashMap<Root, usize> = HashMap::new();
    let root_slot = store.blocks[&root].message.block.slot;

    // stage 1
    for v in latest_votes.values() {
        if let Some(block) = store.blocks.get(&v.root) {
            let mut curr = v.root;

            let mut curr_slot = block.message.block.slot; // mut nes borrowinam

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

    // stage 3
    let mut curr = root;
    loop {
        let children = match child_map.get(&curr) {
            Some(list) if !list.is_empty() => list,
            _ => return curr,
        };

        curr = *children
            .iter()
            .max_by(|&&a, &&b| {
                let wa = vote_weights.get(&a).copied().unwrap_or(0);
                let wb = vote_weights.get(&b).copied().unwrap_or(0);
                let slot_a = store.blocks[&a].message.block.slot;
                let slot_b = store.blocks[&b].message.block.slot;
                wa.cmp(&wb)
                    .then_with(|| slot_b.cmp(&slot_a))
                    .then_with(|| a.cmp(&b))
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
    // note to self: Option?
    if let Some(latest_justified) = get_latest_justified(&store.states) {
        store.latest_justified = latest_justified.clone();
    }

    let mut combined_votes = store.latest_known_votes.clone();
    combined_votes.extend(store.latest_new_votes.clone());

    let current_head = store.head;
    let new_head = get_fork_choice_head(store, store.latest_justified.root, &combined_votes, 0);

    if new_head != current_head {
        let is_extension = is_descendant(store, current_head, new_head);

        if is_extension {
            store.head = new_head;
        } else {
            let should_switch = reorg_new_head(store, current_head, new_head, &combined_votes);
            if should_switch {
                store.head = new_head;
            }
        }
    }

    if let Some(state) = store.states.get(&store.head) {
        store.latest_finalized = state.latest_finalized.clone();
    }
}

fn is_descendant(store: &Store, ancestor: Root, descendant: Root) -> bool {
    let mut curr = descendant;
    while let Some(block) = store.blocks.get(&curr) {
        if curr == ancestor {
            return true;
        }
        if block.message.block.parent_root.0.is_zero() {
            return false;
        }
        curr = block.message.block.parent_root;
    }
    false
}

fn reorg_new_head(
    store: &Store,
    current_head: Root,
    new_head: Root,
    votes: &HashMap<ValidatorIndex, Checkpoint>,
) -> bool {
    let mut current_chain = vec![current_head];
    let mut curr = current_head;
    while let Some(block) = store.blocks.get(&curr) {
        if block.message.block.parent_root.0.is_zero() {
            break;
        }
        current_chain.push(block.message.block.parent_root);
        curr = block.message.block.parent_root;
    }

    let mut new_chain = vec![new_head];
    let mut curr = new_head;
    while let Some(block) = store.blocks.get(&curr) {
        if block.message.block.parent_root.0.is_zero() {
            break;
        }
        new_chain.push(block.message.block.parent_root);
        curr = block.message.block.parent_root;
    }

    let mut current_votes = 0;
    let mut new_votes = 0;

    for (_validator_idx, vote) in votes.iter() {
        let on_current_fork = current_chain.contains(&vote.root);
        let on_new_fork = new_chain.contains(&vote.root);

        if on_current_fork && !on_new_fork {
            current_votes += 1;
        } else if on_new_fork && !on_current_fork {
            new_votes += 1;
        }
    }

    let current_len = current_chain.len();
    let new_len = new_chain.len();

    if current_votes == 0 {
        true
    } else if new_len > current_len {
        true
    } else if new_votes == votes.len() {
        true
    } else {
        false
    }
}

pub fn update_safe_target(store: &mut Store) {
    let n_validators = if let Some(state) = store.states.get(&store.head) {
        let mut count: u64 = 0;
        let mut i: u64 = 0;
        loop {
            match state.validators.get(i) {
                Ok(_) => {
                    count += 1;
                    i += 1;
                }
                Err(_) => break,
            }
        }
        count as usize
    } else {
        0
    };

    let min_score = (n_validators * 2 + 2) / 3;
    let root = store.latest_justified.root;
    store.safe_target = get_fork_choice_head(store, root, &store.latest_new_votes, min_score);
}

pub fn accept_new_votes(store: &mut Store) {
    store
        .latest_known_votes
        .extend(store.latest_new_votes.drain());
    update_head(store);
}

// pakeist
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
    let mut target = store.head;
    let safe_slot = store.blocks[&store.safe_target].message.block.slot;

    for _ in 0..3 {
        if store.blocks[&target].message.block.slot > safe_slot {
            target = store.blocks[&target].message.block.parent_root;
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
        target = store.blocks[&target].message.block.parent_root;
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
    accept_new_votes(store);
    store.head
}
