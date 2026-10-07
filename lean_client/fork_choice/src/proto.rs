use std::collections::HashMap;

use containers::{AggregatedSignatureProof, AttestationData};
use ssz::H256;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct ProtoNode {
    pub slot: u64,
    pub root: H256,
    pub parent: Option<usize>,
    pub weight: u64,
    pub best_child: Option<usize>,
    pub best_descendant: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct ProtoArray {
    nodes: Vec<ProtoNode>,
    indices: HashMap<H256, usize>,
}

impl ProtoArray {
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn index_of(&self, root: &H256) -> Option<usize> {
        self.indices.get(root).copied()
    }

    pub fn root_at(&self, index: usize) -> Option<H256> {
        self.nodes.get(index).map(|n| n.root)
    }

    pub fn on_block(&mut self, slot: u64, root: H256, parent_root: H256) -> bool {
        if self.indices.contains_key(&root) {
            return true;
        }
        let parent = self.indices.get(&parent_root).copied();
        if self.nodes.is_empty() {
            self.nodes.push(ProtoNode {
                slot,
                root,
                parent: None,
                weight: 0,
                best_child: None,
                best_descendant: None,
            });
            self.indices.insert(root, 0);
            return true;
        }
        let Some(parent_index) = parent else {
            return false;
        };
        if slot <= self.nodes[parent_index].slot {
            return false;
        }
        let index = self.nodes.len();
        self.nodes.push(ProtoNode {
            slot,
            root,
            parent: Some(parent_index),
            weight: 0,
            best_child: None,
            best_descendant: None,
        });
        self.indices.insert(root, index);
        true
    }

    pub fn apply_score_changes(&mut self, mut deltas: Vec<i64>, cutoff: u64) {
        if deltas.len() != self.nodes.len() {
            return;
        }
        for i in (0..self.nodes.len()).rev() {
            let delta = deltas[i];
            let parent = self.nodes[i].parent;
            let node = &mut self.nodes[i];
            node.weight = if delta >= 0 {
                node.weight.saturating_add(delta as u64)
            } else {
                node.weight.saturating_sub(delta.unsigned_abs())
            };
            if let Some(p) = parent {
                deltas[p] += delta;
            }
        }
        for node in &mut self.nodes {
            node.best_child = None;
            node.best_descendant = None;
        }
        for i in (1..self.nodes.len()).rev() {
            let Some(p) = self.nodes[i].parent else {
                continue;
            };
            if self.nodes[i].weight < cutoff {
                continue;
            }
            let candidate_descendant = self.nodes[i].best_descendant.unwrap_or(i);
            let better = match self.nodes[p].best_child {
                None => true,
                Some(b) => {
                    (self.nodes[i].weight, self.nodes[i].root)
                        > (self.nodes[b].weight, self.nodes[b].root)
                }
            };
            if better {
                self.nodes[p].best_child = Some(i);
                self.nodes[p].best_descendant = Some(candidate_descendant);
            }
        }
    }

    pub fn find_head(&self, root: &H256) -> Option<H256> {
        let index = self.index_of(root)?;
        Some(match self.nodes[index].best_descendant {
            Some(d) => self.nodes[d].root,
            None => self.nodes[index].root,
        })
    }

    pub fn prune(&mut self, finalized_root: &H256) -> Option<HashMap<usize, usize>> {
        let finalized_index = self.index_of(finalized_root)?;
        if finalized_index == 0 {
            return None;
        }
        let mut keep = vec![false; self.nodes.len()];
        let mut index_map = HashMap::new();
        let mut new_nodes: Vec<ProtoNode> = Vec::with_capacity(self.nodes.len() - finalized_index);
        for i in 0..self.nodes.len() {
            let is_finalized = i == finalized_index;
            let parent_kept = self.nodes[i].parent.map(|p| keep[p]).unwrap_or(false);
            if !(is_finalized || parent_kept) {
                continue;
            }
            keep[i] = true;
            index_map.insert(i, new_nodes.len());
            let mut node = self.nodes[i].clone();
            node.parent = if is_finalized {
                None
            } else {
                node.parent.and_then(|p| index_map.get(&p).copied())
            };
            node.best_child = None;
            node.best_descendant = None;
            new_nodes.push(node);
        }
        self.indices = new_nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.root, i))
            .collect();
        self.nodes = new_nodes;
        Some(index_map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteTarget {
    pub index: usize,
    pub slot: u64,
    pub data_root: H256,
}

fn stronger(a: &VoteTarget, b: &VoteTarget) -> bool {
    (a.slot, a.data_root) > (b.slot, b.data_root)
}

#[derive(Debug, Clone, Default)]
pub struct VoteTracker {
    pub applied: Option<usize>,
    pub known: Option<VoteTarget>,
    pub new: Option<VoteTarget>,
}

#[derive(Debug, Clone, Default)]
pub struct VoteStore {
    trackers: Vec<VoteTracker>,
}

impl VoteStore {
    fn tracker_mut(&mut self, validator: u64) -> &mut VoteTracker {
        let index = validator as usize;
        if index >= self.trackers.len() {
            self.trackers.resize_with(index + 1, VoteTracker::default);
        }
        &mut self.trackers[index]
    }

    pub fn set_new(&mut self, validator: u64, target: VoteTarget) {
        let tracker = self.tracker_mut(validator);
        if tracker.new.map_or(true, |cur| stronger(&target, &cur)) {
            tracker.new = Some(target);
        }
    }

    pub fn set_known(&mut self, validator: u64, target: VoteTarget) {
        let tracker = self.tracker_mut(validator);
        if tracker.known.map_or(true, |cur| stronger(&target, &cur)) {
            tracker.known = Some(target);
        }
    }

    pub fn promote_new_to_known(&mut self) {
        for tracker in &mut self.trackers {
            if let Some(new) = tracker.new.take() {
                if tracker.known.map_or(true, |cur| stronger(&new, &cur)) {
                    tracker.known = Some(new);
                }
            }
        }
    }

    pub fn compute_deltas(&mut self, num_nodes: usize, from_known: bool) -> Vec<i64> {
        let mut deltas = vec![0i64; num_nodes];
        for tracker in &mut self.trackers {
            if let Some(applied) = tracker.applied.take() {
                if applied < num_nodes {
                    deltas[applied] -= 1;
                }
            }
            let target = if from_known {
                tracker.known
            } else {
                tracker.new
            };
            if let Some(target) = target {
                if target.index < num_nodes {
                    deltas[target.index] += 1;
                    tracker.applied = Some(target.index);
                }
            }
        }
        deltas
    }

    pub fn remap(&mut self, index_map: &HashMap<usize, usize>) {
        for tracker in &mut self.trackers {
            tracker.applied = tracker.applied.and_then(|i| index_map.get(&i).copied());
            tracker.known = tracker.known.and_then(|mut t| {
                index_map.get(&t.index).map(|&i| {
                    t.index = i;
                    t
                })
            });
            tracker.new = tracker.new.and_then(|mut t| {
                index_map.get(&t.index).map(|&i| {
                    t.index = i;
                    t
                })
            });
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProtoForkChoice {
    array: ProtoArray,
    votes: VoteStore,
}

impl ProtoForkChoice {
    pub fn on_block(&mut self, slot: u64, root: H256, parent_root: H256) {
        if !self.array.on_block(slot, root, parent_root) {
            warn!(
                slot,
                %root,
                %parent_root,
                "proto fork choice rejected block: parent unknown or slot not above parent"
            );
        }
    }

    pub fn contains_block(&self, root: &H256) -> bool {
        self.array.index_of(root).is_some()
    }

    pub fn num_nodes(&self) -> usize {
        self.array.len()
    }

    pub fn ingest_payload(
        &mut self,
        data: &AttestationData,
        data_root: H256,
        proof: &AggregatedSignatureProof,
        known: bool,
    ) {
        let Some(index) = self.array.index_of(&data.head.root) else {
            return;
        };
        let target = VoteTarget {
            index,
            slot: data.slot.0,
            data_root,
        };
        for validator in proof.get_participant_indices() {
            if known {
                self.votes.set_known(validator, target);
            } else {
                self.votes.set_new(validator, target);
            }
        }
    }

    pub fn promote_new_to_known(&mut self) {
        self.votes.promote_new_to_known();
    }

    pub fn update_head(&mut self, justified_root: &H256) -> Option<H256> {
        let root = self.resolve_root(justified_root)?;
        let deltas = self.votes.compute_deltas(self.array.len(), true);
        self.array.apply_score_changes(deltas, 0);
        self.array.find_head(&root)
    }

    pub fn update_safe_target(&mut self, justified_root: &H256, min_score: u64) -> Option<H256> {
        let root = self.resolve_root(justified_root)?;
        let deltas = self.votes.compute_deltas(self.array.len(), false);
        self.array.apply_score_changes(deltas, min_score);
        self.array.find_head(&root)
    }

    fn resolve_root(&self, justified_root: &H256) -> Option<H256> {
        if justified_root.is_zero() {
            return self.array.root_at(0);
        }
        Some(*justified_root)
    }

    pub fn prune(&mut self, finalized_root: &H256) {
        if let Some(index_map) = self.array.prune(finalized_root) {
            self.votes.remap(&index_map);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 16
        }
    }

    fn h(byte: u64) -> H256 {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&byte.to_be_bytes());
        H256(out)
    }

    fn oracle_head(
        blocks: &HashMap<H256, (u64, H256)>,
        mut root: H256,
        votes: &HashMap<u64, (H256, u64)>,
        min_votes: usize,
    ) -> H256 {
        if root.is_zero() {
            root = *blocks
                .iter()
                .min_by_key(|(_, (slot, _))| *slot)
                .map(|(r, _)| r)
                .unwrap();
        }
        let root_slot = match blocks.get(&root) {
            Some((slot, _)) => *slot,
            None => return root,
        };
        let mut vote_weights: HashMap<H256, usize> = HashMap::new();
        for (head_root, _) in votes.values() {
            let mut curr = *head_root;
            if let Some((slot, _)) = blocks.get(&curr) {
                let mut curr_slot = *slot;
                while curr_slot > root_slot {
                    *vote_weights.entry(curr).or_insert(0) += 1;
                    if let Some((_, parent)) = blocks.get(&curr) {
                        curr = *parent;
                        if curr.is_zero() {
                            break;
                        }
                        if let Some((next_slot, _)) = blocks.get(&curr) {
                            curr_slot = *next_slot;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        let mut child_map: HashMap<H256, Vec<H256>> = HashMap::new();
        for (block_hash, (_, parent)) in blocks {
            if !parent.is_zero()
                && vote_weights.get(block_hash).copied().unwrap_or(0) >= min_votes
            {
                child_map.entry(*parent).or_default().push(*block_hash);
            }
        }
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
                    wa.cmp(&wb).then_with(|| a.cmp(&b))
                })
                .unwrap();
        }
    }

    struct Scenario {
        blocks: HashMap<H256, (u64, H256)>,
        proto: ProtoForkChoice,
        anchor: H256,
        roots: Vec<H256>,
    }

    fn random_scenario(rng: &mut Lcg, num_blocks: usize) -> Scenario {
        let anchor = h(1);
        let mut blocks = HashMap::new();
        blocks.insert(anchor, (0u64, H256::zero()));
        let mut proto = ProtoForkChoice::default();
        proto.on_block(0, anchor, H256::zero());
        let mut roots = vec![anchor];
        for i in 1..num_blocks {
            let parent = roots[(rng.next() as usize) % roots.len()];
            let parent_slot = blocks[&parent].0;
            let slot = parent_slot + 1 + rng.next() % 3;
            let root = h(0x1000 + i as u64 * 7 + rng.next() % 5);
            if blocks.contains_key(&root) {
                continue;
            }
            blocks.insert(root, (slot, parent));
            proto.on_block(slot, root, parent);
            roots.push(root);
        }
        Scenario {
            blocks,
            proto,
            anchor,
            roots,
        }
    }

    fn random_votes(
        rng: &mut Lcg,
        scenario: &mut Scenario,
        num_validators: u64,
        known: bool,
    ) -> HashMap<u64, (H256, u64)> {
        let mut per_validator: HashMap<u64, Vec<(u64, H256, H256)>> = HashMap::new();
        for validator in 0..num_validators {
            let num_votes = 1 + rng.next() % 3;
            for _ in 0..num_votes {
                let head = scenario.roots[(rng.next() as usize) % scenario.roots.len()];
                let vote_slot = scenario.blocks[&head].0 + rng.next() % 4;
                let data_root = h(0x9000_0000 + vote_slot * 131 + (head.0[7] as u64));
                per_validator
                    .entry(validator)
                    .or_default()
                    .push((vote_slot, data_root, head));
            }
        }
        let mut expected = HashMap::new();
        for (validator, mut entries) in per_validator {
            for (vote_slot, data_root, head) in &entries {
                let index = scenario.proto.array.index_of(head).unwrap();
                let target = VoteTarget {
                    index,
                    slot: *vote_slot,
                    data_root: *data_root,
                };
                if known {
                    scenario.proto.votes.set_known(validator, target);
                } else {
                    scenario.proto.votes.set_new(validator, target);
                }
            }
            entries.sort_by(|a, b| (b.0, b.1).cmp(&(a.0, a.1)));
            let (slot, _, head) = entries[0];
            expected.insert(validator, (head, slot));
        }
        expected
    }

    #[test]
    fn head_matches_oracle_randomized() {
        let mut rng = Lcg(42);
        for round in 0..200 {
            let mut scenario = random_scenario(&mut rng, 2 + (round % 40));
            let votes = random_votes(&mut rng, &mut scenario, 1 + round as u64 % 32, true);
            let proto_head = scenario.proto.update_head(&scenario.anchor).unwrap();
            let oracle = oracle_head(&scenario.blocks, scenario.anchor, &votes, 0);
            assert_eq!(proto_head, oracle, "round {round}");
        }
    }

    #[test]
    fn safe_target_matches_oracle_randomized() {
        let mut rng = Lcg(1337);
        for round in 0..200 {
            let mut scenario = random_scenario(&mut rng, 2 + (round % 40));
            let num_validators = 1 + round as u64 % 32;
            let votes = random_votes(&mut rng, &mut scenario, num_validators, false);
            let min_score = (num_validators as usize * 2 + 2) / 3;
            let proto_target = scenario
                .proto
                .update_safe_target(&scenario.anchor, min_score as u64)
                .unwrap();
            let oracle = oracle_head(&scenario.blocks, scenario.anchor, &votes, min_score);
            assert_eq!(proto_target, oracle, "round {round}");
        }
    }

    #[test]
    fn alternating_pools_keep_weights_consistent() {
        let mut rng = Lcg(7);
        let mut scenario = random_scenario(&mut rng, 30);
        let known = random_votes(&mut rng, &mut scenario, 16, true);
        let newer = random_votes(&mut rng, &mut scenario, 16, false);
        for _ in 0..5 {
            let target = scenario.proto.update_safe_target(&scenario.anchor, 11);
            let head = scenario.proto.update_head(&scenario.anchor).unwrap();
            let oracle = oracle_head(&scenario.blocks, scenario.anchor, &known, 0);
            assert_eq!(head, oracle);
            let oracle_target = oracle_head(&scenario.blocks, scenario.anchor, &newer, 11);
            assert_eq!(target.unwrap(), oracle_target);
        }
    }

    #[test]
    fn promote_keeps_strongest_vote() {
        let mut proto = ProtoForkChoice::default();
        let a = h(1);
        let b = h(2);
        proto.on_block(0, a, H256::zero());
        proto.on_block(1, b, a);
        let strong = VoteTarget {
            index: 1,
            slot: 9,
            data_root: h(0xAA),
        };
        let weak = VoteTarget {
            index: 0,
            slot: 3,
            data_root: h(0xBB),
        };
        proto.votes.set_known(0, strong);
        proto.votes.set_new(0, weak);
        proto.promote_new_to_known();
        assert_eq!(proto.votes.trackers[0].known, Some(strong));
        assert_eq!(proto.votes.trackers[0].new, None);
    }

    #[test]
    fn set_vote_keeps_max_slot_and_root() {
        let mut votes = VoteStore::default();
        let first = VoteTarget {
            index: 1,
            slot: 5,
            data_root: h(0x20),
        };
        let older = VoteTarget {
            index: 2,
            slot: 4,
            data_root: h(0xFF),
        };
        let same_slot_higher_root = VoteTarget {
            index: 3,
            slot: 5,
            data_root: h(0x30),
        };
        votes.set_known(0, first);
        votes.set_known(0, older);
        assert_eq!(votes.trackers[0].known, Some(first));
        votes.set_known(0, same_slot_higher_root);
        assert_eq!(votes.trackers[0].known, Some(same_slot_higher_root));
    }

    #[test]
    fn prune_keeps_finalized_subtree_and_remaps_votes() {
        let mut rng = Lcg(99);
        let mut scenario = random_scenario(&mut rng, 40);
        let votes = random_votes(&mut rng, &mut scenario, 20, true);
        let head_before = scenario.proto.update_head(&scenario.anchor).unwrap();
        let mut finalized = head_before;
        for _ in 0..3 {
            if let Some((_, parent)) = scenario.blocks.get(&finalized) {
                if !parent.is_zero() && scenario.blocks.contains_key(parent) {
                    finalized = *parent;
                }
            }
        }
        scenario.proto.prune(&finalized);
        assert!(scenario.proto.contains_block(&finalized));
        assert!(scenario.proto.contains_block(&head_before));
        let head_after = scenario.proto.update_head(&finalized).unwrap();
        let surviving: HashMap<H256, (u64, H256)> = scenario
            .blocks
            .iter()
            .filter(|(root, _)| scenario.proto.contains_block(root))
            .map(|(r, v)| (*r, *v))
            .collect();
        let surviving_votes: HashMap<u64, (H256, u64)> = votes
            .into_iter()
            .filter(|(_, (head, _))| surviving.contains_key(head))
            .collect();
        let oracle = oracle_head(&surviving, finalized, &surviving_votes, 0);
        assert_eq!(head_after, oracle);
    }

    #[test]
    fn empty_array_bootstraps_from_first_block() {
        let mut proto = ProtoForkChoice::default();
        let genesis = h(5);
        proto.on_block(0, genesis, H256::zero());
        assert!(proto.contains_block(&genesis));
        assert_eq!(proto.update_head(&genesis), Some(genesis));
        assert_eq!(proto.update_head(&H256::zero()), Some(genesis));
    }
}
