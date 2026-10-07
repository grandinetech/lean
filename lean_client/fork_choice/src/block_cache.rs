use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use containers::{SignedBlock, Slot};
use ssz::H256;

pub const MAX_CACHED_BLOCKS: usize = 1024;

#[derive(Debug, Clone)]
pub struct PendingBlock {
    pub block: SignedBlock,
    pub root: H256,
    pub parent_root: H256,
    pub slot: Slot,
    pub received_from: Option<String>,
    pub received_at: Instant,
    pub backfill_depth: u32,
}

pub struct BlockCache {
    blocks: HashMap<H256, PendingBlock>,
    insertion_order: VecDeque<H256>,
    by_parent: HashMap<H256, HashSet<H256>>,
    orphans: HashSet<H256>,
    capacity: usize,
}

impl BlockCache {
    pub fn new() -> Self {
        Self::with_capacity(MAX_CACHED_BLOCKS)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            blocks: HashMap::new(),
            insertion_order: VecDeque::new(),
            by_parent: HashMap::new(),
            orphans: HashSet::new(),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    pub fn contains(&self, root: &H256) -> bool {
        self.blocks.contains_key(root)
    }

    pub fn add(
        &mut self,
        block: SignedBlock,
        root: H256,
        parent_root: H256,
        slot: Slot,
        received_from: Option<String>,
        backfill_depth: u32,
    ) {
        if self.blocks.contains_key(&root) {
            return;
        }

        if self.blocks.len() >= self.capacity {
            self.evict_oldest();
        }

        let pending = PendingBlock {
            block,
            root,
            parent_root,
            slot,
            received_from,
            received_at: Instant::now(),
            backfill_depth,
        };

        self.blocks.insert(root, pending);
        self.insertion_order.push_back(root);
        self.by_parent
            .entry(parent_root)
            .or_insert_with(HashSet::new)
            .insert(root);
    }

    pub fn get(&self, root: &H256) -> Option<&PendingBlock> {
        self.blocks.get(root)
    }

    pub fn remove(&mut self, root: &H256) -> Option<PendingBlock> {
        let pending = self.blocks.remove(root)?;

        self.insertion_order.retain(|r| r != root);
        self.orphans.remove(root);

        if let Some(children) = self.by_parent.get_mut(&pending.parent_root) {
            children.remove(root);
            if children.is_empty() {
                self.by_parent.remove(&pending.parent_root);
            }
        }

        Some(pending)
    }

    pub fn get_children(&self, parent_root: &H256) -> Vec<&PendingBlock> {
        let Some(child_roots) = self.by_parent.get(parent_root) else {
            return Vec::new();
        };

        let mut children: Vec<&PendingBlock> = child_roots
            .iter()
            .filter_map(|r| self.blocks.get(r))
            .collect();

        children.sort_by_key(|p| p.slot.0);
        children
    }

    pub fn mark_orphan(&mut self, root: H256) {
        if self.blocks.contains_key(&root) {
            self.orphans.insert(root);
        }
    }

    pub fn unmark_orphan(&mut self, root: &H256) {
        self.orphans.remove(root);
    }

    pub fn get_orphan_parents(&self) -> Vec<H256> {
        let mut seen = HashSet::new();
        for root in &self.orphans {
            if let Some(pending) = self.blocks.get(root) {
                if !self.blocks.contains_key(&pending.parent_root) {
                    seen.insert(pending.parent_root);
                }
            }
        }
        seen.into_iter().collect()
    }

    pub fn get_orphan_parents_with_hints(&self) -> Vec<(H256, Option<String>)> {
        let mut results: HashMap<H256, Option<String>> = HashMap::new();
        for root in &self.orphans {
            if let Some(pending) = self.blocks.get(root) {
                if !self.blocks.contains_key(&pending.parent_root) {
                    results
                        .entry(pending.parent_root)
                        .or_insert_with(|| pending.received_from.clone());
                }
            }
        }
        results.into_iter().collect()
    }

    pub fn prune_finalized(&mut self, finalized_slot: Slot) {
        let stale: Vec<H256> = self
            .blocks
            .iter()
            .filter(|(_, pending)| pending.slot <= finalized_slot)
            .map(|(root, _)| *root)
            .collect();
        for root in stale {
            self.remove(&root);
        }
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.insertion_order.clear();
        self.by_parent.clear();
        self.orphans.clear();
    }

    fn evict_oldest(&mut self) {
        let Some(oldest_root) = self.insertion_order.pop_front() else {
            return;
        };

        self.orphans.remove(&oldest_root);

        if let Some(block) = self.blocks.remove(&oldest_root) {
            if let Some(children) = self.by_parent.get_mut(&block.parent_root) {
                children.remove(&oldest_root);
                if children.is_empty() {
                    self.by_parent.remove(&block.parent_root);
                }
            }
        }
    }
}

impl Default for BlockCache {
    fn default() -> Self {
        Self::new()
    }
}
