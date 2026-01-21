/// Block cache for managing blocks and tracking orphans.
///
/// Maintains a cache of blocks and identifies orphans (blocks whose parent
/// is not yet known). This is essential for handling out-of-order block arrival.

use std::collections::{HashMap, HashSet};
use containers::{Bytes32, SignedBlockWithAttestation, Slot};
use containers::block::hash_tree_root;

/// Block cache for sync operations.
///
/// Manages blocks during synchronization and tracks orphans (blocks with
/// unknown parents). When blocks arrive out of order, orphans are cached
/// until their parent chains can be resolved.
#[derive(Debug, Default, Clone)]
pub struct BlockCache {
    /// All cached blocks, indexed by block root
    blocks: HashMap<Bytes32, SignedBlockWithAttestation>,
    
    /// Blocks whose parent is not in the cache (orphans)
    orphans: HashSet<Bytes32>,
    
    /// Children of each block (parent_root -> set of child roots)
    children: HashMap<Bytes32, HashSet<Bytes32>>,
}

impl BlockCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a block to the cache.
    ///
    /// Automatically detects if the block is an orphan and tracks it.
    /// Returns the block root.
    pub fn add_block(&mut self, block: SignedBlockWithAttestation) -> Bytes32 {
        let root = hash_tree_root(&block.message.block);
        let parent_root = block.message.block.parent_root;

        // Add to cache
        self.blocks.insert(root, block);

        // Track parent-child relationship
        self.children.entry(parent_root)
            .or_insert_with(HashSet::new)
            .insert(root);

        // Check if this is an orphan (parent not in cache)
        if !parent_root.0.is_zero() && !self.blocks.contains_key(&parent_root) {
            self.orphans.insert(root);
        }

        // If adding this block resolves any orphans, remove them from orphan set
        if let Some(children) = self.children.get(&root) {
            for child in children {
                self.orphans.remove(child);
            }
        }

        root
    }

    /// Get a block by its root.
    pub fn get_block(&self, root: &Bytes32) -> Option<&SignedBlockWithAttestation> {
        self.blocks.get(root)
    }

    /// Check if a block exists in the cache.
    pub fn contains(&self, root: &Bytes32) -> bool {
        self.blocks.contains_key(root)
    }

    /// Check if a block is an orphan (parent unknown).
    pub fn is_orphan(&self, root: &Bytes32) -> bool {
        self.orphans.contains(root)
    }

    /// Get all orphan block roots.
    pub fn get_orphans(&self) -> Vec<Bytes32> {
        self.orphans.iter().copied().collect()
    }

    /// Get missing parent roots for orphan blocks.
    ///
    /// Returns roots of parents that are not in the cache.
    pub fn get_missing_parents(&self) -> Vec<Bytes32> {
        self.orphans.iter()
            .filter_map(|orphan_root| {
                self.blocks.get(orphan_root)
                    .map(|block| block.message.block.parent_root)
            })
            .filter(|parent_root| !parent_root.0.is_zero() && !self.blocks.contains_key(parent_root))
            .collect::<HashSet<_>>() // Deduplicate
            .into_iter()
            .collect()
    }

    /// Get all processable blocks (blocks whose parent is known or is genesis).
    ///
    /// Returns blocks that can be processed because their parent exists
    /// in the cache or they are genesis blocks (parent_root is zero).
    pub fn get_processable_blocks(&self) -> Vec<Bytes32> {
        self.blocks.iter()
            .filter_map(|(root, block)| {
                let parent_root = block.message.block.parent_root;
                if parent_root.0.is_zero() || self.blocks.contains_key(&parent_root) {
                    Some(*root)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remove a block from the cache.
    ///
    /// Also updates orphan tracking and parent-child relationships.
    pub fn remove_block(&mut self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        if let Some(block) = self.blocks.remove(root) {
            // Remove from orphan set if present
            self.orphans.remove(root);

            // Remove from parent's children set
            let parent_root = block.message.block.parent_root;
            if let Some(children) = self.children.get_mut(&parent_root) {
                children.remove(root);
                if children.is_empty() {
                    self.children.remove(&parent_root);
                }
            }

            // Mark children as orphans if removing this block orphans them
            if let Some(children) = self.children.get(root) {
                for child in children {
                    self.orphans.insert(*child);
                }
            }

            Some(block)
        } else {
            None
        }
    }

    /// Get the slot of a block.
    pub fn get_slot(&self, root: &Bytes32) -> Option<Slot> {
        self.blocks.get(root).map(|block| block.message.block.slot)
    }

    /// Get children of a block.
    pub fn get_children(&self, root: &Bytes32) -> Vec<Bytes32> {
        self.children.get(root)
            .map(|children| children.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get chain length from a block back to genesis or earliest cached ancestor.
    ///
    /// Returns None if the block is not in the cache.
    pub fn get_chain_length(&self, root: &Bytes32) -> Option<usize> {
        if !self.blocks.contains_key(root) {
            return None;
        }

        let mut length = 0;
        let mut current = *root;

        loop {
            if let Some(block) = self.blocks.get(&current) {
                let parent_root = block.message.block.parent_root;
                if parent_root.0.is_zero() {
                    // Reached genesis
                    break;
                }
                length += 1;
                if !self.blocks.contains_key(&parent_root) {
                    // Parent not in cache, can't continue
                    break;
                }
                current = parent_root;
            } else {
                break;
            }
        }

        Some(length)
    }

    /// Clear all blocks from the cache.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.orphans.clear();
        self.children.clear();
    }

    /// Get the number of cached blocks.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}
