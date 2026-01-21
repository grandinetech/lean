/// Head synchronization for processing gossip blocks.
///
/// Manages the processing of blocks received via gossip to advance the chain head.
/// Works in coordination with backfill sync to handle out-of-order block arrivals.
use containers::{Bytes32, SignedBlockWithAttestation, Slot};
use tracing::debug;

use super::block_cache::BlockCache;

/// Head synchronization manager.
///
/// Processes blocks to advance the chain head. Works with BlockCache to
/// handle blocks that arrive in any order.
///
/// ## How It Works
///
/// 1. Blocks arrive via gossip
/// 2. HeadSync adds them to the BlockCache
/// 3. If parent exists, block is processable immediately
/// 4. If parent missing, block is cached as orphan (BackfillSync will fetch parent)
/// 5. Once parent chain is complete, all descendants become processable
///
/// ## Integration
///
/// HeadSync coordinates with:
/// - **BlockCache**: Tracks blocks and identifies orphans
/// - **BackfillSync**: Fetches missing parents for orphans
/// - **SyncService**: Orchestrates overall sync flow
pub struct HeadSync {
    block_cache: BlockCache,
}

impl HeadSync {
    pub fn new(block_cache: BlockCache) -> Self {
        Self { block_cache }
    }

    /// Process a gossip block.
    ///
    /// Adds the block to the cache and returns information about what happened:
    /// - The block root
    /// - Whether the block is processable (parent exists)
    /// - Missing parent roots (if block is orphan)
    pub fn process_gossip_block(&mut self, block: SignedBlockWithAttestation) -> ProcessResult {
        let slot = block.message.block.slot;
        let parent_root = block.message.block.parent_root;

        debug!(
            slot = slot.0,
            parent = ?parent_root,
            "Processing gossip block"
        );

        // Add to cache
        let root = self.block_cache.add_block(block);

        // Check if processable
        let is_orphan = self.block_cache.is_orphan(&root);

        if is_orphan {
            debug!(
                slot = slot.0,
                root = ?root,
                "Block is orphan (parent unknown)"
            );

            // Get missing parents for backfill
            let missing_parents = if parent_root.0.is_zero() {
                vec![]
            } else if !self.block_cache.contains(&parent_root) {
                vec![parent_root]
            } else {
                vec![]
            };

            ProcessResult {
                root,
                is_processable: false,
                missing_parents,
            }
        } else {
            debug!(
                slot = slot.0,
                root = ?root,
                "Block is processable (parent known)"
            );

            ProcessResult {
                root,
                is_processable: true,
                missing_parents: vec![],
            }
        }
    }

    /// Get all blocks ready for processing.
    ///
    /// Returns blocks whose parents exist in the cache or are genesis.
    /// These blocks can be safely processed in topological order.
    pub fn get_processable_blocks(&self) -> Vec<Bytes32> {
        self.block_cache.get_processable_blocks()
    }

    /// Get a block by its root.
    pub fn get_block(&self, root: &Bytes32) -> Option<&SignedBlockWithAttestation> {
        self.block_cache.get_block(root)
    }

    /// Remove a block from the cache after processing.
    pub fn remove_block(&mut self, root: &Bytes32) -> Option<SignedBlockWithAttestation> {
        self.block_cache.remove_block(root)
    }

    /// Check if a block exists in the cache.
    pub fn contains_block(&self, root: &Bytes32) -> bool {
        self.block_cache.contains(root)
    }

    /// Get all orphan blocks.
    pub fn get_orphans(&self) -> Vec<Bytes32> {
        self.block_cache.get_orphans()
    }

    /// Get missing parent roots for all orphans.
    pub fn get_missing_parents(&self) -> Vec<Bytes32> {
        self.block_cache.get_missing_parents()
    }

    /// Get reference to block cache.
    pub fn block_cache(&self) -> &BlockCache {
        &self.block_cache
    }

    /// Get mutable reference to block cache.
    pub fn block_cache_mut(&mut self) -> &mut BlockCache {
        &mut self.block_cache
    }

    /// Get the highest slot among cached blocks.
    pub fn get_highest_cached_slot(&self) -> Option<Slot> {
        self.block_cache
            .get_processable_blocks()
            .iter()
            .filter_map(|root| self.block_cache.get_slot(root))
            .max()
    }

    /// Get statistics about the cache.
    pub fn get_stats(&self) -> HeadSyncStats {
        let total_blocks = self.block_cache.len();
        let orphan_blocks = self.block_cache.get_orphans().len();
        let processable_blocks = self.block_cache.get_processable_blocks().len();

        HeadSyncStats {
            total_blocks,
            orphan_blocks,
            processable_blocks,
        }
    }
}

/// Result of processing a gossip block.
#[derive(Debug, Clone)]
pub struct ProcessResult {
    /// The root of the processed block
    pub root: Bytes32,

    /// Whether the block can be processed immediately
    pub is_processable: bool,

    /// Missing parent roots (if block is orphan)
    pub missing_parents: Vec<Bytes32>,
}

/// Statistics about the head sync cache.
#[derive(Debug, Clone, Copy)]
pub struct HeadSyncStats {
    pub total_blocks: usize,
    pub orphan_blocks: usize,
    pub processable_blocks: usize,
}
