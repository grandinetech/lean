use containers::{Bytes32, SignedBlockWithAttestation};
use libp2p_identity::PeerId;
/// Backfill synchronization for resolving orphan blocks.
///
/// When a block arrives whose parent is unknown, we need to fetch that parent.
/// If the parent also has an unknown parent, we continue recursively. This process
/// is called "backfill" because we are filling in gaps going backward in time.
///
/// ## The Challenge
///
/// Blocks can arrive out of order for several reasons:
/// 1. **Gossip timing**: A child block gossips faster than its parent
/// 2. **Parallel downloads**: Responses arrive in different order than requests
/// 3. **Network partitions**: Some blocks were missed during a brief disconnect
///
/// Without backfill, these orphan blocks would be useless. With backfill, we can
/// resolve their parent chains and process them.
///
/// ## Safety: Depth Limits
///
/// - An attacker could send a block claiming to have a parent millions of slots ago
/// - Without limits, we would exhaust memory trying to fetch the entire chain
/// - MAX_BACKFILL_DEPTH (512) covers legitimate reorgs while bounding resources
use std::collections::HashSet;
use tracing::{debug, warn};

use super::{
    block_cache::BlockCache,
    config::{MAX_BACKFILL_DEPTH, MAX_BLOCKS_PER_REQUEST},
    peer_manager::PeerManager,
};

/// Network requester trait for fetching blocks.
///
/// Abstracts the network layer to allow testing with mocks.
#[async_trait::async_trait]
pub trait NetworkRequester: Send + Sync {
    /// Request blocks by their roots from a peer.
    ///
    /// Returns the blocks if successful, or None if the request failed.
    async fn request_blocks_by_root(
        &self,
        peer_id: PeerId,
        roots: Vec<Bytes32>,
    ) -> Option<Vec<SignedBlockWithAttestation>>;
}

/// Backfill synchronization manager.
///
/// Resolves orphan blocks by fetching their missing parents. When blocks
/// arrive with unknown parents, this class orchestrates fetching those parents.
///
/// ## How It Works
///
/// 1. **Detection**: BlockCache marks blocks as orphans when added
/// 2. **Request**: BackfillSync requests missing parents from peers
/// 3. **Recursion**: If fetched parents are also orphans, continue fetching
/// 4. **Resolution**: When parent chain is complete, blocks become processable
///
/// ## Integration
///
/// BackfillSync does not process blocks itself. It only ensures parents exist
/// in the BlockCache. The SyncService is responsible for:
/// - Calling `fill_missing()` when orphans are detected
/// - Processing blocks when they become processable
/// - Integrating blocks into the Store
///
/// ## Thread Safety
///
/// This class is designed for single-threaded async operation. The `_pending`
/// set prevents duplicate requests for the same root.
pub struct BackfillSync<N: NetworkRequester> {
    peer_manager: PeerManager,
    block_cache: BlockCache,
    network: N,

    /// Roots currently being fetched (prevents duplicate requests)
    pending: HashSet<Bytes32>,
}

impl<N: NetworkRequester> BackfillSync<N> {
    pub fn new(peer_manager: PeerManager, block_cache: BlockCache, network: N) -> Self {
        Self {
            peer_manager,
            block_cache,
            network,
            pending: HashSet::new(),
        }
    }

    /// Fill missing parent blocks for orphans.
    ///
    /// Recursively fetches parents until:
    /// - All parents are found
    /// - MAX_BACKFILL_DEPTH is reached
    /// - No peers are available
    ///
    /// This method is idempotent and safe to call multiple times.
    pub async fn fill_missing(&mut self, roots: Vec<Bytes32>, depth: usize) {
        self.fill_missing_internal(roots, depth).await;
    }

    fn fill_missing_internal<'a>(
        &'a mut self,
        roots: Vec<Bytes32>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if depth >= MAX_BACKFILL_DEPTH {
                // Depth limit reached. Stop fetching to prevent resource exhaustion.
                // This is a safety measure, not an error. Deep chains may be
                // legitimate but we cannot fetch them via backfill.
                debug!(
                    depth = depth,
                    max_depth = MAX_BACKFILL_DEPTH,
                    "Backfill depth limit reached"
                );
                return;
            }

            // Filter out roots we are already fetching or have cached
            let roots_to_fetch: Vec<Bytes32> = roots
                .into_iter()
                .filter(|root| !self.pending.contains(root) && !self.block_cache.contains(root))
                .collect();

            if roots_to_fetch.is_empty() {
                return;
            }

            debug!(
                num_roots = roots_to_fetch.len(),
                depth = depth,
                "Backfilling missing parents"
            );

            // Mark roots as pending to avoid duplicate requests
            for root in &roots_to_fetch {
                self.pending.insert(*root);
            }

            // Fetch in batches to respect request limits
            for batch_start in (0..roots_to_fetch.len()).step_by(MAX_BLOCKS_PER_REQUEST) {
                let batch_end = (batch_start + MAX_BLOCKS_PER_REQUEST).min(roots_to_fetch.len());
                let batch = roots_to_fetch[batch_start..batch_end].to_vec();

                self.fetch_batch(batch, depth).await;
            }

            // Clear pending status
            for root in &roots_to_fetch {
                self.pending.remove(root);
            }
        })
    }

    async fn fetch_batch(&mut self, roots: Vec<Bytes32>, depth: usize) {
        // Select a peer for the request
        let peer = match self.peer_manager.select_peer_for_request(None) {
            Some(p) => p.peer_id,
            None => {
                debug!("No available peer for backfill request");
                return;
            }
        };

        debug!(
            peer = %peer,
            num_roots = roots.len(),
            depth = depth,
            "Requesting blocks from peer"
        );

        // Mark request as started
        self.peer_manager.on_request_start(&peer);

        // Request blocks
        match self
            .network
            .request_blocks_by_root(peer, roots.clone())
            .await
        {
            Some(blocks) if !blocks.is_empty() => {
                debug!(
                    peer = %peer,
                    num_blocks = blocks.len(),
                    "Received blocks from peer"
                );

                self.peer_manager.on_request_complete(&peer);
                self.process_received_blocks(blocks, peer, depth).await;
            }
            Some(_) => {
                // Empty response. Peer may not have the blocks.
                debug!(peer = %peer, "Peer returned no blocks");
                self.peer_manager.on_request_complete(&peer);
            }
            None => {
                // Network error
                warn!(peer = %peer, "Block request failed");
                self.peer_manager
                    .on_request_failure(&peer, "backfill request failed");
            }
        }
    }

    async fn process_received_blocks(
        &mut self,
        blocks: Vec<SignedBlockWithAttestation>,
        peer_id: PeerId,
        depth: usize,
    ) {
        let mut new_orphan_parents = Vec::new();

        for block in blocks {
            let root = self.block_cache.add_block(block);

            // If this block is an orphan, we need to fetch its parent
            if self.block_cache.is_orphan(&root) {
                if let Some(parent_root) = self
                    .block_cache
                    .get_block(&root)
                    .map(|b| b.message.block.parent_root)
                {
                    if !parent_root.0.is_zero() {
                        new_orphan_parents.push(parent_root);
                    }
                }
            }
        }

        // Recursively fetch parents of newly discovered orphans
        if !new_orphan_parents.is_empty() {
            debug!(
                peer = %peer_id,
                num_parents = new_orphan_parents.len(),
                next_depth = depth + 1,
                "Found orphan parents, continuing backfill"
            );

            self.fill_missing_internal(new_orphan_parents, depth + 1)
                .await;
        }
    }

    /// Get reference to block cache.
    pub fn block_cache(&self) -> &BlockCache {
        &self.block_cache
    }

    /// Get mutable reference to block cache.
    pub fn block_cache_mut(&mut self) -> &mut BlockCache {
        &mut self.block_cache
    }

    /// Get reference to peer manager.
    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager
    }

    /// Get mutable reference to peer manager.
    pub fn peer_manager_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_manager
    }
}
