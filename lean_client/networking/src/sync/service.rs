use containers::{Bytes32, SignedBlockWithAttestation, Slot};
use libp2p_identity::PeerId;
use parking_lot::Mutex;
/// Sync service coordinating all synchronization operations.
///
/// The SyncService is the main entry point for synchronization. It coordinates:
/// - HeadSync: Processing gossip blocks
/// - BackfillSync: Fetching missing parent blocks
/// - PeerManager: Tracking peer status
/// - State machine: Managing IDLE -> SYNCING -> SYNCED transitions
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::{
    backfill_sync::{BackfillSync, NetworkRequester},
    block_cache::BlockCache,
    peer_manager::PeerManager,
    states::SyncState,
};
use crate::types::ConnectionState;

/// Sync service coordinating all sync operations.
///
/// This is the main sync coordinator that:
/// 1. Receives blocks from gossip via HeadSync
/// 2. Triggers backfill for orphan blocks via BackfillSync
/// 3. Manages sync state (IDLE -> SYNCING -> SYNCED)
/// 4. Provides blocks to the fork choice for processing
pub struct SyncService<N: NetworkRequester> {
    state: SyncState,
    head_sync: Arc<Mutex<BlockCache>>,
    backfill_sync: Arc<Mutex<BackfillSync<N>>>,
    peer_manager: Arc<Mutex<PeerManager>>,
    local_head_slot: Slot,
}

impl<N: NetworkRequester> SyncService<N> {
    pub fn new(network: N, peer_manager: PeerManager, block_cache: BlockCache) -> Self {
        let peer_manager_arc = Arc::new(Mutex::new(peer_manager));
        let block_cache_arc = Arc::new(Mutex::new(block_cache));

        let pm_clone = peer_manager_arc.lock().clone();
        let bc_clone = block_cache_arc.lock().clone();

        Self {
            state: SyncState::default(),
            head_sync: block_cache_arc.clone(),
            backfill_sync: Arc::new(Mutex::new(BackfillSync::new(pm_clone, bc_clone, network))),
            peer_manager: peer_manager_arc,
            local_head_slot: Slot(0),
        }
    }

    /// Get current sync state.
    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Add a peer to the sync service.
    pub fn add_peer(&self, peer_id: PeerId, connection_state: ConnectionState) {
        let mut pm = self.peer_manager.lock();
        pm.add_peer(peer_id, connection_state);
        info!(peer = %peer_id, "Peer added to sync service");
    }

    /// Remove a peer from the sync service.
    pub fn remove_peer(&self, peer_id: &PeerId) {
        let mut pm = self.peer_manager.lock();
        pm.remove_peer(peer_id);
        info!(peer = %peer_id, "Peer removed from sync service");
    }

    /// Update peer connection state.
    pub fn update_peer_connection(&self, peer_id: &PeerId, state: ConnectionState) {
        let mut pm = self.peer_manager.lock();
        pm.update_connection_state(peer_id, state);
    }

    /// Update peer chain status.
    pub fn update_peer_status(&self, peer_id: &PeerId, status: containers::Status) {
        let finalized_slot = status.finalized.slot;
        let mut pm = self.peer_manager.lock();
        pm.update_status(peer_id, status);
        debug!(peer = %peer_id, finalized_slot = finalized_slot.0, "Updated peer status");
    }

    /// Process a gossip block.
    ///
    /// Returns the block root and whether backfill is needed.
    pub async fn process_gossip_block(
        &mut self,
        block: SignedBlockWithAttestation,
    ) -> (Bytes32, bool) {
        let slot = block.message.block.slot;
        let parent_root = block.message.block.parent_root;

        let (root, is_orphan, missing_parents) = {
            let mut cache = self.head_sync.lock();
            let root = cache.add_block(block);
            let is_orphan = cache.is_orphan(&root);

            let missing_parents = if is_orphan && !parent_root.0.is_zero() {
                if !cache.contains(&parent_root) {
                    vec![parent_root]
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            (root, is_orphan, missing_parents)
        };

        debug!(
            slot = slot.0,
            root = ?root,
            processable = !is_orphan,
            "Processed gossip block"
        );

        // If block has missing parents, trigger backfill
        if !missing_parents.is_empty() {
            debug!(
                num_missing = missing_parents.len(),
                "Triggering backfill for missing parents"
            );

            let mut bs = self.backfill_sync.lock();
            bs.fill_missing(missing_parents, 0).await;
        }

        (root, !is_orphan)
    }

    /// Get all blocks ready for processing.
    ///
    /// Returns blocks in topological order (parents before children).
    pub fn get_processable_blocks(&self) -> Vec<SignedBlockWithAttestation> {
        let cache = self.head_sync.lock();
        let roots = cache.get_processable_blocks();

        // Sort by slot to ensure topological order
        let mut blocks: Vec<_> = roots
            .iter()
            .filter_map(|root| {
                cache
                    .get_block(root)
                    .map(|b| (b.clone(), b.message.block.slot))
            })
            .collect();

        blocks.sort_by_key(|(_, slot)| *slot);
        blocks.into_iter().map(|(block, _)| block).collect()
    }

    /// Remove a block from the cache after processing.
    pub fn remove_processed_block(&self, root: &Bytes32) {
        let mut cache = self.head_sync.lock();
        cache.remove_block(root);
    }

    /// Update local head slot (from fork choice).
    pub fn update_local_head(&mut self, slot: Slot) {
        self.local_head_slot = slot;
        self.update_sync_state();
    }

    /// Update sync state based on current conditions.
    fn update_sync_state(&mut self) {
        let pm = self.peer_manager.lock();
        let network_finalized = pm.get_network_finalized_slot();
        drop(pm);

        let new_state = match (self.state, network_finalized) {
            // IDLE -> SYNCING: Peers connected and we need to sync
            (SyncState::Idle, Some(finalized)) if self.local_head_slot < finalized => {
                info!(
                    local_head = self.local_head_slot.0,
                    network_finalized = finalized.0,
                    "Transitioning to SYNCING"
                );
                SyncState::Syncing
            }

            // SYNCING -> SYNCED: Caught up with network
            (SyncState::Syncing, Some(finalized)) if self.local_head_slot >= finalized => {
                info!(
                    local_head = self.local_head_slot.0,
                    network_finalized = finalized.0,
                    "Transitioning to SYNCED"
                );
                SyncState::Synced
            }

            // SYNCED -> SYNCING: Fell behind network
            (SyncState::Synced, Some(finalized)) if self.local_head_slot < finalized => {
                warn!(
                    local_head = self.local_head_slot.0,
                    network_finalized = finalized.0,
                    "Fell behind, transitioning to SYNCING"
                );
                SyncState::Syncing
            }

            // Any state -> IDLE: No peers or no network info
            (_, None) => {
                if self.state != SyncState::Idle {
                    info!("No peer information, transitioning to IDLE");
                }
                SyncState::Idle
            }

            // No transition needed
            _ => self.state,
        };

        if new_state != self.state {
            if !self.state.can_transition_to(new_state) {
                warn!(
                    from = ?self.state,
                    to = ?new_state,
                    "Invalid state transition attempted"
                );
                return;
            }
            self.state = new_state;
        }
    }

    /// Periodic tick for sync service.
    ///
    /// Should be called regularly (e.g., every SYNC_TICK_INTERVAL_SECS).
    /// Performs periodic tasks like state evaluation and orphan resolution.
    pub async fn tick(&mut self) {
        self.update_sync_state();

        // Check for orphans and trigger backfill if needed
        let missing_parents = {
            let cache = self.head_sync.lock();
            cache.get_missing_parents()
        };

        if !missing_parents.is_empty() {
            debug!(
                num_missing = missing_parents.len(),
                "Found missing parents, triggering backfill"
            );

            let mut bs = self.backfill_sync.lock();
            bs.fill_missing(missing_parents, 0).await;
        }
    }

    /// Get sync statistics.
    pub fn get_stats(&self) -> SyncStats {
        let cache = self.head_sync.lock();
        let orphan_blocks = cache.get_orphans().len();
        let processable_blocks = cache.get_processable_blocks().len();
        let cached_blocks = cache.len();
        drop(cache);

        let pm = self.peer_manager.lock();
        let connected_peers = pm.get_all_peers().filter(|p| p.is_connected()).count();

        SyncStats {
            state: self.state,
            local_head_slot: self.local_head_slot,
            cached_blocks,
            orphan_blocks,
            processable_blocks,
            connected_peers,
        }
    }
}

/// Statistics about the sync service.
#[derive(Debug, Clone, Copy)]
pub struct SyncStats {
    pub state: SyncState,
    pub local_head_slot: Slot,
    pub cached_blocks: usize,
    pub orphan_blocks: usize,
    pub processable_blocks: usize,
    pub connected_peers: usize,
}
