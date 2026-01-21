pub mod backfill_sync;
pub mod block_cache;
/// Sync service for the lean Ethereum consensus client.
///
/// This module provides synchronization capabilities for downloading and
/// validating blocks to catch up with the network. It includes:
///
/// - **Block Cache**: Manages blocks and tracks orphans (blocks with unknown parents)
/// - **Peer Manager**: Tracks peer chain status and selects peers for requests
/// - **Backfill Sync**: Resolves orphan chains by fetching missing parent blocks
/// - **Head Sync**: Advances the chain head by processing gossip blocks
/// - **Sync Service**: Coordinates all sync operations and manages state transitions
///
/// ## Architecture
///
/// The sync service operates reactively:
/// 1. Blocks arrive via gossip
/// 2. If parent is known, process immediately
/// 3. If parent is unknown, cache block and trigger backfill
/// 4. Backfill fetches missing parents recursively (up to MAX_BACKFILL_DEPTH)
/// 5. Once parent chain is complete, process all cached blocks
///
/// ## State Machine
///
/// - **IDLE**: No peers, waiting to start
/// - **SYNCING**: Processing blocks to catch up
/// - **SYNCED**: Reached network finalized checkpoint
pub mod config;
pub mod head_sync;
pub mod peer_manager;
pub mod service;
pub mod states;

pub use backfill_sync::BackfillSync;
pub use block_cache::BlockCache;
pub use config::*;
pub use head_sync::HeadSync;
pub use peer_manager::{PeerManager, SyncPeer};
pub use service::SyncService;
pub use states::SyncState;

#[cfg(test)]
mod tests;
