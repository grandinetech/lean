/// Sync service configuration constants.
///
/// Operational parameters for synchronization: batch sizes, timeouts, and limits.

/// Maximum blocks to request in a single BlocksByRoot request.
pub const MAX_BLOCKS_PER_REQUEST: usize = 10;

/// Maximum concurrent requests to a single peer.
pub const MAX_CONCURRENT_REQUESTS: usize = 2;

/// Maximum depth to backfill when resolving orphan chains.
/// This prevents resource exhaustion from malicious deep chains.
pub const MAX_BACKFILL_DEPTH: usize = 512;

/// Interval between sync state evaluations (in seconds).
pub const SYNC_TICK_INTERVAL_SECS: u64 = 1;
