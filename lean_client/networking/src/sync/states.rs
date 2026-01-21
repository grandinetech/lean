/// Sync service state machine.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Idle state: No peers connected or sync not yet started.
    ///
    /// Initial state when the sync service starts. The client remains idle
    /// until peers connect and provide chain status.
    Idle,

    /// Syncing state: Processing blocks to catch up with the network.
    ///
    /// The client is actively processing blocks (from gossip or request/response)
    /// to reach the network's finalized checkpoint. Backfill happens naturally
    /// within this state when orphan blocks are detected.
    Syncing,

    /// Synced state: Caught up with the network's finalized checkpoint.
    ///
    /// Local head has reached or exceeded the network's most common finalized slot.
    /// The client continues to process new blocks via gossip but is considered
    /// fully synchronized.
    Synced,
}

impl SyncState {
    /// Check if a transition to the target state is valid.
    ///
    /// State machines enforce invariants through transition rules. This method
    /// encodes those rules. Callers should check validity before transitioning
    /// to catch logic errors early.
    pub fn can_transition_to(&self, target: SyncState) -> bool {
        match self {
            SyncState::Idle => matches!(target, SyncState::Syncing),
            SyncState::Syncing => matches!(target, SyncState::Synced | SyncState::Idle),
            SyncState::Synced => matches!(target, SyncState::Syncing | SyncState::Idle),
        }
    }
}

impl Default for SyncState {
    fn default() -> Self {
        SyncState::Idle
    }
}
