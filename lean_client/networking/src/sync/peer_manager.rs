use super::config::MAX_CONCURRENT_REQUESTS;
use crate::types::ConnectionState;
use containers::{Slot, Status};
use libp2p_identity::PeerId;
/// Peer manager for sync operations.
///
/// Tracks peer chain status and selects peers for block requests.
use std::collections::HashMap;

/// Sync-specific peer state.
///
/// Wraps peer information with sync-specific state: chain status and request tracking.
#[derive(Debug, Clone)]
pub struct SyncPeer {
    pub peer_id: PeerId,
    pub connection_state: ConnectionState,
    pub status: Option<Status>,
    pub requests_in_flight: usize,
}

impl SyncPeer {
    pub fn new(peer_id: PeerId, connection_state: ConnectionState) -> Self {
        Self {
            peer_id,
            connection_state,
            status: None,
            requests_in_flight: 0,
        }
    }

    /// Check if peer is connected.
    pub fn is_connected(&self) -> bool {
        self.connection_state == ConnectionState::Connected
    }

    /// Check if peer is available for new requests.
    ///
    /// A peer is available if:
    /// - Connected
    /// - Below MAX_CONCURRENT_REQUESTS limit
    pub fn is_available(&self) -> bool {
        self.is_connected() && self.requests_in_flight < MAX_CONCURRENT_REQUESTS
    }

    /// Check if peer likely has data for given slot.
    pub fn has_slot(&self, slot: Slot) -> bool {
        if let Some(status) = &self.status {
            status.head.slot >= slot
        } else {
            false
        }
    }

    /// Mark that a request has been sent to this peer.
    pub fn on_request_start(&mut self) {
        self.requests_in_flight += 1;
    }

    /// Mark that a request has completed.
    pub fn on_request_complete(&mut self) {
        self.requests_in_flight = self.requests_in_flight.saturating_sub(1);
    }
}

/// Peer manager for sync operations.
///
/// Tracks peer chain status, selects peers for requests, and manages
/// request concurrency limits.
#[derive(Debug, Default, Clone)]
pub struct PeerManager {
    peers: HashMap<PeerId, SyncPeer>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a peer to the manager.
    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        connection_state: ConnectionState,
    ) -> &mut SyncPeer {
        self.peers
            .entry(peer_id)
            .or_insert_with(|| SyncPeer::new(peer_id, connection_state))
    }

    /// Remove a peer from the manager.
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<SyncPeer> {
        self.peers.remove(peer_id)
    }

    /// Get a peer by ID.
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&SyncPeer> {
        self.peers.get(peer_id)
    }

    /// Get a mutable peer by ID.
    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut SyncPeer> {
        self.peers.get_mut(peer_id)
    }

    /// Update peer connection state.
    pub fn update_connection_state(&mut self, peer_id: &PeerId, state: ConnectionState) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.connection_state = state;
        }
    }

    /// Update peer chain status.
    pub fn update_status(&mut self, peer_id: &PeerId, status: Status) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.status = Some(status);
        }
    }

    /// Select an available peer for a request.
    ///
    /// Returns the first available peer. If min_slot is provided, only
    /// considers peers that likely have data for that slot.
    pub fn select_peer_for_request(&self, min_slot: Option<Slot>) -> Option<&SyncPeer> {
        self.peers.values().find(|peer| {
            if !peer.is_available() {
                return false;
            }
            if let Some(slot) = min_slot {
                peer.has_slot(slot)
            } else {
                true
            }
        })
    }

    /// Get network's finalized slot (most common among connected peers).
    ///
    /// Returns the mode (most common) finalized slot reported by connected peers.
    pub fn get_network_finalized_slot(&self) -> Option<Slot> {
        let mut finalized_slots: Vec<Slot> = self
            .peers
            .values()
            .filter(|peer| peer.status.is_some() && peer.is_connected())
            .map(|peer| peer.status.as_ref().unwrap().finalized.slot)
            .collect();

        if finalized_slots.is_empty() {
            return None;
        }

        // Find mode (most common value)
        finalized_slots.sort();
        let mut max_count = 0;
        let mut mode = finalized_slots[0];
        let mut current_count = 1;
        let mut current_slot = finalized_slots[0];

        for i in 1..finalized_slots.len() {
            if finalized_slots[i] == current_slot {
                current_count += 1;
            } else {
                if current_count > max_count {
                    max_count = current_count;
                    mode = current_slot;
                }
                current_slot = finalized_slots[i];
                current_count = 1;
            }
        }

        // Check last group
        if current_count > max_count {
            mode = current_slot;
        }

        Some(mode)
    }

    /// Mark that a request has been sent to a peer.
    pub fn on_request_start(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.on_request_start();
        }
    }

    /// Mark that a request has completed successfully.
    pub fn on_request_complete(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.on_request_complete();
        }
    }

    /// Mark that a request has failed.
    pub fn on_request_failure(&mut self, peer_id: &PeerId, _reason: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.on_request_complete();
            // Could implement reputation/scoring here
        }
    }

    /// Get all tracked peers.
    pub fn get_all_peers(&self) -> impl Iterator<Item = &SyncPeer> {
        self.peers.values()
    }
}
