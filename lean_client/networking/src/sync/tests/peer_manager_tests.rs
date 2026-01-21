use crate::sync::{PeerManager, SyncPeer};
use crate::sync::config::MAX_CONCURRENT_REQUESTS;
use crate::types::ConnectionState;
use containers::{Checkpoint, Bytes32, Status, Slot};
use libp2p_identity::PeerId;

#[test]
fn test_sync_peer_is_available() {
    let mut peer = SyncPeer::new(
        PeerId::random(),
        ConnectionState::Connected
    );
    assert!(peer.is_available());

    peer.requests_in_flight = MAX_CONCURRENT_REQUESTS;
    assert!(!peer.is_available());
}

#[test]
fn test_peer_manager_add_and_get() {
    let mut manager = PeerManager::new();
    let peer_id = PeerId::random();
    
    manager.add_peer(peer_id, ConnectionState::Connected);
    assert!(manager.get_peer(&peer_id).is_some());
}

#[test]
fn test_peer_manager_update_status() {
    let mut manager = PeerManager::new();
    let peer_id = PeerId::random();
    
    manager.add_peer(peer_id, ConnectionState::Connected);
    
    let status = Status {
        finalized: Checkpoint {
            root: Bytes32::default(),
            slot: Slot(100),
        },
        head: Checkpoint {
            root: Bytes32::default(),
            slot: Slot(150),
        },
    };
    
    manager.update_status(&peer_id, status.clone());
    
    let peer = manager.get_peer(&peer_id).unwrap();
    assert_eq!(peer.status.as_ref().unwrap().finalized.slot, Slot(100));
}
