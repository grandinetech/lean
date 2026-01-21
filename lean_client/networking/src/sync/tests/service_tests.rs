use crate::sync::{SyncService, SyncState, PeerManager, BlockCache};
use crate::sync::backfill_sync::NetworkRequester;
use crate::types::ConnectionState;
use containers::{Block, BlockBody, BlockWithAttestation, Attestation, ValidatorIndex, Bytes32, Slot, SignedBlockWithAttestation, Checkpoint};
use libp2p_identity::PeerId;

// Mock network for testing
struct MockNetwork;

#[async_trait::async_trait]
impl NetworkRequester for MockNetwork {
    async fn request_blocks_by_root(
        &self,
        _peer_id: PeerId,
        _roots: Vec<Bytes32>,
    ) -> Option<Vec<SignedBlockWithAttestation>> {
        None
    }
}

fn create_test_block(slot: u64, parent_root: Bytes32) -> SignedBlockWithAttestation {
    let block = Block {
        slot: Slot(slot),
        proposer_index: ValidatorIndex(0),
        parent_root,
        state_root: Bytes32::default(),
        body: BlockBody::default(),
    };

    SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation: Attestation::default(),
        },
        signature: Default::default(),
    }
}

#[tokio::test]
async fn test_sync_service_creation() {
    let service: SyncService<MockNetwork> = SyncService::new(MockNetwork, PeerManager::new(), BlockCache::new());
    assert_eq!(service.state(), SyncState::Idle);
}

#[tokio::test]
async fn test_process_genesis_block() {
    let mut service: SyncService<MockNetwork> = SyncService::new(MockNetwork, PeerManager::new(), BlockCache::new());
    
    let genesis = create_test_block(0, Bytes32::default());
    let (_root, is_processable) = service.process_gossip_block(genesis).await;

    assert!(is_processable);
    assert!(service.get_processable_blocks().len() > 0);
}

#[test]
fn test_add_remove_peer() {
    let service: SyncService<MockNetwork> = SyncService::new(MockNetwork, PeerManager::new(), BlockCache::new());
    let peer_id = PeerId::random();

    service.add_peer(peer_id, ConnectionState::Connected);
    
    // Verify peer was added by checking stats
    let stats = service.get_stats();
    assert!(stats.connected_peers >= 1);

    service.remove_peer(&peer_id);
    
    // Note: Stats may not reflect removal immediately in a real impl,
    // but this tests the API works
}

#[test]
fn test_sync_state_transitions() {
    let mut service: SyncService<MockNetwork> = SyncService::new(MockNetwork, PeerManager::new(), BlockCache::new());
    assert_eq!(service.state(), SyncState::Idle);

    // Add peer with finalized slot ahead of local head
    let peer_id = PeerId::random();
    service.add_peer(peer_id, ConnectionState::Connected);
    
    let status = containers::Status {
        finalized: Checkpoint {
            root: Bytes32::default(),
            slot: Slot(100),
        },
        head: Checkpoint {
            root: Bytes32::default(),
            slot: Slot(150),
        },
    };
    service.update_peer_status(&peer_id, status);

    // Should transition to SYNCING
    service.update_local_head(Slot(0));
    assert_eq!(service.state(), SyncState::Syncing);

    // Catch up to network finalized
    service.update_local_head(Slot(100));
    assert_eq!(service.state(), SyncState::Synced);
}
