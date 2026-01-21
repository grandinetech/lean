use crate::sync::{BackfillSync, BlockCache, PeerManager};
use crate::sync::backfill_sync::NetworkRequester;
use crate::types::ConnectionState;
use containers::{Block, BlockBody, BlockWithAttestation, Attestation, ValidatorIndex, Slot, Bytes32, SignedBlockWithAttestation};
use libp2p_identity::PeerId;

// Mock network for testing
struct MockNetwork {
    blocks: std::collections::HashMap<Bytes32, SignedBlockWithAttestation>,
}

impl MockNetwork {
    fn new() -> Self {
        Self {
            blocks: std::collections::HashMap::new(),
        }
    }

    fn add_block(&mut self, block: SignedBlockWithAttestation) -> Bytes32 {
        let root = containers::block::hash_tree_root(&block.message.block);
        self.blocks.insert(root, block);
        root
    }
}

#[async_trait::async_trait]
impl NetworkRequester for MockNetwork {
    async fn request_blocks_by_root(
        &self,
        _peer_id: PeerId,
        roots: Vec<Bytes32>,
    ) -> Option<Vec<SignedBlockWithAttestation>> {
        let blocks: Vec<_> = roots.iter()
            .filter_map(|root| self.blocks.get(root).cloned())
            .collect();
        
        if blocks.is_empty() {
            None
        } else {
            Some(blocks)
        }
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
async fn test_backfill_single_missing_block() {
    let mut peer_manager = PeerManager::new();
    let peer_id = PeerId::random();
    peer_manager.add_peer(peer_id, ConnectionState::Connected);

    let mut network = MockNetwork::new();
    let block_cache = BlockCache::new();

    // Create parent block and add to network
    let parent = create_test_block(1, Bytes32::default());
    let parent_root = network.add_block(parent);

    let mut backfill = BackfillSync::new(peer_manager, block_cache, network);

    // Request the missing parent
    backfill.fill_missing(vec![parent_root], 0).await;

    // Parent should now be in cache
    assert!(backfill.block_cache().contains(&parent_root));
}
