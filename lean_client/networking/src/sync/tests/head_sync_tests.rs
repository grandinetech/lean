use crate::sync::{BlockCache, HeadSync};
use containers::{
    Attestation, Block, BlockBody, BlockWithAttestation, Bytes32, SignedBlockWithAttestation, Slot,
    ValidatorIndex,
};

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

#[test]
fn test_process_genesis_block() {
    let mut head_sync = HeadSync::new(BlockCache::new());

    let genesis = create_test_block(0, Bytes32::default());
    let result = head_sync.process_gossip_block(genesis);

    assert!(result.is_processable);
    assert!(result.missing_parents.is_empty());
}

#[test]
fn test_process_orphan_block() {
    let mut head_sync = HeadSync::new(BlockCache::new());

    let unknown_parent = Bytes32(ssz::H256::from([1u8; 32]));
    let orphan = create_test_block(1, unknown_parent);

    let result = head_sync.process_gossip_block(orphan);

    assert!(!result.is_processable);
    assert_eq!(result.missing_parents.len(), 1);
    assert_eq!(result.missing_parents[0], unknown_parent);
}

#[test]
fn test_process_chain_in_order() {
    let mut head_sync = HeadSync::new(BlockCache::new());

    // Add genesis
    let genesis = create_test_block(0, Bytes32::default());
    let genesis_result = head_sync.process_gossip_block(genesis);

    // Add child
    let child = create_test_block(1, genesis_result.root);
    let child_result = head_sync.process_gossip_block(child);

    assert!(child_result.is_processable);
    assert!(child_result.missing_parents.is_empty());
}

#[test]
fn test_get_processable_blocks() {
    let mut head_sync = HeadSync::new(BlockCache::new());

    // Add genesis
    let genesis = create_test_block(0, Bytes32::default());
    let genesis_root = head_sync.process_gossip_block(genesis).root;

    // Add child
    let child = create_test_block(1, genesis_root);
    let child_root = head_sync.process_gossip_block(child).root;

    // Add orphan
    let orphan = create_test_block(2, Bytes32(ssz::H256::from([99u8; 32])));
    head_sync.process_gossip_block(orphan);

    let processable = head_sync.get_processable_blocks();
    assert_eq!(processable.len(), 2);
    assert!(processable.contains(&genesis_root));
    assert!(processable.contains(&child_root));
}

#[test]
fn test_stats() {
    let mut head_sync = HeadSync::new(BlockCache::new());

    // Add genesis and child
    let genesis = create_test_block(0, Bytes32::default());
    let genesis_root = head_sync.process_gossip_block(genesis).root;

    let child = create_test_block(1, genesis_root);
    head_sync.process_gossip_block(child);

    // Add orphan
    let orphan = create_test_block(2, Bytes32(ssz::H256::from([99u8; 32])));
    head_sync.process_gossip_block(orphan);

    let stats = head_sync.get_stats();
    assert_eq!(stats.total_blocks, 3);
    assert_eq!(stats.orphan_blocks, 1);
    assert_eq!(stats.processable_blocks, 2);
}
