use crate::sync::BlockCache;
use containers::{Block, BlockBody, BlockWithAttestation, Attestation, ValidatorIndex, Bytes32, Slot, SignedBlockWithAttestation};

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
fn test_add_block() {
    let mut cache = BlockCache::new();
    let block = create_test_block(1, Bytes32::default());
    
    let root = cache.add_block(block);
    assert!(cache.contains(&root));
}

#[test]
fn test_orphan_detection() {
    let mut cache = BlockCache::new();
    
    // Create a block with unknown parent
    let unknown_parent = Bytes32(ssz::H256::from([1u8; 32]));
    let orphan_block = create_test_block(2, unknown_parent);
    
    let orphan_root = cache.add_block(orphan_block);
    
    assert!(cache.is_orphan(&orphan_root));
    assert_eq!(cache.get_orphans().len(), 1);
}

#[test]
fn test_orphan_resolution() {
    let mut cache = BlockCache::new();
    
    // Add genesis
    let genesis = create_test_block(0, Bytes32::default());
    let genesis_root = cache.add_block(genesis.clone());
    
    // Add child (should not be orphan)
    let child = create_test_block(1, genesis_root);
    let child_root = cache.add_block(child);
    
    assert!(!cache.is_orphan(&child_root));
    assert_eq!(cache.get_orphans().len(), 0);
}

#[test]
fn test_get_missing_parents() {
    let mut cache = BlockCache::new();
    
    let parent1 = Bytes32(ssz::H256::from([1u8; 32]));
    let parent2 = Bytes32(ssz::H256::from([2u8; 32]));
    
    let orphan1 = create_test_block(1, parent1);
    let orphan2 = create_test_block(2, parent2);
    let orphan3 = create_test_block(3, parent1); // Same parent as orphan1
    
    cache.add_block(orphan1);
    cache.add_block(orphan2);
    cache.add_block(orphan3);
    
    let missing = cache.get_missing_parents();
    assert_eq!(missing.len(), 2); // Only 2 unique parents
    assert!(missing.contains(&parent1));
    assert!(missing.contains(&parent2));
}

#[test]
fn test_get_processable_blocks() {
    let mut cache = BlockCache::new();
    
    // Add genesis (processable)
    let genesis = create_test_block(0, Bytes32::default());
    let genesis_root = cache.add_block(genesis);
    
    // Add child (processable)
    let child = create_test_block(1, genesis_root);
    let child_root = cache.add_block(child);
    
    // Add orphan (not processable)
    let orphan = create_test_block(2, Bytes32(ssz::H256::from([99u8; 32])));
    cache.add_block(orphan);
    
    let processable = cache.get_processable_blocks();
    assert_eq!(processable.len(), 2);
    assert!(processable.contains(&genesis_root));
    assert!(processable.contains(&child_root));
}
