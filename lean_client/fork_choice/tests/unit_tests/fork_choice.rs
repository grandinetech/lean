use super::common::create_test_store;
use containers::{Block, BlockBody, Slot};
use fork_choice::store::get_proposal_head;
use ssz::{H256, SszHash};

#[test]
fn test_get_proposal_head_basic() {
    let mut store = create_test_store();
    let head = get_proposal_head(&mut store, Slot(0));

    assert_eq!(head, store.head);
}

#[test]
fn test_get_proposal_head_advances_time() {
    let mut store = create_test_store();
    let initial_time = store.time;

    get_proposal_head(&mut store, Slot(5));

    assert!(store.time >= initial_time);
}

#[test]
fn test_get_vote_target_chain() {
    let mut store = create_test_store();
    let mut parent_root = store.head;

    // Create a chain of 10 blocks
    // Per leanSpec, store.blocks now contains Block (not SignedBlockWithAttestation)
    for i in 1..=10 {
        let block = Block {
            slot: Slot(i),
            proposer_index: 0,
            parent_root,
            state_root: H256::default(),
            body: BlockBody::default(),
        };

        let block_root = block.hash_tree_root();

        // Insert Block directly per leanSpec
        store.blocks.insert(block_root, block);
        parent_root = block_root;
    }

    store.head = parent_root;

    // With head at 10 and safe_target at 0:
    // 1. Walk back 3 slots from head -> 7
    // 2. Walk back until justifiable from finalized (0) -> 6
    let target = store.get_attestation_target();

    assert_eq!(target.slot, Slot(6));
}
