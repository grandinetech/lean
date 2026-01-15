use super::common::create_test_store;
use fork_choice::store::{get_proposal_head, get_vote_target};
use containers::Slot;
use containers::ssz::SszHash;

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
    use containers::block::{Block, BlockBody, BlockWithAttestation, SignedBlockWithAttestation};

    let mut store = create_test_store();
    let mut parent_root = store.head;

    for i in 1..=10 {
        let block = Block {
            slot: Slot(i),
            proposer_index: 0, 
            parent_root,
            state_root: containers::ssz::H256::zero(), 
            body: BlockBody::default(),
        };

        let block_root = block.hash_tree_root(); 

        let signed_block = SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block: block.clone(),
                proposer_attestation: Default::default(),
            },
            signature: Default::default(),
        };

        store.blocks.insert(block_root, signed_block);
        parent_root = block_root;
    }

    store.head = parent_root;
    let target = get_vote_target(&store);
    assert_eq!(target.slot, Slot(6));
}