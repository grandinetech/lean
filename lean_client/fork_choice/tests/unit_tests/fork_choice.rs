use super::common::{create_test_store, test_storage};
use containers::{Block, BlockBody, Config, SignedBlock, Slot, State, Validator};
use fork_choice::store::{get_forkchoice_store, get_proposal_head};
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

#[test]
fn get_forkchoice_store_restores_from_db() {
    let storage = test_storage();
    let state = State::generate_genesis_with_validators(1000, vec![Validator::default(); 4]);
    let block = Block {
        slot: Slot(0),
        proposer_index: 0,
        parent_root: H256::default(),
        state_root: state.hash_tree_root(),
        body: BlockBody::default(),
    };
    let signed_block = SignedBlock {
        block,
        proof: Default::default(),
    };
    let config = Config { genesis_time: 1000 };

    let fresh = get_forkchoice_store(
        state.clone(),
        signed_block.clone(),
        config.clone(),
        true,
        1,
        storage.clone(),
    );
    let head = fresh.head;
    let finalized = fresh.latest_finalized.clone();
    drop(fresh);

    let restored = get_forkchoice_store(state, signed_block, config, true, 1, storage);
    assert_eq!(restored.head, head);
    assert!(restored.blocks.contains_key(&head));
    assert!(restored.states.contains_key(&head));
    assert_eq!(restored.latest_finalized, finalized);
}
