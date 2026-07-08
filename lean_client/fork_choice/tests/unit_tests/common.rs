use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use containers::{Block, BlockBody, Config, SignedBlock, Slot, State, Validator};
use fork_choice::store::{Store, get_forkchoice_store};
use ssz::{H256, SszHash};
use storage::Storage;

/// Open a throwaway `Storage` in a unique temp directory. Each store gets its
/// own libmdbx environment so tests running in parallel never open the same
/// path twice within a process.
pub fn test_storage() -> Arc<Storage> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("lean-test-{}-{n}", std::process::id()));
    Arc::new(Storage::new(dir).expect("failed to open test storage"))
}

pub fn create_test_store() -> Store {
    let config = Config { genesis_time: 1000 };

    let validators = vec![Validator::default(); 10];

    let state = State::generate_genesis_with_validators(1000, validators);

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

    get_forkchoice_store(state, signed_block, config, true, 1, test_storage())
}
