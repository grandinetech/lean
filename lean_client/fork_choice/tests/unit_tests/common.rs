use containers::{
    Attestation, Block, BlockBody, BlockWithAttestation, Config, SignedBlockWithAttestation, Slot,
    State, Validator,
};
use fork_choice::store::{Store, get_forkchoice_store};
use ssz::{H256, SszHash};

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

    let block_with_attestation = BlockWithAttestation {
        block: block.clone(),
        proposer_attestation: Attestation::default(),
    };

    let signed_block = SignedBlockWithAttestation {
        message: block_with_attestation,
        signature: Default::default(),
    };

    get_forkchoice_store(state, signed_block, config)
}
