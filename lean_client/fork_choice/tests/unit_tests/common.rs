use fork_choice::store::{get_forkchoice_store, Store};
use containers::{
    attestation::Attestation,
    block::{Block, BlockBody, BlockWithAttestation, SignedBlockWithAttestation},
    config::Config,
    state::State,
    validator::Validator,
    Bytes32, Slot, Uint64, ValidatorIndex,
};
use ssz::SszHash;

pub fn create_test_store() -> Store {
    let config = Config {
        genesis_time: 1000,
    };
    
    let validators = vec![
        Validator::default(); 10
    ];
    
    let state = State::generate_genesis_with_validators(Uint64(1000), validators);
    
    let block = Block {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Bytes32::default(),
        state_root: Bytes32(state.hash_tree_root()),
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
