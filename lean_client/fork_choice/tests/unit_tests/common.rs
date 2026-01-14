use fork_choice::store::{get_forkchoice_store, Store};
use containers::{
    attestation::Attestation,
    block::{Block, BlockBody, BlockWithAttestation, SignedBlockWithAttestation},
    config::Config,
    state::State,
    validator::Validator,
    Bytes32, Slot, ValidatorIndex,
};
use containers::types::Uint64;
use containers::ssz::SszHash;

pub fn create_test_store() -> Store {
    let config = Config {
    genesis_time: 0, 
    seconds_per_slot: 4,
    intervals_per_slot: 4,
    seconds_per_interval: 1,
    genesis_validators: Vec::new(),
};
    
    let validators = vec![
        Validator::default(); 10
    ];
    
    let state = State::generate_genesis_with_validators(1000, validators);
    
    let block = Block {
        slot: Slot(0),
        proposer_index: 0,
        parent_root: Bytes32::default(),
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
