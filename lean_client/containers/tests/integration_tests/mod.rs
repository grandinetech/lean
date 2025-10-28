pub mod runner;
pub mod test_single_block_with_slot_gap;
pub mod test_sequential_blocks;
pub mod test_single_empty_block;

use serde::{Deserialize, Serialize};
use containers::{
    Bytes32, Slot, block::SignedBlock, config::Config as ContainerConfig, state::State, vote::SignedVote
};

#[derive(Debug, Serialize, Deserialize)]
pub struct TestCase<T> {
    pub network: String,
    pub pre: T,
    pub blocks: Option<Vec<SignedBlock>>,
    pub post: Option<PostState>,
    pub _info: Info,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostState {
    pub slot: Slot,
    pub validator_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Info {
    pub hash: Bytes32,
    pub comment: String,
    pub test_id: String,
    pub description: String,
    pub fixture_format: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestVector<T> {
    pub test_case: Vec<TestCase<T>>,
}
