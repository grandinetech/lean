pub mod runner;
pub mod state_transition;
pub mod block_processing;
pub mod vote_processing;

use serde::{Deserialize, Serialize};
use crate::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct TestCase<T> {
    pub description: String,
    pub pre: T,
    pub post: Option<T>,
    pub blocks: Option<Vec<SignedBlock>>,
    pub votes: Option<Vec<SignedVote>>,
    pub valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestVector<T> {
    pub test_cases: Vec<TestCase<T>>,
    pub config: Config,
}
