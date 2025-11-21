pub mod block_processing;
pub mod runner;
pub mod state_transition;
pub mod vote_processing;

use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TestCase<T> {
    pub description: String,
    pub pre: T,
    pub post: Option<T>,
    pub blocks: Option<Vec<SignedBlock>>,
    pub votes: Option<Vec<Attestation>>,
    pub valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestVector<T> {
    pub test_cases: Vec<TestCase<T>>,
    pub config: Config,
}
