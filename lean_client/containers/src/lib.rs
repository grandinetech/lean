pub mod types;
pub mod config;
pub mod slot;
pub mod checkpoint;
pub mod vote;
pub mod block;
pub mod state;

#[cfg(test)]
pub mod test_vectors;

pub use block::{Block, BlockBody, BlockHeader, SignedBlock};
pub use checkpoint::Checkpoint;
pub use config::Config;
pub use slot::Slot;
pub use state::State;
pub use types::{Bytes32, Uint64, ValidatorIndex};
pub use vote::{SignedVote, Vote};

pub use types::Bytes32 as Root;
// Re-export grandine ssz so tests can reference it if needed
pub use ssz;
