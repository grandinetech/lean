use crate::Slot;
use serde::{Deserialize, Serialize};
use ssz::{H256, Ssz};

/// Represents a checkpoint in the chain's history.
///
/// A checkpoint marks a specific moment in the chain. It combines a block
/// identifier with a slot number. Checkpoints are used for justification and
/// finalization.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The root hash of the checkpoint's block.
    pub root: H256,
    /// The slot number of the checkpoint's block.
    pub slot: Slot,
}
