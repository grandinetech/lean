use crate::{Bytes32, Slot};
use serde::{Deserialize, Serialize};
use ssz_derive::Ssz;

/// Represents a checkpoint in the chain's history.
///
/// A checkpoint marks a specific moment in the chain. It combines a block
/// identifier with a slot number. Checkpoints are used for justification and
/// finalization.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The root hash of the checkpoint's block.
    pub root: Bytes32,
    /// The slot number of the checkpoint's block.
    pub slot: Slot,
}

impl Checkpoint {
    /// Return a default checkpoint with zero root and slot 0.
    pub fn default_checkpoint() -> Self {
        Self {
            root: Bytes32(ssz::H256::zero()),
            slot: Slot(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_checkpoint() {
        let checkpoint = Checkpoint::default_checkpoint();
        assert_eq!(checkpoint.root, Bytes32(ssz::H256::zero()));
        assert_eq!(checkpoint.slot, Slot(0));
    }

    #[test]
    fn test_checkpoint_equality() {
        let cp1 = Checkpoint::default_checkpoint();
        let cp2 = Checkpoint {
            root: Bytes32(ssz::H256::zero()),
            slot: Slot(0),
        };
        assert_eq!(cp1, cp2);
    }
}
