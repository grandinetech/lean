use crate::Checkpoint;
use serde::{Deserialize, Serialize};
use ssz::Ssz;

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}

impl Status {
    pub fn new(finalized: Checkpoint, head: Checkpoint) -> Self {
        Self { finalized, head }
    }
}
