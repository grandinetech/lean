use crate::{Bytes32, Slot,  SignedVote, ValidatorIndex, U4000};
use ssz::{ByteVector, PersistentList as List};
use ssz_derive::Ssz;
use serde::{Deserialize, Serialize};
use typenum::U4096;

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct BlockBody {
    #[serde(with = "crate::serde_helpers")]
    pub attestations: List<SignedVote, U4096>,
}

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct Block {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body: BlockBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct SignedBlock {
    pub message: Block,
    pub signature: ByteVector<U4000>,
}

/// Compute the SSZ hash tree root for any type implementing `SszHash`.
pub fn hash_tree_root<T: ssz::SszHash>(value: &T) -> Bytes32 {
    let h = value.hash_tree_root();
    Bytes32(h)
}

