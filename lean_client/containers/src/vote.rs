use crate::{Bytes32, Slot, Uint64, Checkpoint};
use ssz_derive::Ssz;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct Vote {
    pub validator_id: Uint64,
    pub slot: Slot,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

// TODO: Rename votes to attestation and add functions from leanspec
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct SignedVote {
    pub data: Vote,
    pub signature: Bytes32, //placeholder
}