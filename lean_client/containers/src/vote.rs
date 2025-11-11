use crate::{Checkpoint, Slot, Uint64, U4000};
use ssz::ByteVector;
use ssz_derive::Ssz;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct Vote {
    pub slot: Slot,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

// TODO: Rename votes to attestation and add functions from leanspec
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct SignedVote {
    pub validator_id: Uint64,
    pub message: Vote,
    pub signature: ByteVector<U4000>,
}