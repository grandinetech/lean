use ssz::H256;
use ssz_derive::Ssz;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Ssz, Default, Serialize, Deserialize)]
#[ssz(transparent)]
pub struct Bytes32(pub H256);

#[derive(Clone, Hash, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Ssz, Default, Serialize, Deserialize)]
#[ssz(transparent)]
pub struct Uint64(pub u64);

#[derive(Clone, Hash, Copy, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[ssz(transparent)]
pub struct ValidatorIndex(pub u64);
