use ssz::H256;
use ssz_derive::Ssz;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::fmt;
use hex::FromHex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Ssz, Default, Serialize, Deserialize)]
#[ssz(transparent)]
pub struct Bytes32(pub H256);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Ssz, Default, Serialize, Deserialize)]
#[ssz(transparent)]
pub struct Uint64(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[ssz(transparent)]
pub struct ValidatorIndex(pub u64);



impl FromStr for Bytes32 {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = <[u8; 32]>::from_hex(s)?;
        Ok(Bytes32(H256::from(bytes)))
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}