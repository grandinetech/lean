use hex::FromHex;
use serde::{Deserialize, Serialize};
use ssz::H256;
use ssz_derive::Ssz;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// 20-byte array for message IDs (gossipsub message IDs)
/// Using transparent SSZ encoding - just the raw bytes
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Bytes20(pub [u8; 20]);

impl Default for Bytes20 {
    fn default() -> Self {
        Bytes20([0u8; 20])
    }
}

impl Bytes20 {
    pub fn new(data: [u8; 20]) -> Self {
        Bytes20(data)
    }
    
    pub fn len(&self) -> usize {
        20
    }
    
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl Hash for Bytes20 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<&[u8]> for Bytes20 {
    fn from(slice: &[u8]) -> Self {
        let mut data = [0u8; 20];
        let len = slice.len().min(20);
        data[..len].copy_from_slice(&slice[..len]);
        Bytes20(data)
    }
}

impl AsRef<[u8]> for Bytes20 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Ssz, Default, Serialize, Deserialize,
)]
#[ssz(transparent)]
pub struct Bytes32(pub H256);

#[derive(
    Clone, Hash, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Ssz, Default, Serialize, Deserialize,
)]
#[ssz(transparent)]
pub struct Uint64(pub u64);

#[derive(Clone, Hash, Copy, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
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

// Type-level constants for SSZ collection limits
use crate::validator::Validator;
use typenum::{Prod, U1000, U1073741824, U262144, U4, U4096};
// 2^18, 4096 * 262144

/// Type-level number for 4000 bytes (signature size) = 4 * 1000
pub type U4000 = Prod<U4, U1000>;

/// List of historical block root hashes (SSZList<Bytes32, historical_roots_limit>)
pub type HistoricalBlockHashes = ssz::PersistentList<Bytes32, U262144>;

pub type Validators = ssz::PersistentList<Validator, U4096>;

/// List of justified block roots (SSZList<Bytes32, historical_roots_limit>)
pub type JustificationRoots = ssz::PersistentList<Bytes32, U262144>;

/// Bitlist tracking justified slots (BitList<historical_roots_limit>)
pub type JustifiedSlots = ssz::BitList<U262144>; // 2^18

/// Bitlist for tracking validator justifications (BitList<validator_registry_limit * historical_roots_limit>)
pub type JustificationsValidators = ssz::BitList<U1073741824>; // 4096 * 262144
