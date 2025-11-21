use hex::FromHex;
use serde::{Deserialize, Serialize};
use ssz::H256;
use ssz_derive::Ssz;
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;

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
use typenum::{Prod, U1000, U1073741824, U262144, U4}; // 2^18, 4096 * 262144

/// Type-level number for 4000 bytes (signature size) = 4 * 1000
pub type U4000 = Prod<U4, U1000>;

/// List of historical block root hashes (SSZList<Bytes32, historical_roots_limit>)
pub type HistoricalBlockHashes = ssz::PersistentList<Bytes32, U262144>;

/// List of justified block roots (SSZList<Bytes32, historical_roots_limit>)
pub type JustificationRoots = ssz::PersistentList<Bytes32, U262144>;

/// Bitlist tracking justified slots (BitList<historical_roots_limit>)
pub type JustifiedSlots = ssz::BitList<U262144>; // 2^18

/// Bitlist for tracking validator justifications (BitList<validator_registry_limit * historical_roots_limit>)
pub type JustificationsValidators = ssz::BitList<U1073741824>; // 4096 * 262144
