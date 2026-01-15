pub use ssz::H256;

pub type ValidatorIndex = u64;

// Type-level constants for SSZ collection limits
use typenum::{Prod, U4, U1000, U4096, U262144, U1073741824};
use crate::validator::Validator;
// 2^18, 4096 * 262144

/// Type-level number for 4000 bytes (signature size) = 4 * 1000
pub type U4000 = Prod<U4, U1000>;

/// List of historical block root hashes (SSZList<H256, historical_roots_limit>)
pub type HistoricalBlockHashes = ssz::PersistentList<H256, U262144>;

pub type Validators = ssz::PersistentList<Validator, U4096>;

/// List of justified block roots (SSZList<H256, historical_roots_limit>)
pub type JustificationRoots = ssz::PersistentList<H256, U262144>;

/// Bitlist tracking justified slots (BitList<historical_roots_limit>)
pub type JustifiedSlots = ssz::BitList<U262144>; // 2^18

/// Bitlist for tracking validator justifications (BitList<validator_registry_limit * historical_roots_limit>)
pub type JustificationsValidators = ssz::BitList<U1073741824>; // 4096 * 262144