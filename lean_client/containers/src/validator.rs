use serde::{Deserialize, Serialize};
use ssz_derive::Ssz;

#[derive(Clone, Debug, PartialEq, Eq, Default, Ssz, Serialize, Deserialize)]
pub struct Validator {
    // This now uses new XMSS PublicKey struct
    pub pubkey: crate::public_key::PublicKey,
    #[serde(default)]
    pub index: crate::Uint64,
}
