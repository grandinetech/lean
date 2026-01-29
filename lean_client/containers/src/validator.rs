use serde::{Deserialize, Serialize};
use ssz::{PersistentList, Ssz};
use typenum::U4096;
use xmss::PublicKey;

// todo(containers): default implementation doesn't make sense here
#[derive(Clone, Debug, Ssz, Serialize, Deserialize, Default)]
pub struct Validator {
    pub pubkey: PublicKey,
    #[serde(default)]
    pub index: u64,
}

pub type ValidatorRegistryLimit = U4096;

pub type Validators = PersistentList<Validator, ValidatorRegistryLimit>;
