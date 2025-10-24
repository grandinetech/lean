use ssz_derive::Ssz;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct Config {
    pub num_validators: u64,
    pub genesis_time: u64,
}