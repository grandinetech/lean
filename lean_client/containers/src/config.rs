use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs::File;
use std::io::BufReader;
use crate::validator::Validator;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)] 
pub struct Config {
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
    pub intervals_per_slot: u64,
    pub seconds_per_interval: u64,
    pub genesis_validators: Vec<Validator>,
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let config = serde_json::from_reader(reader)?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            genesis_time: 0,
            seconds_per_slot: 12,   
            intervals_per_slot: 4,
            seconds_per_interval: 3,
            genesis_validators: Vec::new(),
        }
    }
}
