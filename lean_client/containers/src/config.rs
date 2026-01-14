use ssz_derive::Ssz;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs::File;
use std::io::BufReader;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Ssz)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub genesis_time: u64,
    
    #[serde(default = "default_seconds_per_slot")]
    pub seconds_per_slot: u64,
    
    #[serde(default = "default_intervals_per_slot")]
    pub intervals_per_slot: u64,
    
    #[serde(default = "default_seconds_per_interval")]
    pub seconds_per_interval: u64,

    #[ssz(skip)] 
    #[serde(default)]
    pub genesis_validators: Vec<serde_json::Value>,
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let config = serde_json::from_reader(reader)?;
        Ok(config)
    }
}

fn default_seconds_per_slot() -> u64 { 4 }
fn default_intervals_per_slot() -> u64 { 4 }
fn default_seconds_per_interval() -> u64 { 1 }