//! Test vector modules for devnet2 format
//!
//! Contains test runners and test cases for block processing, genesis, and signature verification.

// Test vector modules
pub mod block_processing;
pub mod genesis;
pub mod runner;
pub mod verify_signatures;

use containers::{Block, SignedBlockWithAttestation, Slot, State};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Custom deserializer that handles both plain values and {"data": T} wrapper format
fn deserialize_flexible<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::de::Error;

    // Deserialize as a generic Value first to inspect the structure
    let value = Value::deserialize(deserializer)?;

    // Check if it's an object with a "data" field
    if let Value::Object(ref map) = value {
        if map.contains_key("data") && map.len() == 1 {
            // Extract just the data field
            if let Some(data_value) = map.get("data") {
                return serde_json::from_value(data_value.clone()).map_err(|e| {
                    D::Error::custom(format!("Failed to deserialize from data wrapper: {}", e))
                });
            }
        }
    }

    // Otherwise, deserialize as a plain value
    serde_json::from_value(value)
        .map_err(|e| D::Error::custom(format!("Failed to deserialize plain value: {}", e)))
}

/// Top-level wrapper for test vector files with dynamic test name keys
#[derive(Debug, Serialize, Deserialize)]
pub struct TestVectorFile {
    #[serde(flatten)]
    pub tests: HashMap<String, TestCase>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestCase {
    pub network: String,
    pub pre: State,
    #[serde(deserialize_with = "deserialize_flexible", default)]
    pub blocks: Option<Vec<Block>>,
    pub post: Option<PostState>,
    #[serde(default)]
    pub expect_exception: Option<String>,
    #[serde(rename = "_info")]
    pub info: Info,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostState {
    pub slot: Slot,
    #[serde(default)]
    pub validator_count: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    pub hash: String,
    pub comment: String,
    pub test_id: String,
    pub description: String,
    pub fixture_format: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestVector {
    pub test_case: Vec<TestCase>,
}

/// Top-level wrapper for verify_signatures test vector files
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifySignaturesTestVectorFile {
    #[serde(flatten)]
    pub tests: HashMap<String, VerifySignaturesTestCase>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySignaturesTestCase {
    pub network: String,
    pub anchor_state: State,
    pub signed_block_with_attestation: SignedBlockWithAttestation,
    #[serde(default)]
    pub expect_exception: Option<String>,
    #[serde(rename = "_info")]
    pub info: Info,
}
