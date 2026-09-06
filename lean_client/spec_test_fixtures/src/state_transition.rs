//! State-transition fixture types.
//!
//! Uses fixture-shape wrappers (`TestAnchorState`, `TestBlock`) rather than
//! the raw `containers::State` / `containers::Block` because
//! `containers::Validator` is derived without `#[serde(rename_all =
//! "camelCase")]` and so cannot deserialize the leanSpec fixture's
//! `attestationPubkey` / `proposalPubkey` keys.

use std::collections::HashMap;

use containers::Slot;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::common::{TestAnchorState, TestBlock};

/// Top-level wrapper for a state-transition fixture file. Each file holds a
/// `{test_name -> case}` map.
#[derive(Debug, Deserialize)]
pub struct TestVectorFile {
    #[serde(flatten)]
    pub tests: HashMap<String, TestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestCase {
    #[serde(default)]
    pub network: Option<String>,
    pub pre: TestAnchorState,
    /// Some fixtures wrap the block list in `{"data": [...]}`; others use a
    /// plain array. The flexible deserializer handles both shapes.
    #[serde(deserialize_with = "deserialize_flexible", default)]
    pub blocks: Option<Vec<TestBlock>>,
    #[serde(default)]
    pub post: Option<PostState>,
    #[serde(default)]
    pub rejection_reason: Option<String>,
    /// `_info` is metadata for traceability; we don't read any sub-field, so
    /// we keep it fully optional to tolerate fixtures that omit it.
    #[serde(default, rename = "_info")]
    pub info: Option<Info>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostState {
    #[serde(default)]
    pub slot: Option<Slot>,
    #[serde(default)]
    pub validator_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    pub hash: String,
    pub comment: String,
    pub test_id: String,
    pub description: String,
    pub fixture_format: String,
}

/// Deserialize a value that may appear either as a plain JSON value or as
/// `{"data": <value>}`. Used because some leanSpec fixtures wrap collections
/// in a `data` envelope while others do not.
fn deserialize_flexible<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::de::Error;

    let value = Value::deserialize(deserializer)?;

    if let Value::Object(ref map) = value {
        if map.len() == 1 {
            if let Some(data_value) = map.get("data") {
                return serde_json::from_value(data_value.clone()).map_err(|e| {
                    D::Error::custom(format!("Failed to deserialize from data wrapper: {e}"))
                });
            }
        }
    }

    serde_json::from_value(value)
        .map_err(|e| D::Error::custom(format!("Failed to deserialize plain value: {e}")))
}
