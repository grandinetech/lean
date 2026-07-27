//! Fork-choice fixture types matching the JSON emitted by leanSpec.
//!
//! The `steps` array is a discriminated union keyed on `stepType`. We model
//! it as a Rust enum tagged with `#[serde(tag = "stepType")]` so the
//! deserializer rejects unknown variants instead of silently dropping fields.

use serde::Deserialize;

use crate::common::{
    HexBytesJSON, TestAggregationBits, TestAnchorBlock, TestAnchorState, TestAttestation,
    TestAttestationData, TestBlockWithAttestation,
};

/// Top-level fork-choice fixture case (one entry inside the JSON file's
/// `{test_name -> case}` map).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkChoiceTest {
    pub network: String,
    pub anchor_state: TestAnchorState,
    pub anchor_block: TestAnchorBlock,
    pub steps: Vec<ForkChoiceStep>,
}

/// One step in a fork-choice fixture's `steps` array.
///
/// The `stepType` discriminator selects the variant. Unknown discriminators
/// will fail to deserialize, which is the desired behaviour: a fixture using
/// a step type the harness does not understand should fail loudly so we know
/// to add support for it.
#[derive(Debug, Deserialize)]
#[serde(tag = "stepType", rename_all = "camelCase")]
pub enum ForkChoiceStep {
    /// Advance store time. Fixtures supply exactly one of:
    ///   - `time`     — absolute wall-clock seconds since the unix epoch.
    ///   - `interval` — target store-interval to advance to (relative).
    /// `hasProposal` defaults to false.
    #[serde(rename = "tick")]
    Tick {
        #[serde(default)]
        valid: Option<bool>,
        #[serde(default)]
        time: Option<u64>,
        #[serde(default)]
        interval: Option<u64>,
        #[serde(default)]
        has_proposal: Option<bool>,
        #[serde(default)]
        checks: Option<StoreChecks>,
    },
    /// Older alias used by some fixtures that emit `stepType: "time"`.
    /// Same payload semantics as `Tick`.
    #[serde(rename = "time")]
    Time {
        #[serde(default)]
        valid: Option<bool>,
        #[serde(default)]
        time: Option<u64>,
        #[serde(default)]
        interval: Option<u64>,
        #[serde(default)]
        has_proposal: Option<bool>,
        #[serde(default)]
        checks: Option<StoreChecks>,
    },
    /// Apply a block to the store.
    #[serde(rename = "block")]
    Block {
        valid: bool,
        #[serde(default)]
        checks: Option<StoreChecks>,
        block: TestBlockWithAttestation,
    },
    /// Apply a single-validator gossip attestation to the store.
    #[serde(rename = "attestation")]
    Attestation {
        valid: bool,
        #[serde(default)]
        checks: Option<StoreChecks>,
        attestation: TestAttestation,
    },
    /// Apply an aggregated attestation received via gossip.
    ///
    /// Unlike `Attestation`, the fixture for this step ships the
    /// pre-computed aggregated XMSS proof (the harness can never
    /// re-aggregate it without the producer's private keys), so the inner
    /// payload is the richer [`GossipAggregatedAttestationStep`] rather
    /// than a plain `TestAggregatedAttestation`.
    #[serde(rename = "gossipAggregatedAttestation")]
    GossipAggregatedAttestation {
        #[serde(default)]
        valid: Option<bool>,
        #[serde(default)]
        checks: Option<StoreChecks>,
        #[serde(default)]
        attestation: Option<GossipAggregatedAttestationStep>,
    },
    /// A pure assertion step — no state mutation, only checks.
    #[serde(rename = "checks")]
    Checks { checks: StoreChecks },
}

/// Subset of fork-choice store fields a fixture step can assert against.
/// All fields are optional; only the ones the fixture supplies are checked.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreChecks {
    #[serde(default)]
    pub head_slot: Option<u64>,
    #[serde(default)]
    pub head_root: Option<String>,
    #[serde(default)]
    pub head_root_label: Option<String>,
    #[serde(default)]
    pub time: Option<u64>,
    #[serde(default)]
    pub justified_checkpoint: Option<CheckpointCheck>,
    #[serde(default)]
    pub finalized_checkpoint: Option<CheckpointCheck>,
    #[serde(default)]
    pub safe_target: Option<String>,
    #[serde(default)]
    pub attestation_checks: Vec<AttestationCheck>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointCheck {
    pub slot: u64,
    pub root: String,
}

/// Per-validator attestation check inside a fork-choice step's `attestationChecks` array.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationCheck {
    pub validator: u64,
    #[serde(default)]
    pub attestation_slot: Option<u64>,
    #[serde(default)]
    pub source_slot: Option<u64>,
    #[serde(default)]
    pub target_slot: Option<u64>,
    pub location: String,
}

/// Payload for the `gossipAggregatedAttestation` step variant.
///
/// Mirrors the shape leanSpec emits: an attestation `data` body plus a
/// pre-computed aggregated XMSS proof. The harness consumes the proof bytes
/// directly because reconstructing them would require the producer's
/// private keys.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GossipAggregatedAttestationStep {
    pub data: TestAttestationData,
    pub proof: GossipProofJSON,
}

/// The pre-computed aggregated proof bundle attached to a gossip aggregated
/// attestation step.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GossipProofJSON {
    pub participants: TestAggregationBits,
    #[serde(alias = "proof")]
    pub proof_data: HexBytesJSON,
}
