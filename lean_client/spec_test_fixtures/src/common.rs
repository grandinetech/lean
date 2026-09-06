//! Shared serde types for all leanSpec spec-test JSON fixtures.
//!
//! One module (this one) holds every fixture-shape consensus type (state,
//! block, attestation, signed block); the per-family modules
//! (`fork_choice.rs`, `state_transition.rs`, `verify_signatures.rs`) hold
//! only the top-level fixture wrappers.

use containers::{
    AggregatedAttestation, AggregatedSignatureProof, AggregationBits, Attestation, AttestationData,
    Block, BlockBody, BlockHeader, Checkpoint, Config, HistoricalBlockHashes, JustificationRoots,
    JustificationValidators, JustifiedSlots, MultiMessageAggregate, SignedBlock, Slot, State,
    Validator, Validators,
};
use serde::Deserialize;
use ssz::{BitList, H256, PersistentList};
use xmss::{AggregatedSignature, PublicKey};

// === Primitive wrappers ====================================================

/// Wrapper that matches the `{"data": [...]}` envelope used by leanSpec
/// fixtures for variable-length lists (e.g. `historicalBlockHashes`,
/// `validators`, `justifiedSlots`).
#[derive(Debug, Default, Deserialize)]
pub struct TestDataWrapper<T> {
    pub data: Vec<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestConfig {
    pub genesis_time: u64,
}

impl From<TestConfig> for Config {
    fn from(value: TestConfig) -> Self {
        Self {
            genesis_time: value.genesis_time,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TestCheckpoint {
    pub root: String,
    pub slot: u64,
}

impl From<TestCheckpoint> for Checkpoint {
    fn from(value: TestCheckpoint) -> Self {
        Self {
            root: parse_root(&value.root),
            slot: Slot(value.slot),
        }
    }
}

/// Validator entry as it appears in fork-choice fixtures. Both pubkey fields
/// are loaded as strings; the conversion to `containers::Validator` parses
/// them via `xmss::PublicKey::FromStr`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestValidator {
    /// Legacy single-key fixtures emit `pubkey` instead of the camelCase
    /// `attestationPublicKey`; `rename_all` handles the camelCase, the explicit
    /// alias keeps the legacy form working.
    #[serde(alias = "pubkey")]
    pub attestation_public_key: String,
    #[serde(default)]
    pub proposal_public_key: Option<String>,
    #[serde(default)]
    pub index: u64,
}

/// Parse a 32-byte root encoded as either `0x...` hex or a short all-zero
/// placeholder used by some fixtures. Panics on malformed input — these
/// fixtures are vendored and validated, so a malformed root indicates a real
/// bug rather than user input.
#[must_use]
pub fn parse_root(hex_str: &str) -> H256 {
    let hex = hex_str.trim_start_matches("0x");
    let mut bytes = [0u8; 32];

    if hex.len() == 64 {
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|_| panic!("Invalid hex at position {i}: {hex}"));
        }
    } else if !hex.chars().all(|c| c == '0') {
        panic!("Invalid root length: {} (expected 64 hex chars)", hex.len());
    }

    H256::from(bytes)
}

// === Attestation types =====================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestAttestation {
    pub validator_index: u64,
    pub data: TestAttestationData,
}

impl From<TestAttestation> for Attestation {
    fn from(value: TestAttestation) -> Self {
        Self {
            validator_id: value.validator_index,
            data: value.data.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TestAttestationData {
    pub slot: u64,
    pub head: TestCheckpoint,
    pub target: TestCheckpoint,
    pub source: TestCheckpoint,
}

impl From<TestAttestationData> for AttestationData {
    fn from(value: TestAttestationData) -> Self {
        Self {
            slot: Slot(value.slot),
            head: value.head.into(),
            target: value.target.into(),
            source: value.source.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestAggregatedAttestation {
    pub aggregation_bits: TestAggregationBits,
    pub data: TestAttestationData,
}

impl From<TestAggregatedAttestation> for AggregatedAttestation {
    fn from(value: TestAggregatedAttestation) -> Self {
        Self {
            aggregation_bits: value.aggregation_bits.into(),
            data: value.data.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TestAggregationBits {
    pub data: Vec<bool>,
}

impl From<TestAggregationBits> for AggregationBits {
    fn from(value: TestAggregationBits) -> Self {
        let mut bitlist = BitList::with_length(value.data.len());
        for (i, &bit) in value.data.iter().enumerate() {
            bitlist.set(i, bit);
        }
        Self(bitlist)
    }
}

// === State + block-header types ============================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestAnchorState {
    pub config: TestConfig,
    pub slot: u64,
    pub latest_block_header: TestBlockHeader,
    pub latest_justified: TestCheckpoint,
    pub latest_finalized: TestCheckpoint,
    #[serde(default)]
    pub historical_block_hashes: TestDataWrapper<String>,
    #[serde(default)]
    pub justified_slots: TestDataWrapper<bool>,
    pub validators: TestDataWrapper<TestValidator>,
    #[serde(default)]
    pub justifications_roots: TestDataWrapper<String>,
    #[serde(default)]
    pub justifications_validators: TestDataWrapper<bool>,
}

impl From<TestAnchorState> for State {
    fn from(value: TestAnchorState) -> Self {
        let config = value.config.into();
        let latest_block_header = value.latest_block_header.into();

        let mut historical_block_hashes = HistoricalBlockHashes::default();
        for hash_str in &value.historical_block_hashes.data {
            historical_block_hashes
                .push(parse_root(hash_str))
                .expect("historical_block_hashes within capacity");
        }

        let mut justified_slots =
            JustifiedSlots(BitList::new(false, value.justified_slots.data.len()));
        for (i, &bit) in value.justified_slots.data.iter().enumerate() {
            if bit {
                justified_slots.0.set(i, true);
            }
        }

        let mut justifications_roots = JustificationRoots::default();
        for root_str in &value.justifications_roots.data {
            justifications_roots
                .push(parse_root(root_str))
                .expect("justifications_roots within capacity");
        }

        let mut justifications_validators =
            JustificationValidators::new(false, value.justifications_validators.data.len());
        for (i, &bit) in value.justifications_validators.data.iter().enumerate() {
            if bit {
                justifications_validators.set(i, true);
            }
        }

        let mut validators = Validators::default();
        for test_validator in &value.validators.data {
            let attestation_pubkey: PublicKey = test_validator
                .attestation_public_key
                .parse()
                .expect("Failed to parse validator attestation_pubkey");
            let proposal_pubkey: PublicKey = test_validator
                .proposal_public_key
                .as_deref()
                .map(|s| {
                    s.parse()
                        .expect("Failed to parse validator proposal_pubkey")
                })
                .unwrap_or_default();
            validators
                .push(Validator {
                    attestation_pubkey,
                    proposal_pubkey,
                    index: test_validator.index,
                })
                .expect("validators within capacity");
        }

        Self {
            config,
            slot: Slot(value.slot),
            latest_block_header,
            latest_justified: value.latest_justified.into(),
            latest_finalized: value.latest_finalized.into(),
            historical_block_hashes,
            justified_slots,
            validators,
            justifications_roots,
            justifications_validators,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: String,
    pub state_root: String,
    pub body_root: String,
}

impl From<TestBlockHeader> for BlockHeader {
    fn from(value: TestBlockHeader) -> Self {
        Self {
            slot: Slot(value.slot),
            proposer_index: value.proposer_index,
            parent_root: parse_root(&value.parent_root),
            state_root: parse_root(&value.state_root),
            body_root: parse_root(&value.body_root),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestBlock {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: String,
    pub state_root: String,
    pub body: TestBlockBody,
}

impl From<TestBlock> for Block {
    fn from(value: TestBlock) -> Self {
        Self {
            slot: Slot(value.slot),
            proposer_index: value.proposer_index,
            parent_root: parse_root(&value.parent_root),
            state_root: parse_root(&value.state_root),
            body: value.body.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TestBlockBody {
    pub attestations: TestDataWrapper<TestAggregatedAttestation>,
}

impl From<TestBlockBody> for BlockBody {
    fn from(value: TestBlockBody) -> Self {
        let mut attestations = PersistentList::default();
        for attestation in value.attestations.data {
            attestations
                .push(attestation.into())
                .expect("block body attestations within capacity");
        }
        Self { attestations }
    }
}

/// Variant of `TestBlock` used inside fork-choice steps. Carries an optional
/// `blockRootLabel` that the fixture uses to refer to a block produced by
/// this step in subsequent `headRootLabel` checks.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestBlockWithAttestation {
    #[serde(flatten)]
    pub block: TestBlock,
    /// Ignored in devnet4 — proposer attestation removed from block format.
    #[serde(default)]
    pub proposer_attestation: Option<TestAttestation>,
    #[serde(default)]
    pub block_root_label: Option<String>,
}

impl From<TestBlockWithAttestation> for Block {
    fn from(value: TestBlockWithAttestation) -> Self {
        value.block.into()
    }
}

// === Anchor block ==========================================================

/// Anchor block fixture type — leanSpec's anchor block JSON does not carry a
/// signature, so the conversion wraps the inner block in a `SignedBlock` with
/// the default (zero) `BlockSignatures`. Distinct from `TestSignedBlock`
/// (which the simulator uses for the `verify_signatures` family) because
/// anchor JSON has no `signature` envelope.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestAnchorBlock {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: String,
    pub state_root: String,
    pub body: TestAnchorBlockBody,
}

#[derive(Debug, Deserialize)]
pub struct TestAnchorBlockBody {
    pub attestations: TestDataWrapper<TestAggregatedAttestation>,
}

impl From<TestAnchorBlock> for SignedBlock {
    fn from(value: TestAnchorBlock) -> Self {
        let mut attestations = PersistentList::default();
        for attestation in value.body.attestations.data {
            attestations
                .push(attestation.into())
                .expect("anchor block attestations within capacity");
        }

        let block = Block {
            slot: Slot(value.slot),
            proposer_index: value.proposer_index,
            parent_root: parse_root(&value.parent_root),
            state_root: parse_root(&value.state_root),
            body: BlockBody { attestations },
        };

        Self {
            block,
            proof: MultiMessageAggregate::default(),
        }
    }
}

// === Signed block (verify_signatures family) ===============================

/// Wrapper around hex-encoded byte payloads serialized as `{"data": "0x..."}`.
/// Reused by `TestAggregatedSignatureProofFixture::proof_data` and by
/// fork-choice's `gossipAggregatedAttestation` step proof bundle.
#[derive(Debug, Deserialize)]
pub struct HexBytesJSON {
    pub data: String,
}

/// Fixture-shape signed block (devnet5).
///
/// Mirrors leanSpec's `SignedBlock { block, proof: MultiMessageAggregate }`
/// where `MultiMessageAggregate` is the container `{ proof: ByteList512KiB }`.
#[derive(Debug, Deserialize)]
pub struct TestSignedBlock {
    pub block: TestBlock,
    pub proof: TestMultiMessageAggregateFixture,
}

#[derive(Debug, Deserialize)]
pub struct TestMultiMessageAggregateFixture {
    pub proof: HexBytesJSON,
}

/// One entry inside `signature.attestationSignatures.data`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestAggregatedSignatureProofFixture {
    pub participants: TestAggregationBits,
    pub proof_data: HexBytesJSON,
}

impl TryFrom<TestSignedBlock> for SignedBlock {
    type Error = String;

    fn try_from(value: TestSignedBlock) -> Result<Self, Self::Error> {
        let block = value.block.into();
        let bytes = decode_hex(&value.proof.proof.data)?;
        let proof = MultiMessageAggregate::new(&bytes)
            .map_err(|err| format!("multi-message aggregate decode: {err}"))?;
        Ok(Self { block, proof })
    }
}

impl TryFrom<TestAggregatedSignatureProofFixture> for AggregatedSignatureProof {
    type Error = String;

    fn try_from(value: TestAggregatedSignatureProofFixture) -> Result<Self, Self::Error> {
        let bytes = decode_hex(&value.proof_data.data)?;
        let proof_data = AggregatedSignature::new(&bytes)
            .map_err(|err| format!("aggregated signature decode: {err}"))?;
        Ok(Self {
            participants: value.participants.into(),
            proof_data,
        })
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim_start_matches("0x");
    hex::decode(trimmed).map_err(|err| format!("hex decode failed: {err}"))
}
