use fork_choice::{
    handlers::{on_block, on_tick},
    store::{get_forkchoice_store, Store},
};

use containers::{
    attestation::{Attestation, AttestationData},
    block::{
        hash_tree_root, Block, BlockBody, BlockHeader, BlockSignatures, BlockWithAttestation,
        SignedBlockWithAttestation,
    },
    checkpoint::Checkpoint,
    config::Config,
    public_key::PublicKey,
    state::State,
    AggregatedAttestation, AggregationBits, Bytes32, HistoricalBlockHashes, JustificationRoots,
    JustificationsValidators, JustifiedSlots, Signature, Slot, Uint64, ValidatorIndex, Validators,
};

use serde::Deserialize;
use ssz::{SszHash, H256};
use std::{collections::HashMap, fs::File};
use std::{panic::AssertUnwindSafe, path::Path};
use test_generator::test_resources;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    #[allow(dead_code)]
    network: String,
    anchor_state: TestAnchorState,
    anchor_block: TestAnchorBlock,
    steps: Vec<TestStep>,
    #[serde(rename = "_info")]
    info: TestInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestAnchorState {
    config: TestConfig,
    slot: u64,
    latest_block_header: TestBlockHeader,
    latest_justified: TestCheckpoint,
    latest_finalized: TestCheckpoint,
    #[serde(default)]
    historical_block_hashes: TestDataWrapper<String>,
    #[serde(default)]
    justified_slots: TestDataWrapper<bool>,
    validators: TestDataWrapper<TestValidator>,
    #[serde(default)]
    justifications_roots: TestDataWrapper<String>,
    #[serde(default)]
    justifications_validators: TestDataWrapper<bool>,
}

impl Into<State> for TestAnchorState {
    fn into(self) -> State {
        let config = self.config.into();

        let latest_block_header = self.latest_block_header.into();

        let mut historical_block_hashes = HistoricalBlockHashes::default();
        for hash_str in &self.historical_block_hashes.data {
            historical_block_hashes
                .push(parse_root(hash_str))
                .expect("within limit");
        }

        let mut justified_slots = JustifiedSlots::new(false, self.justified_slots.data.len());
        for (i, &val) in self.justified_slots.data.iter().enumerate() {
            if val {
                justified_slots.set(i, true);
            }
        }

        let mut justifications_roots = JustificationRoots::default();
        for root_str in &self.justifications_roots.data {
            justifications_roots
                .push(parse_root(root_str))
                .expect("within limit");
        }

        let mut justifications_validators =
            JustificationsValidators::new(false, self.justifications_validators.data.len());
        for (i, &val) in self.justifications_validators.data.iter().enumerate() {
            if val {
                justifications_validators.set(i, true);
            }
        }

        let mut validators = Validators::default();
        for test_validator in &self.validators.data {
            let pubkey = PublicKey::from_hex(&test_validator.pubkey)
                .expect("Failed to parse validator pubkey");
            let validator = containers::validator::Validator {
                pubkey,
                index: containers::Uint64(test_validator.index),
            };
            validators.push(validator).expect("Failed to add validator");
        }

        State {
            config,
            slot: Slot(self.slot),
            latest_block_header,
            latest_justified: self.latest_justified.into(),
            latest_finalized: self.latest_finalized.into(),
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
struct TestConfig {
    genesis_time: u64,
}

impl Into<Config> for TestConfig {
    fn into(self) -> Config {
        Config {
            genesis_time: self.genesis_time,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: String,
    state_root: String,
    body_root: String,
}

impl Into<BlockHeader> for TestBlockHeader {
    fn into(self) -> BlockHeader {
        BlockHeader {
            slot: Slot(self.slot),
            proposer_index: ValidatorIndex(self.proposer_index),
            parent_root: parse_root(&self.parent_root),
            state_root: parse_root(&self.state_root),
            body_root: parse_root(&self.body_root),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TestCheckpoint {
    root: String,
    slot: u64,
}

impl Into<Checkpoint> for TestCheckpoint {
    fn into(self) -> Checkpoint {
        Checkpoint {
            root: parse_root(&self.root),
            slot: Slot(self.slot),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct TestDataWrapper<T> {
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct TestValidator {
    #[allow(dead_code)]
    pubkey: String,
    #[allow(dead_code)]
    #[serde(default)]
    index: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestAnchorBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: String,
    state_root: String,
    body: TestBlockBody,
}

impl Into<SignedBlockWithAttestation> for TestAnchorBlock {
    fn into(self) -> SignedBlockWithAttestation {
        let mut attestations = ssz::PersistentList::default();

        for (i, attestation) in self.body.attestations.data.into_iter().enumerate() {
            attestations
                .push(attestation.into())
                .expect(&format!("Failed to add attestation {}", i));
        }

        let block = Block {
            slot: Slot(self.slot),
            proposer_index: ValidatorIndex(self.proposer_index),
            parent_root: parse_root(&self.parent_root),
            state_root: parse_root(&self.state_root),
            body: BlockBody { attestations },
        };

        // Create proposer attestation
        let proposer_attestation = Attestation {
            validator_id: Uint64(self.proposer_index),
            data: AttestationData {
                slot: Slot(self.slot),
                head: Checkpoint {
                    root: parse_root(&self.parent_root),
                    slot: Slot(self.slot),
                },
                target: Checkpoint {
                    root: parse_root(&self.parent_root),
                    slot: Slot(self.slot),
                },
                source: Checkpoint {
                    root: parse_root(&self.parent_root),
                    slot: Slot(0),
                },
            },
        };

        SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation,
            },
            signature: BlockSignatures::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: String,
    state_root: String,
    body: TestBlockBody,
}

impl Into<Block> for TestBlock {
    fn into(self) -> Block {
        Block {
            slot: Slot(self.slot),
            proposer_index: ValidatorIndex(self.proposer_index),
            parent_root: parse_root(&self.parent_root),
            state_root: parse_root(&self.state_root),
            body: self.body.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestBlockWithAttestation {
    block: TestBlock,
    proposer_attestation: TestAttestation,
    #[serde(default)]
    block_root_label: Option<String>,
}

impl Into<BlockWithAttestation> for TestBlockWithAttestation {
    fn into(self) -> BlockWithAttestation {
        BlockWithAttestation {
            block: self.block.into(),
            proposer_attestation: self.proposer_attestation.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestAttestation {
    validator_id: u64,
    data: TestAttestationData,
}

impl Into<Attestation> for TestAttestation {
    fn into(self) -> Attestation {
        Attestation {
            validator_id: Uint64(self.validator_id),
            data: self.data.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TestBlockBody {
    attestations: TestDataWrapper<TestAggregatedAttestation>,
}

impl Into<BlockBody> for TestBlockBody {
    fn into(self) -> BlockBody {
        let mut attestations = ssz::PersistentList::default();

        for attestation in self.attestations.data {
            attestations
                .push(attestation.into())
                .expect("failed to add attestation");
        }

        BlockBody { attestations }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestAggregatedAttestation {
    aggregation_bits: TestAggregationBits,
    data: TestAttestationData,
}

impl Into<AggregatedAttestation> for TestAggregatedAttestation {
    fn into(self) -> AggregatedAttestation {
        AggregatedAttestation {
            aggregation_bits: self.aggregation_bits.into(),
            data: self.data.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TestAggregationBits {
    data: Vec<bool>,
}

impl Into<AggregationBits> for TestAggregationBits {
    fn into(self) -> AggregationBits {
        let mut bitlist = ssz::BitList::with_length(self.data.len());
        for (i, &bit) in self.data.iter().enumerate() {
            bitlist.set(i, bit);
        }
        AggregationBits(bitlist)
    }
}

#[derive(Debug, Deserialize)]
struct TestAttestationData {
    slot: u64,
    head: TestCheckpoint,
    target: TestCheckpoint,
    source: TestCheckpoint,
}

impl Into<AttestationData> for TestAttestationData {
    fn into(self) -> AttestationData {
        AttestationData {
            slot: Slot(self.slot),
            head: self.head.into(),
            target: self.target.into(),
            source: self.source.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestStep {
    valid: bool,
    #[serde(default)]
    checks: Option<TestChecks>,
    #[serde(rename = "stepType")]
    step_type: String,
    block: Option<TestBlockWithAttestation>,
    attestation: Option<TestAggregatedAttestation>,
    tick: Option<u64>,
    time: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestChecks {
    #[serde(rename = "headSlot")]
    head_slot: Option<u64>,
    #[serde(rename = "headRootLabel")]
    head_root_label: Option<String>,
    #[serde(rename = "attestationChecks")]
    attestation_checks: Option<Vec<AttestationCheck>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationCheck {
    validator: u64,
    #[allow(dead_code)]
    #[serde(rename = "attestationSlot")]
    attestation_slot: u64,
    #[serde(rename = "targetSlot")]
    target_slot: Option<u64>,
    location: String,
}

#[derive(Debug, Deserialize)]
struct TestInfo {
    #[allow(dead_code)]
    hash: String,
    #[allow(dead_code)]
    comment: String,
    #[serde(rename = "testId")]
    test_id: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    #[serde(rename = "fixtureFormat")]
    fixture_format: String,
}

fn parse_root(hex_str: &str) -> Bytes32 {
    let hex = hex_str.trim_start_matches("0x");
    let mut bytes = [0u8; 32];

    if hex.len() == 64 {
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|_| panic!("Invalid hex at position {}: {}", i, hex));
        }
    } else if !hex.chars().all(|c| c == '0') {
        panic!("Invalid root length: {} (expected 64 hex chars)", hex.len());
    }

    Bytes32(ssz::H256::from(bytes))
}

fn verify_checks(
    store: &Store,
    checks: &Option<TestChecks>,
    block_labels: &HashMap<String, Bytes32>,
    step_idx: usize,
) -> Result<(), String> {
    // If no checks provided, nothing to verify
    let checks = match checks {
        Some(c) => c,
        None => return Ok(()),
    };

    if let Some(expected_slot) = checks.head_slot {
        // Per devnet-2, store.blocks now contains Block (not SignedBlockWithAttestation)
        let actual_slot = store.blocks[&store.head].slot.0;
        if actual_slot != expected_slot {
            return Err(format!(
                "Step {}: Head slot mismatch - expected {}, got {}",
                step_idx, expected_slot, actual_slot
            ));
        }
    }

    if let Some(label) = &checks.head_root_label {
        let expected_root = block_labels
            .get(label)
            .ok_or_else(|| format!("Step {}: Block label '{}' not found", step_idx, label))?;
        if &store.head != expected_root {
            // Per devnet-2, store.blocks now contains Block (not SignedBlockWithAttestation)
            let actual_slot = store.blocks.get(&store.head).map(|b| b.slot.0).unwrap_or(0);
            let expected_slot = store
                .blocks
                .get(expected_root)
                .map(|b| b.slot.0)
                .unwrap_or(0);
            return Err(format!(
                "Step {}: Head root mismatch for label '{}' - expected slot {}, got slot {} (known_attestations: {}, new_attestations: {})",
                step_idx, label, expected_slot, actual_slot,
                store.latest_known_attestations.len(), store.latest_new_attestations.len()
            ));
        }
    }

    if let Some(att_checks) = &checks.attestation_checks {
        for check in att_checks {
            let validator = ValidatorIndex(check.validator);

            match check.location.as_str() {
                "new" => {
                    if !store.latest_new_attestations.contains_key(&validator) {
                        return Err(format!(
                            "Step {}: Expected validator {} in new attestations, but not found",
                            step_idx, check.validator
                        ));
                    }
                    if let Some(target_slot) = check.target_slot {
                        // Per devnet-2, store now holds AttestationData directly (not SignedAttestation)
                        let attestation_data = &store.latest_new_attestations[&validator];
                        if attestation_data.target.slot.0 != target_slot {
                            return Err(format!(
                                "Step {}: Validator {} new attestation target slot mismatch - expected {}, got {}",
                                step_idx, check.validator, target_slot, attestation_data.target.slot.0
                            ));
                        }
                    }
                }
                "known" => {
                    if !store.latest_known_attestations.contains_key(&validator) {
                        return Err(format!(
                            "Step {}: Expected validator {} in known attestations, but not found",
                            step_idx, check.validator
                        ));
                    }
                }
                _ => {
                    return Err(format!(
                        "Step {}: Unknown attestation location: {}",
                        step_idx, check.location
                    ));
                }
            }
        }
    }

    Ok(())
}

#[test_resources("test_vectors/fork_choice/*/fc/*/*.json")]
fn forkchoice(spec_file: &str) {
    let spec_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(spec_file);
    let mut file =
        File::open(&spec_path).expect(&format!("failed to open spec file {spec_path:?}"));
    let test_cases: HashMap<String, TestCase> = serde_json::from_reader(&mut file).unwrap();

    for (_, case) in test_cases {
        let config = Config {
            genesis_time: case.anchor_state.config.genesis_time,
        };

        let mut anchor_state: State = case.anchor_state.into();
        let anchor_block: SignedBlockWithAttestation = case.anchor_block.into();

        let body_root = hash_tree_root(&anchor_block.message.block.body);
        anchor_state.latest_block_header = BlockHeader {
            slot: anchor_block.message.block.slot,
            proposer_index: anchor_block.message.block.proposer_index,
            parent_root: anchor_block.message.block.parent_root,
            state_root: anchor_block.message.block.state_root,
            body_root,
        };

        let mut store = get_forkchoice_store(anchor_state, anchor_block, config);
        let mut block_labels: HashMap<String, Bytes32> = HashMap::new();

        for (step_idx, step) in case.steps.into_iter().enumerate() {
            match step.step_type.as_str() {
                "block" => {
                    let test_block = step
                        .block
                        .expect(&format!("Step {step_idx}: Missing block data"));

                    let block_root_label = test_block.block_root_label.clone();

                    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        let block: BlockWithAttestation = test_block.into();
                        let signed_block: SignedBlockWithAttestation = SignedBlockWithAttestation {
                            message: block,
                            signature: BlockSignatures::default(),
                        };
                        let block_root = containers::block::compute_block_root(&signed_block.message.block);

                        // Advance time to the block's slot to ensure attestations are processable
                        // SECONDS_PER_SLOT is 4 (not 12)
                        let block_time =
                            store.config.genesis_time + (signed_block.message.block.slot.0 * 4);
                        on_tick(&mut store, block_time, false);

                        on_block(&mut store, signed_block)?;
                        Ok(block_root)
                    }));

                    let result = match result {
                        Ok(inner) => inner,
                        Err(e) => Err(format!("Panic: {:?}", e)),
                    };

                    if let Ok(block_root) = &result {
                        if let Some(label) = block_root_label {
                            block_labels.insert(label.clone(), *block_root);
                        }
                    }

                    if step.valid && result.is_err() {
                        panic!(
                            "Step {step_idx}: Block should be valid but processing failed: {:?}",
                            result.err().unwrap()
                        );
                    } else if !step.valid && result.is_ok() {
                        panic!(
                            "Step: {step_idx}: Block should be invalid but processing succeeded"
                        );
                    }

                    if step.valid && result.is_ok() {
                        verify_checks(&store, &step.checks, &block_labels, step_idx).expect(
                            &format!("Step: {step_idx}: Should be valid but checks failed"),
                        );
                    }
                }
                "tick" | "time" => {
                    let time_value = step
                        .tick
                        .or(step.time)
                        .expect(&format!("Step {step_idx}: Missing tick/time data"));
                    on_tick(&mut store, time_value, false);

                    if step.valid {
                        verify_checks(&store, &step.checks, &block_labels, step_idx).expect(
                            &format!("Step: {step_idx}: Should be valid but checks failed"),
                        );
                    }
                }
                // "attestation" => {
                //     let test_att = step
                //         .attestation
                //         .as_ref()
                //         .expect(&format!("Step {}: Missing attestation data", step_idx));

                //     let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                //         let attestation: AttestationData = test_att.into();
                //         let signed_attestation = SignedAttestation {
                //             message: attestation,
                //             signature: Signature::default(),
                //         };
                //         on_attestation(&mut store, signed_attestation, false)
                //     }));

                //     let result = match result {
                //         Ok(inner) => inner,
                //         Err(e) => Err(format!("Panic: {:?}", e)),
                //     };

                //     if step.valid && result.is_err() {
                //         panic!("Step {step_idx}: Attestation should be valid but processing failed: {:?}", result.err().unwrap());
                //     } else if !step.valid && result.is_ok() {
                //         panic!("Step {step_idx}: Attestation should be invalid but processing succeeded");
                //     }

                //     if step.valid && result.is_ok() {
                //         verify_checks(&store, &step.checks, &block_labels, step_idx)?;
                //     }
                // }
                _ => {
                    panic!("Step {step_idx}: Unknown step type: {}", step.step_type);
                }
            }
        }
    }
}
