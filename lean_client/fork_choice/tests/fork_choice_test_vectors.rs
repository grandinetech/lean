use fork_choice::{
    handlers::{on_attestation, on_block, on_tick},
    store::{get_forkchoice_store, Store},
};

use containers::{
    attestation::{Attestation, AttestationData, Signature, SignedAttestation},
    block::{
        hash_tree_root, Block, BlockBody, BlockHeader, BlockWithAttestation,
        SignedBlockWithAttestation,
    },
    checkpoint::Checkpoint,
    config::Config,
    state::State,
    Bytes32, Slot, Uint64, ValidatorIndex,
};

use serde::Deserialize;
use ssz::{PersistentList, SszHash};
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVectorFile {
    #[serde(flatten)]
    tests: HashMap<String, TestVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVector {
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestConfig {
    genesis_time: u64,
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

#[derive(Debug, Deserialize)]
struct TestCheckpoint {
    root: String,
    slot: u64,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: String,
    state_root: String,
    body: TestBlockBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestBlockWithAttestation {
    block: TestBlock,
    proposer_attestation: TestAttestation,
    #[serde(default)]
    block_root_label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestBlockBody {
    attestations: TestDataWrapper<TestAttestation>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TestAttestation {
    #[serde(rename_all = "camelCase")]
    Nested {
        validator_id: u64,
        data: TestAttestationData,
    },
    #[serde(rename_all = "camelCase")]
    Flat {
        validator_id: u64,
        slot: u64,
        head: TestCheckpoint,
        target: TestCheckpoint,
        source: TestCheckpoint,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestAttestationData {
    slot: u64,
    head: TestCheckpoint,
    target: TestCheckpoint,
    source: TestCheckpoint,
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
    attestation: Option<TestAttestation>,
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

fn convert_test_checkpoint(test_cp: &TestCheckpoint) -> Checkpoint {
    Checkpoint {
        root: parse_root(&test_cp.root),
        slot: Slot(test_cp.slot),
    }
}

fn convert_test_attestation(test_att: &TestAttestation) -> Attestation {
    let (validator_id, slot, head, target, source) = match test_att {
        TestAttestation::Nested { validator_id, data } => (
            *validator_id,
            data.slot,
            &data.head,
            &data.target,
            &data.source,
        ),
        TestAttestation::Flat {
            validator_id,
            slot,
            head,
            target,
            source,
        } => (*validator_id, *slot, head, target, source),
    };

    Attestation {
        validator_id: Uint64(validator_id),
        data: AttestationData {
            slot: Slot(slot),
            head: convert_test_checkpoint(head),
            target: convert_test_checkpoint(target),
            source: convert_test_checkpoint(source),
        },
    }
}

fn convert_test_anchor_block(test_block: &TestAnchorBlock) -> SignedBlockWithAttestation {
    let mut attestations = ssz::PersistentList::default();

    for (i, test_att) in test_block.body.attestations.data.iter().enumerate() {
        let signed_vote = convert_test_attestation(test_att);
        attestations
            .push(signed_vote)
            .expect(&format!("Failed to add attestation {}", i));
    }

    let block = Block {
        slot: Slot(test_block.slot),
        proposer_index: ValidatorIndex(test_block.proposer_index),
        parent_root: parse_root(&test_block.parent_root),
        state_root: parse_root(&test_block.state_root),
        body: BlockBody { attestations },
    };

    // Create proposer attestation
    let proposer_attestation = Attestation {
        validator_id: Uint64(test_block.proposer_index),
        data: AttestationData {
            slot: Slot(test_block.slot),
            head: Checkpoint {
                root: parse_root(&test_block.parent_root),
                slot: Slot(test_block.slot),
            },
            target: Checkpoint {
                root: parse_root(&test_block.parent_root),
                slot: Slot(test_block.slot),
            },
            source: Checkpoint {
                root: parse_root(&test_block.parent_root),
                slot: Slot(0),
            },
        },
    };

    SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: PersistentList::default(),
    }
}

fn convert_test_block(
    test_block_with_att: &TestBlockWithAttestation,
) -> SignedBlockWithAttestation {
    let test_block = &test_block_with_att.block;
    let mut attestations = ssz::PersistentList::default();

    for (i, test_att) in test_block.body.attestations.data.iter().enumerate() {
        let signed_vote = convert_test_attestation(test_att);
        attestations
            .push(signed_vote)
            .expect(&format!("Failed to add attestation {}", i));
    }

    let block = Block {
        slot: Slot(test_block.slot),
        proposer_index: ValidatorIndex(test_block.proposer_index),
        parent_root: parse_root(&test_block.parent_root),
        state_root: parse_root(&test_block.state_root),
        body: BlockBody { attestations },
    };

    let proposer_attestation = convert_test_attestation(&test_block_with_att.proposer_attestation);

    SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: PersistentList::default(),
    }
}

fn initialize_state_from_test(test_state: &TestAnchorState) -> State {
    use containers::{
        HistoricalBlockHashes, JustificationRoots, JustificationsValidators, JustifiedSlots,
    };
    use ssz::PersistentList as List;

    let config = Config {
        genesis_time: test_state.config.genesis_time,
    };

    let latest_block_header = BlockHeader {
        slot: Slot(test_state.latest_block_header.slot),
        proposer_index: ValidatorIndex(test_state.latest_block_header.proposer_index),
        parent_root: parse_root(&test_state.latest_block_header.parent_root),
        state_root: parse_root(&test_state.latest_block_header.state_root),
        body_root: parse_root(&test_state.latest_block_header.body_root),
    };

    let mut historical_block_hashes = HistoricalBlockHashes::default();
    for hash_str in &test_state.historical_block_hashes.data {
        historical_block_hashes
            .push(parse_root(hash_str))
            .expect("within limit");
    }

    let mut justified_slots = JustifiedSlots::new(false, test_state.justified_slots.data.len());
    for (i, &val) in test_state.justified_slots.data.iter().enumerate() {
        if val {
            justified_slots.set(i, true);
        }
    }

    let mut justifications_roots = JustificationRoots::default();
    for root_str in &test_state.justifications_roots.data {
        justifications_roots
            .push(parse_root(root_str))
            .expect("within limit");
    }

    let mut justifications_validators =
        JustificationsValidators::new(false, test_state.justifications_validators.data.len());
    for (i, &val) in test_state.justifications_validators.data.iter().enumerate() {
        if val {
            justifications_validators.set(i, true);
        }
    }

    let mut validators = List::default();
    for test_validator in &test_state.validators.data {
        let pubkey = containers::validator::BlsPublicKey::from_hex(&test_validator.pubkey)
            .expect("Failed to parse validator pubkey");
        let validator = containers::validator::Validator {
            pubkey,
            index: containers::Uint64(test_validator.index),
        };
        validators.push(validator).expect("Failed to add validator");
    }

    State {
        config,
        slot: Slot(test_state.slot),
        latest_block_header,
        latest_justified: convert_test_checkpoint(&test_state.latest_justified),
        latest_finalized: convert_test_checkpoint(&test_state.latest_finalized),
        historical_block_hashes,
        justified_slots,
        validators,
        justifications_roots,
        justifications_validators,
    }
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
        let actual_slot = store.blocks[&store.head].message.block.slot.0;
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
            let actual_slot = store
                .blocks
                .get(&store.head)
                .map(|b| b.message.block.slot.0)
                .unwrap_or(0);
            let expected_slot = store
                .blocks
                .get(expected_root)
                .map(|b| b.message.block.slot.0)
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
                        let attestation = &store.latest_new_attestations[&validator];
                        if attestation.message.data.target.slot.0 != target_slot {
                            return Err(format!(
                                "Step {}: Validator {} new attestation target slot mismatch - expected {}, got {}",
                                step_idx, check.validator, target_slot, attestation.message.data.target.slot.0
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

fn run_single_test(_test_name: &str, test: TestVector) -> Result<(), String> {
    println!("  Running: {}", test.info.test_id);

    let mut anchor_state = initialize_state_from_test(&test.anchor_state);
    let anchor_block = convert_test_anchor_block(&test.anchor_block);

    let body_root = hash_tree_root(&anchor_block.message.block.body);
    anchor_state.latest_block_header = BlockHeader {
        slot: anchor_block.message.block.slot,
        proposer_index: anchor_block.message.block.proposer_index,
        parent_root: anchor_block.message.block.parent_root,
        state_root: anchor_block.message.block.state_root,
        body_root,
    };

    let config = Config {
        genesis_time: test.anchor_state.config.genesis_time,
    };

    let mut store = get_forkchoice_store(anchor_state, anchor_block, config);
    let mut block_labels: HashMap<String, Bytes32> = HashMap::new();

    for (step_idx, step) in test.steps.iter().enumerate() {
        match step.step_type.as_str() {
            "block" => {
                let test_block = step
                    .block
                    .as_ref()
                    .ok_or_else(|| format!("Step {}: Missing block data", step_idx))?;

                let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    let signed_block = convert_test_block(test_block);
                    let block_root = Bytes32(signed_block.message.block.hash_tree_root());

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
                    if let Some(label) = &test_block.block_root_label {
                        block_labels.insert(label.clone(), *block_root);
                    }
                }

                if step.valid && result.is_err() {
                    return Err(format!(
                        "Step {}: Block should be valid but processing failed: {:?}",
                        step_idx,
                        result.err()
                    ));
                } else if !step.valid && result.is_ok() {
                    return Err(format!(
                        "Step {}: Block should be invalid but processing succeeded",
                        step_idx
                    ));
                }

                if step.valid && result.is_ok() {
                    verify_checks(&store, &step.checks, &block_labels, step_idx)?;
                }
            }
            "tick" | "time" => {
                let time_value = step
                    .tick
                    .or(step.time)
                    .ok_or_else(|| format!("Step {}: Missing tick/time data", step_idx))?;
                on_tick(&mut store, time_value, false);

                if step.valid {
                    verify_checks(&store, &step.checks, &block_labels, step_idx)?;
                }
            }
            "attestation" => {
                let test_att = step
                    .attestation
                    .as_ref()
                    .ok_or_else(|| format!("Step {}: Missing attestation data", step_idx))?;

                let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    let attestation = convert_test_attestation(test_att);
                    let signed_attestation = SignedAttestation {
                        message: attestation,
                        signature: Signature::default(),
                    };
                    on_attestation(&mut store, signed_attestation, false)
                }));

                let result = match result {
                    Ok(inner) => inner,
                    Err(e) => Err(format!("Panic: {:?}", e)),
                };

                if step.valid && result.is_err() {
                    return Err(format!(
                        "Step {}: Attestation should be valid but processing failed: {:?}",
                        step_idx,
                        result.err()
                    ));
                } else if !step.valid && result.is_ok() {
                    return Err(format!(
                        "Step {}: Attestation should be invalid but processing succeeded",
                        step_idx
                    ));
                }

                if step.valid && result.is_ok() {
                    verify_checks(&store, &step.checks, &block_labels, step_idx)?;
                }
            }
            _ => {
                return Err(format!(
                    "Step {}: Unknown step type: {}",
                    step_idx, step.step_type
                ));
            }
        }
    }

    Ok(())
}

fn run_test_vector_file(test_path: &str) -> Result<(), String> {
    let json_str = std::fs::read_to_string(test_path)
        .map_err(|e| format!("Failed to read file {}: {}", test_path, e))?;

    let test_data: TestVectorFile = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse JSON from {}: {}", test_path, e))?;

    for (test_name, test_vector) in test_data.tests {
        run_single_test(&test_name, test_vector)?;
    }

    Ok(())
}

#[test]
fn test_fork_choice_head_vectors() {
    let test_dir = "../tests/test_vectors/test_fork_choice/test_fork_choice_head";

    let entries =
        std::fs::read_dir(test_dir).expect(&format!("Failed to read test directory: {}", test_dir));

    let mut test_count = 0;
    let mut pass_count = 0;
    let mut fail_count = 0;

    println!("\n=== Fork Choice Head Tests ===");

    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |ext| ext == "json") {
            test_count += 1;
            println!("\nTest file: {:?}", path.file_name().unwrap());

            match run_test_vector_file(path.to_str().unwrap()) {
                Ok(_) => {
                    println!("  ✓ PASSED");
                    pass_count += 1;
                }
                Err(e) => {
                    println!("  ✗ FAILED: {}", e);
                    fail_count += 1;
                }
            }
        }
    }

    println!("\n=== Summary ===");
    println!(
        "Total: {}, Passed: {}, Failed: {}",
        test_count, pass_count, fail_count
    );

    if fail_count > 0 {
        panic!("{} test(s) failed", fail_count);
    }
}

#[test]
fn test_attestation_processing_vectors() {
    let test_dir = "../tests/test_vectors/test_fork_choice/test_attestation_processing";

    let entries =
        std::fs::read_dir(test_dir).expect(&format!("Failed to read test directory: {}", test_dir));

    let mut test_count = 0;
    let mut pass_count = 0;
    let mut fail_count = 0;

    println!("\n=== Attestation Processing Tests ===");

    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |ext| ext == "json") {
            test_count += 1;
            println!("\nTest file: {:?}", path.file_name().unwrap());

            match run_test_vector_file(path.to_str().unwrap()) {
                Ok(_) => {
                    println!("  ✓ PASSED");
                    pass_count += 1;
                }
                Err(e) => {
                    println!("  ✗ FAILED: {}", e);
                    fail_count += 1;
                }
            }
        }
    }

    println!("\n=== Summary ===");
    println!(
        "Total: {}, Passed: {}, Failed: {}",
        test_count, pass_count, fail_count
    );

    if fail_count > 0 {
        panic!("{} test(s) failed", fail_count);
    }
}

#[test]
fn test_fork_choice_reorgs_vectors() {
    let test_dir = "../tests/test_vectors/test_fork_choice/test_fork_choice_reorgs";

    let entries =
        std::fs::read_dir(test_dir).expect(&format!("Failed to read test directory: {}", test_dir));

    let mut test_count = 0;
    let mut pass_count = 0;
    let mut fail_count = 0;

    println!("\n=== Fork Choice Reorg Tests ===");

    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |ext| ext == "json") {
            test_count += 1;
            println!("\nTest file: {:?}", path.file_name().unwrap());

            match run_test_vector_file(path.to_str().unwrap()) {
                Ok(_) => {
                    println!("  ✓ PASSED");
                    pass_count += 1;
                }
                Err(e) => {
                    println!("  ✗ FAILED: {}", e);
                    fail_count += 1;
                }
            }
        }
    }

    println!("\n=== Summary ===");
    println!(
        "Total: {}, Passed: {}, Failed: {}",
        test_count, pass_count, fail_count
    );

    if fail_count > 0 {
        panic!("{} test(s) failed", fail_count);
    }
}

#[test]
fn test_attestation_target_selection_vectors() {
    let test_dir = "../tests/test_vectors/test_fork_choice/test_attestation_target_selection";

    let entries =
        std::fs::read_dir(test_dir).expect(&format!("Failed to read test directory: {}", test_dir));

    let mut test_count = 0;
    let mut pass_count = 0;
    let mut fail_count = 0;

    println!("\n=== Attestation Target Selection Tests ===");

    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |ext| ext == "json") {
            test_count += 1;
            println!("\nTest file: {:?}", path.file_name().unwrap());

            match run_test_vector_file(path.to_str().unwrap()) {
                Ok(_) => {
                    println!("  ✓ PASSED");
                    pass_count += 1;
                }
                Err(e) => {
                    println!("  ✗ FAILED: {}", e);
                    fail_count += 1;
                }
            }
        }
    }

    println!("\n=== Summary ===");
    println!(
        "Total: {}, Passed: {}, Failed: {}",
        test_count, pass_count, fail_count
    );

    if fail_count > 0 {
        panic!("{} test(s) failed", fail_count);
    }
}

#[test]
fn test_lexicographic_tiebreaker_vectors() {
    let test_dir = "../tests/test_vectors/test_fork_choice/test_lexicographic_tiebreaker";

    let entries =
        std::fs::read_dir(test_dir).expect(&format!("Failed to read test directory: {}", test_dir));

    let mut test_count = 0;
    let mut pass_count = 0;
    let mut fail_count = 0;

    println!("\n=== Lexicographic Tiebreaker Tests ===");

    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |ext| ext == "json") {
            test_count += 1;
            println!("\nTest file: {:?}", path.file_name().unwrap());

            match run_test_vector_file(path.to_str().unwrap()) {
                Ok(_) => {
                    println!("  ✓ PASSED");
                    pass_count += 1;
                }
                Err(e) => {
                    println!("  ✗ FAILED: {}", e);
                    fail_count += 1;
                }
            }
        }
    }

    println!("\n=== Summary ===");
    println!(
        "Total: {}, Passed: {}, Failed: {}",
        test_count, pass_count, fail_count
    );

    if fail_count > 0 {
        panic!("{} test(s) failed", fail_count);
    }
}
