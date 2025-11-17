// Integration test: All block processing test vectors
use super::runner::TestRunner;

// Legacy test vector, possible DELETION in the future
#[test]
fn run_sequential_block_processing_test() {
    let test_path = "../tests/test_vectors/test_blocks/test_sequential_blocks.json";
    if std::path::Path::new(test_path).exists() {
        TestRunner::run_sequential_block_processing_tests(test_path)
            .expect("Block processing tests should pass");
    } else {
        println!("Test vector file not found, skipping: {}", test_path);
    }
}

// Legacy test vector, possible DELETION in the future
#[test]
fn run_single_empty_block_test() {
    let test_path = "../tests/test_vectors/test_blocks/test_single_empty_block.json";
    if std::path::Path::new(test_path).exists() {
        TestRunner::run_single_empty_block_tests(test_path)
            .expect("Single empty block test should pass");
    } else {
        println!("Test vector file not found, skipping: {}", test_path);
    }
}

// Legacy test vector, possible DELETION in the future
#[test]
fn run_single_block_with_slot_gap_test() {
    let test_path = "../tests/test_vectors/test_blocks/test_single_empty_block.json";
    if std::path::Path::new(test_path).exists() {
        TestRunner::run_single_block_with_slot_gap_tests(test_path)
            .expect("State transition tests should pass");
    } else {
        println!("Test vector file not found, skipping: {}", test_path);
    }
}

#[test]
fn test_process_first_block_after_genesis() {
    let test_path = "../tests/test_vectors/test_blocks/test_process_first_block_after_genesis.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_process_first_block_after_genesis failed");
}

#[test]
fn test_sequential_blocks() {
    let test_path = "../tests/test_vectors/test_blocks/test_sequential_blocks.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_sequential_blocks failed");
}

#[test]
fn test_single_block_with_slot_gap() {
    let test_path = "../tests/test_vectors/test_blocks/test_single_block_with_slot_gap.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_single_block_with_slot_gap failed");
}

#[test]
fn test_single_empty_block() {
    let test_path = "../tests/test_vectors/test_blocks/test_single_empty_block.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_single_empty_block failed");
}

#[test]
fn test_blocks_with_gaps() {
    let test_path = "../tests/test_vectors/test_blocks/test_blocks_with_gaps.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_blocks_with_gaps failed");
}

#[test]
fn test_linear_chain_multiple_blocks() {
    let test_path = "../tests/test_vectors/test_blocks/test_linear_chain_multiple_blocks.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_linear_chain_multiple_blocks failed");
}

#[test]
fn test_block_extends_deep_chain() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_extends_deep_chain.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_extends_deep_chain failed");
}

#[test]
fn test_empty_blocks() {
    let test_path = "../tests/test_vectors/test_blocks/test_empty_blocks.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_empty_blocks failed");
}

#[test]
fn test_empty_blocks_with_missed_slots() {
    let test_path = "../tests/test_vectors/test_blocks/test_empty_blocks_with_missed_slots.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_empty_blocks_with_missed_slots failed");
}

#[test]
fn test_block_at_large_slot_number() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_at_large_slot_number.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_at_large_slot_number failed");
}

// Invalid block tests (expecting failures)

#[test]
fn test_block_with_invalid_parent_root() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_with_invalid_parent_root.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_with_invalid_parent_root failed");
}

#[test]
fn test_block_with_invalid_proposer() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_with_invalid_proposer.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_with_invalid_proposer failed");
}

#[test]
fn test_block_with_invalid_state_root() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_with_invalid_state_root.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_with_invalid_state_root failed");
}
