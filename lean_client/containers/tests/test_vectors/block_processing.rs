// Integration test: All block processing test vectors
use super::runner::TestRunner;

#[test]
#[cfg(feature = "devnet1")]
fn test_process_first_block_after_genesis() {
    let test_path = "../tests/test_vectors/test_blocks/test_process_first_block_after_genesis.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_process_first_block_after_genesis failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_blocks_with_gaps() {
    let test_path = "../tests/test_vectors/test_blocks/test_blocks_with_gaps.json";
    TestRunner::run_block_processing_test(test_path).expect("test_blocks_with_gaps failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_linear_chain_multiple_blocks() {
    let test_path = "../tests/test_vectors/test_blocks/test_linear_chain_multiple_blocks.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_linear_chain_multiple_blocks failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_block_extends_deep_chain() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_extends_deep_chain.json";
    TestRunner::run_block_processing_test(test_path).expect("test_block_extends_deep_chain failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_empty_blocks() {
    let test_path = "../tests/test_vectors/test_blocks/test_empty_blocks.json";
    TestRunner::run_block_processing_test(test_path).expect("test_empty_blocks failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_empty_blocks_with_missed_slots() {
    let test_path = "../tests/test_vectors/test_blocks/test_empty_blocks_with_missed_slots.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_empty_blocks_with_missed_slots failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_block_at_large_slot_number() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_at_large_slot_number.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_at_large_slot_number failed");
}

// Invalid block tests (expecting failures)

#[test]
#[cfg(feature = "devnet1")]
fn test_block_with_invalid_parent_root() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_with_invalid_parent_root.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_with_invalid_parent_root failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_block_with_invalid_proposer() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_with_invalid_proposer.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_with_invalid_proposer failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_block_with_invalid_state_root() {
    let test_path = "../tests/test_vectors/test_blocks/test_block_with_invalid_state_root.json";
    TestRunner::run_block_processing_test(test_path)
        .expect("test_block_with_invalid_state_root failed");
}
