//! Integration test: All block processing test vectors for devnet2 format
use std::path::Path;

use test_generator::test_resources;

use super::runner::TestRunner;

#[test_resources("test_vectors/state_transition/*/state_transition/test_block_processing/*.json")]
fn block_processing(spec_file: &str) {
    let test_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(spec_file);

    TestRunner::run_block_processing_test(test_path).unwrap();
}
