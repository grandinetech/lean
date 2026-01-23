//! Integration test: Genesis state test vectors
use std::path::Path;

use test_generator::test_resources;

use super::runner::TestRunner;

#[test_resources("test_vectors/state_transition/*/state_transition/test_genesis/*.json")]
fn genesis(spec_file: &str) {
    let test_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(spec_file);

    TestRunner::run_genesis_test(test_path).unwrap();
}
