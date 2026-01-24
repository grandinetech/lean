//! Integration test: verify_signatures test vectors
//! Tests XMSS signature verification on SignedBlockWithAttestation
//!
//! NOTE: Without the `xmss-verify` feature, signature verification only checks
//! structure (attestation count matches signature count, validator indices valid).
//! Full cryptographic verification requires `--features xmss-verify`.

use std::path::Path;

use test_generator::test_resources;

use super::runner::TestRunner;

#[test_resources("test_vectors/verify_signatures/*/verify_signatures/*/*.json")]
fn verify_signatures(spec_file: &str) {
    let test_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(spec_file);

    TestRunner::run_verify_signatures_test(test_path).unwrap();
}
