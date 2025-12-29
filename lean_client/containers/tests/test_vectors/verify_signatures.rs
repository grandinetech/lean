// Integration test: verify_signatures test vectors
// Tests XMSS signature verification on SignedBlockWithAttestation
//
// NOTE: Without the `xmss-verify` feature, signature verification only checks
// structure (attestation count matches signature count, validator indices valid).
// Full cryptographic verification requires `--features xmss-verify`.
//
// IMPORTANT: There is currently a configuration mismatch between leanSpec Python
// (HASH_LEN_FE=8, 52-byte pubkeys) and leansig Rust (HASH_LEN_FE=7, 48-byte pubkeys).
// Until this is resolved, the xmss-verify tests will fail with "Invalid public key length".
use super::runner::TestRunner;

// Valid signature tests
// These tests verify that properly signed blocks pass verification.
// Without xmss-verify feature, they pass because structural validation succeeds.

#[test]
#[cfg(feature = "devnet1")]
fn test_proposer_signature() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_valid_signatures/test_proposer_signature.json";
    TestRunner::run_verify_signatures_test(test_path).expect("test_proposer_signature failed");
}

#[test]
#[cfg(feature = "devnet1")]
fn test_proposer_and_attester_signatures() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_valid_signatures/test_proposer_and_attester_signatures.json";
    TestRunner::run_verify_signatures_test(test_path)
        .expect("test_proposer_and_attester_signatures failed");
}

// Invalid signature tests (expecting verification failure)
// NOTE: These tests are ignored by default because without the `xmss-verify` feature,
// signature verification doesn't actually check cryptographic validity.
// Run with `cargo test --features xmss-verify` to enable full signature verification.

#[test]
#[cfg(feature = "devnet1")]
#[ignore = "Requires xmss-verify feature for actual signature validation. Run with: cargo test --features xmss-verify"]
fn test_invalid_signature() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_invalid_signatures/test_invalid_signature.json";
    TestRunner::run_verify_signatures_test(test_path).expect("test_invalid_signature failed");
}

#[test]
#[cfg(feature = "devnet1")]
#[ignore = "Requires xmss-verify feature for actual signature validation. Run with: cargo test --features xmss-verify"]
fn test_mixed_valid_invalid_signatures() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_invalid_signatures/test_mixed_valid_invalid_signatures.json";
    TestRunner::run_verify_signatures_test(test_path)
        .expect("test_mixed_valid_invalid_signatures failed");
}
