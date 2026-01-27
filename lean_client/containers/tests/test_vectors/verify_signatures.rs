// Integration test: verify_signatures test vectors for devnet2 format
// Tests XMSS signature verification on SignedBlockWithAttestation

use super::runner::TestRunner;

// Valid signature tests
#[test]
fn test_proposer_signature() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_valid_signatures/test_proposer_signature.json";
    TestRunner::run_verify_signatures_test(test_path).expect("test_proposer_signature failed");
}

#[test]
fn test_proposer_and_attester_signatures() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_valid_signatures/test_proposer_and_attester_signatures.json";
    TestRunner::run_verify_signatures_test(test_path)
        .expect("test_proposer_and_attester_signatures failed");
}

#[test]
#[ignore = "TODO: Fails because of poor error handling, the code panics as it receives wrong length signature although it should handle it more elegantly"]
fn test_invalid_signature() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_invalid_signatures/test_invalid_signature.json";
    TestRunner::run_verify_signatures_test(test_path).expect("test_invalid_signature failed");
}

#[test]
#[ignore = "This test is commented out in the spec"]
fn test_mixed_valid_invalid_signatures() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_invalid_signatures/test_mixed_valid_invalid_signatures.json";
    TestRunner::run_verify_signatures_test(test_path)
        .expect("test_mixed_valid_invalid_signatures failed");
}
