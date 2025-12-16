//! Integration tests for signature verification test vectors
use super::runner::TestRunner;

#[test]
fn test_proposer_signature() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_valid_signatures/test_proposer_signature.json";
    TestRunner::run_signature_verification_test(test_path)
        .expect("test_proposer_signature failed");
}

#[test]
fn test_proposer_and_attester_signatures() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_valid_signatures/test_proposer_and_attester_signatures.json";
    TestRunner::run_signature_verification_test(test_path)
        .expect("test_proposer_and_attester_signatures failed");
}

#[test]
fn test_invalid_signature() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_invalid_signatures/test_invalid_signature.json";
    TestRunner::run_signature_verification_test(test_path)
        .expect("test_invalid_signature failed");
}

#[test]
fn test_mixed_valid_invalid_signatures() {
    let test_path = "../tests/test_vectors/test_verify_signatures/test_invalid_signatures/test_mixed_valid_invalid_signatures.json";
    TestRunner::run_signature_verification_test(test_path)
        .expect("test_mixed_valid_invalid_signatures failed");
}