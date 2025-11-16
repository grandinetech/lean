// Integration test: Genesis state test vectors
use super::runner::TestRunner;

#[test]
fn test_genesis_default_configuration() {
    let test_path = "../tests/test_vectors/test_genesis/test_genesis_default_configuration.json";
    TestRunner::run_genesis_test(test_path)
        .expect("test_genesis_default_configuration failed");
}

#[test]
fn test_genesis_custom_time() {
    let test_path = "../tests/test_vectors/test_genesis/test_genesis_custom_time.json";
    TestRunner::run_genesis_test(test_path)
        .expect("test_genesis_custom_time failed");
}

#[test]
fn test_genesis_custom_validator_set() {
    let test_path = "../tests/test_vectors/test_genesis/test_genesis_custom_validator_set.json";
    TestRunner::run_genesis_test(test_path)
        .expect("test_genesis_custom_validator_set failed");
}
