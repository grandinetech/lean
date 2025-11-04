#[cfg(test)]
use super::runner::TestRunner;

#[test]
fn run_invalid_proposer_test() {
    let test_path = "../tests/test_vectors/test_invalid/test_invalid_proposer.json";
    if std::path::Path::new(test_path).exists() {
        TestRunner::run_invalid_test(test_path)
            .expect("Invalid proposer test should pass (by catching the expected error)");
    } else {
        println!("Test vector file not found, skipping: {}", test_path);
    }
}
