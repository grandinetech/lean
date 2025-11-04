#[cfg(test)]
use super::runner::TestRunner;

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
