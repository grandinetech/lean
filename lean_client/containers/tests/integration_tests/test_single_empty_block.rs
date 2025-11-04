#[cfg(test)]
use super::runner::TestRunner;

#[test]
fn run_single_empty_block_test() {
    let test_path = "../tests/test_vectors/test_blocks/test_single_empty_block.json";
    if std::path::Path::new(test_path).exists() {
        TestRunner::run_single_empty_block_tests(test_path)
            .expect("Single empty block test should pass");
    } else {
        println!("Test vector file not found, skipping: {}", test_path);
    }
}
