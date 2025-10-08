#[macro_export]
macro_rules! test_shuffling {
    () => {
        #[cfg(test)]
        mod tests_shuffling {
            use std::str::FromStr;

            use rstest::rstest;
            use serde_yaml::Value;

            use super::*;

            #[derive(Debug, serde::Deserialize)]
            struct ShufflingTest {
                seed: String,
                count: usize,
                mapping: Vec<usize>,
            }

            #[rstest]
            fn test_shuffling() {
                let base_path = "mainnet/tests/mainnet/phase0/shuffling/core/shuffle";

                for entry in std::fs::read_dir(base_path).unwrap() {
                    let entry = entry.unwrap();
                    let case_dir = entry.path();

                    if !case_dir.is_dir() {
                        continue;
                    }

                    let case_name = case_dir.file_name().unwrap().to_str().unwrap();
                    println!("Testing case: {}", case_name);

                    // Read and parse mapping.yaml
                    let test_data: ShufflingTest = {
                        let mapping_path = case_dir.join("mapping.yaml");
                        let content = std::fs::read_to_string(mapping_path)
                            .expect("Failed to read mapping.yaml");
                        serde_yaml::from_str(&content).expect("Failed to parse mapping.yaml")
                    };

                    // Convert hex seed to bytes
                    let seed = alloy_primitives::B256::from_str(&test_data.seed)
                        .expect("Failed to parse seed");

                    // Test compute_shuffled_index for each index
                    for i in 0..test_data.count {
                        let shuffled = compute_shuffled_index(i, test_data.count, seed)
                            .expect("shuffling should not fail");
                        assert_eq!(
                            shuffled, test_data.mapping[i],
                            "Mismatch at index {i} in case {case_name}"
                        );
                    }
                }
            }
        }
    };
}
