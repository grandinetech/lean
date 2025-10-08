#[macro_export]
macro_rules! test_operation_impl {
    ($operation_name:ident, $operation_object:ty, $input_name:literal, $compute_result:expr) => {{
        use std::fs;
        use std::path::PathBuf;
        use containers::State;

        // Path for your operation test vectors
        let base_path = format!("tests/operations/{}/", stringify!($operation_name));
        for entry in fs::read_dir(&base_path).expect("Missing test directory") {
            let entry = entry.expect("Invalid test case entry");
            let case_dir = entry.path();
            if !case_dir.is_dir() {
                continue;
            }
            let case_name = case_dir.file_name().unwrap().to_str().unwrap();
            println!("Running Beam operation case: {}", case_name);

            // Load pre-state
            let pre_state_path = case_dir.join("pre.ssz");
            let mut state: State = State::from_ssz_bytes(
                &fs::read(&pre_state_path).expect("Missing pre.ssz"),
            )
            .expect("Invalid pre-state file");

            // Load operation input (e.g. Block, Vote, etc.)
            let input_path = case_dir.join(format!("{}.ssz", $input_name));
            let input: $operation_object = <$operation_object>::from_ssz_bytes(
                &fs::read(&input_path).expect("Missing input ssz"),
            )
            .expect("Invalid operation input file");

            // Load expected post-state (optional)
            let expected_post_path = case_dir.join("post.ssz");
            let expected_post = fs::read(&expected_post_path)
                .ok()
                .and_then(|bytes| State::from_ssz_bytes(&bytes).ok());

            // Execute operation logic (user-defined)
            let result = $compute_result(&mut state, input, case_dir.clone());

            // Compare actual vs expected
            match (result, expected_post) {
                (Ok(_), Some(expected)) => {
                    assert_eq!(
                        state, expected,
                        "Beam test case '{}' post-state mismatch",
                        case_name
                    );
                }
                (Ok(_), None) => panic!("Case '{}' should have failed but succeeded", case_name),
                (Err(_), Some(_)) => panic!("Case '{}' should have succeeded but failed", case_name),
                (Err(_), None) => (), // expected failure
            }
        }
    }};
}

#[macro_export]
macro_rules! test_operation {
    ($operation_name:ident, $operation_object:ty, $input_name:literal, $processing_fn:path) => {
        paste::paste! {
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod [<tests_ $operation_name>] {
                use super::*;
                use std::path::PathBuf;
                use containers::State;

                #[test]
                fn test_operation() {
                    $crate::test_operation_impl!(
                        $operation_name,
                        $operation_object,
                        $input_name,
                        |state: &mut State, input: $operation_object, _case_dir: PathBuf| {
                            // Calls your Beam Chain state method
                            state.$processing_fn(&input)
                        }
                    );
                }
            }
        }
    };
}
