// AI Generated tests
use std::sync::Arc;

use containers::Slot;
use dedicated_executor::DedicatedExecutor;
use validator::{ValidatorConfig, ValidatorService};

#[test]
fn test_proposer_selection() {
    let config = ValidatorConfig {
        node_id: "test_0".to_string(),
        validator_indices: vec![2],
        key_files: Default::default(),
    };
    let exec = Arc::new(DedicatedExecutor::new_testing());
    let service = ValidatorService::new(config, 4, exec.clone(), exec.clone(), exec);

    // Validator 2 should propose at slots 2, 6, 10, ...
    assert!(service.get_proposer_for_slot(Slot(2)).is_some());
    assert!(service.get_proposer_for_slot(Slot(6)).is_some());
    assert!(service.get_proposer_for_slot(Slot(10)).is_some());

    // Validator 2 should NOT propose at slots 0, 1, 3, 4, 5, ...
    assert!(service.get_proposer_for_slot(Slot(0)).is_none());
    assert!(service.get_proposer_for_slot(Slot(1)).is_none());
    assert!(service.get_proposer_for_slot(Slot(3)).is_none());
    assert!(service.get_proposer_for_slot(Slot(4)).is_none());
    assert!(service.get_proposer_for_slot(Slot(5)).is_none());
}

#[test]
fn test_is_assigned() {
    let config = ValidatorConfig {
        node_id: "test_0".to_string(),
        validator_indices: vec![2, 5, 8],
        key_files: Default::default(),
    };

    assert!(config.is_assigned(2));
    assert!(config.is_assigned(5));
    assert!(config.is_assigned(8));
    assert!(!config.is_assigned(0));
    assert!(!config.is_assigned(1));
    assert!(!config.is_assigned(3));
}

#[test]
fn test_load_from_file_rejects_single_key_entry() {
    let path = std::env::temp_dir().join(format!(
        "annotated_validators_single_key_{}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        "test_0:\n  - index: 0\n    pubkey_hex: \"0x00\"\n    privkey_file: validator_0_sk.ssz\n",
    )
    .unwrap();

    let result = ValidatorConfig::load_from_file(&path, "test_0");
    std::fs::remove_file(&path).unwrap();
    let err = result.expect_err("single-key entry").to_string();
    assert!(
        err.contains("names neither an attester nor a proposer key"),
        "error {err:?}"
    );
}
