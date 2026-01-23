// AI Generated tests
use containers::Slot;
use validator::{ValidatorConfig, ValidatorService};

#[test]
fn test_proposer_selection() {
    let config = ValidatorConfig {
        node_id: "test_0".to_string(),
        validator_indices: vec![2],
    };
    let service = ValidatorService::new(config, 4);

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
    };

    assert!(config.is_assigned(2));
    assert!(config.is_assigned(5));
    assert!(config.is_assigned(8));
    assert!(!config.is_assigned(0));
    assert!(!config.is_assigned(1));
    assert!(!config.is_assigned(3));
}
