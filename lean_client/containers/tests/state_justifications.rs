// tests/state_justifications.rs
use containers::{
    state::State,
    types::Bytes32,
    Container
};
use pretty_assertions::assert_eq;
use rstest::{fixture, rstest};
use ssz::PersistentList as List;

#[path = "common.rs"]
mod common;
use common::{
    base_state, create_votes, sample_config, DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT,
};

#[fixture]
fn config() -> Container {
    sample_config()
}

#[fixture]
fn state(config: Container) -> State {
    base_state(config)
}

#[test]
fn test_get_justifications_empty() {
    let state = state(sample_config());

    assert!(state.justifications_roots.is_empty());
    assert!(state.justifications_validators.is_empty());

    let justifications = state.get_justifications();
    assert!(justifications.is_empty());
}

#[test]
fn test_get_justifications_single_root() {
    let mut state = state(sample_config());
    let root1 = Bytes32(ssz::H256::from_slice(&[1u8; 32]));

    let mut votes1 = vec![false; DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT];
    votes1[2] = true;
    votes1[5] = true;

    state.justifications_roots = vec![root1];
    state.justifications_validators = votes1.clone();

    let justifications = state.get_justifications();

    let expected = vec![(root1, votes1)].into_iter().collect();
    assert_eq!(justifications, expected);
}

#[test]
fn test_get_justifications_multiple_roots() {
    let mut state = state(sample_config());
    let root1 = Bytes32(ssz::H256::from_slice(&[1u8; 32]));
    let root2 = Bytes32(ssz::H256::from_slice(&[2u8; 32]));
    let root3 = Bytes32(ssz::H256::from_slice(&[3u8; 32]));

    let limit = DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT;

    let mut votes1 = vec![false; limit];
    votes1[0] = true;

    let mut votes2 = vec![false; limit];
    votes2[1] = true;
    votes2[2] = true;

    let votes3 = vec![true; limit];

    let all_votes = [votes1.clone(), votes2.clone(), votes3.clone()].concat();

    state.justifications_roots = vec![root1, root2, root3];
    state.justifications_validators = all_votes;

    let justifications = state.get_justifications();

    let mut expected = std::collections::BTreeMap::new();
    expected.insert(root1, votes1);
    expected.insert(root2, votes2);
    expected.insert(root3, votes3);

    assert_eq!(justifications.len(), 3);
    assert_eq!(justifications, expected);
}

#[test]
fn test_with_justifications_empty() {
    let config = sample_config();
    let mut initial_state = base_state(config.clone());

    initial_state.justifications_roots = vec![Bytes32(ssz::H256::from_slice(&[1u8;32]))];
    initial_state.justifications_validators = vec![true; DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT];

    let new_state = initial_state.clone().with_justifications(std::collections::BTreeMap::new());

    assert!(new_state.justifications_roots.is_empty());
    assert!(new_state.justifications_validators.is_empty());
    assert!(!initial_state.justifications_roots.is_empty());
    assert!(!initial_state.justifications_validators.is_empty());
}

#[test]
fn test_with_justifications_deterministic_order() {
    let state = state(sample_config());
    let root1 = Bytes32(ssz::H256::from_slice(&[1u8; 32]));
    let root2 = Bytes32(ssz::H256::from_slice(&[2u8; 32]));

    let limit = DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT;
    let votes1 = vec![false; limit];
    let votes2 = vec![true; limit];

    let mut justifications = std::collections::BTreeMap::new();
    justifications.insert(root2, votes2.clone());
    justifications.insert(root1, votes1.clone());

    let new_state = state.with_justifications(justifications);

    let expected_roots = vec![root1, root2];
    let expected_validators = [votes1, votes2].concat();

    assert_eq!(new_state.justifications_roots, expected_roots);
    assert_eq!(new_state.justifications_validators, expected_validators);
}

#[test]
#[should_panic(expected = "vote vector must match validator limit")]
fn test_with_justifications_invalid_length() {
    let state = state(sample_config());
    let root1 = Bytes32(ssz::H256::from_slice(&[1u8; 32]));

    let invalid_votes = vec![true; DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT - 1];
    let mut justifications = std::collections::BTreeMap::new();
    justifications.insert(root1, invalid_votes);

    let _ = state.with_justifications(justifications);
}

#[rstest]
#[case::empty_justifications(std::collections::BTreeMap::new())]
#[case::single_root({
    let mut map = std::collections::BTreeMap::new();
    map.insert(Bytes32(ssz::H256::from_slice(&[1u8; 32])), create_votes(&[0]));
    map
})]
#[case::multiple_roots_sorted({
    let mut map = std::collections::BTreeMap::new();
    map.insert(Bytes32(ssz::H256::from_slice(&[1u8; 32])), create_votes(&[0]));
    map.insert(Bytes32(ssz::H256::from_slice(&[2u8; 32])), create_votes(&[1, 2]));
    map
})]
#[case::multiple_roots_unsorted({
    let mut map = std::collections::BTreeMap::new();
    map.insert(Bytes32(ssz::H256::from_slice(&[2u8; 32])), create_votes(&[1, 2]));
    map.insert(Bytes32(ssz::H256::from_slice(&[1u8; 32])), create_votes(&[0]));
    map
})]
#[case::complex_unsorted({
    let mut map = std::collections::BTreeMap::new();
    map.insert(Bytes32(ssz::H256::from_slice(&[3u8; 32])), vec![true; DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT]);
    map.insert(Bytes32(ssz::H256::from_slice(&[1u8; 32])), create_votes(&[0]));
    map.insert(Bytes32(ssz::H256::from_slice(&[2u8; 32])), create_votes(&[1, 2]));
    map
})]
fn test_justifications_roundtrip(
    #[case] justifications_map: std::collections::BTreeMap<Bytes32, Vec<bool>>,
) {
    let state = state(sample_config());

    let new_state = state.with_justifications(justifications_map.clone());
    let reconstructed_map = new_state.get_justifications();

    let expected_map = justifications_map;
    // BTreeMap is already ordered by key; direct comparison is deterministic
    assert_eq!(reconstructed_map, expected_map);
}
