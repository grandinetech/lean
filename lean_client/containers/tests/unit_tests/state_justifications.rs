// tests/state_justifications.rs
use containers::{
    state::State,
    types::Bytes32,
    ContainerConfig
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
fn config() -> ContainerConfig {
    sample_config()
}

#[fixture]
fn state(config: ContainerConfig) -> State {
    base_state(config)
}

#[test]
fn test_get_justifications_empty() {
    let state = state(sample_config());

    assert!(state.justifications_roots.get(0).is_err());
    assert!(state.justifications_validators.get(0).is_none());

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

    let mut roots_list = List::default();
    roots_list.push(root1).unwrap();
    state.justifications_roots = roots_list;
    
    // Convert Vec<bool> to BitList
    let mut bitlist = ssz::BitList::with_length(DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT);
    for (i, &val) in votes1.iter().enumerate() {
        bitlist.set(i, val);
    }
    state.justifications_validators = bitlist;

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

    let mut roots_list = List::default();
    roots_list.push(root1).unwrap();
    roots_list.push(root2).unwrap();
    roots_list.push(root3).unwrap();
    state.justifications_roots = roots_list;
    
    // Convert Vec<bool> to BitList
    let mut bitlist = ssz::BitList::with_length(all_votes.len());
    for (i, &val) in all_votes.iter().enumerate() {
        bitlist.set(i, val);
    }
    state.justifications_validators = bitlist;

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

    let mut roots_list = List::default();
    roots_list.push(Bytes32(ssz::H256::from_slice(&[1u8;32]))).unwrap();
    initial_state.justifications_roots = roots_list;
    
    let mut bitlist = ssz::BitList::with_length(DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT);
    for i in 0..DEVNET_CONFIG_VALIDATOR_REGISTRY_LIMIT {
        bitlist.set(i, true);
    }
    initial_state.justifications_validators = bitlist;

    let new_state = initial_state.clone().with_justifications(std::collections::BTreeMap::new());

    assert!(new_state.justifications_roots.get(0).is_err());
    assert!(new_state.justifications_validators.get(0).is_none());
    assert!(initial_state.justifications_roots.get(0).is_ok());
    assert!(initial_state.justifications_validators.get(0).is_some());
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

    // Expected roots in sorted order (root1 < root2)
    assert_eq!(new_state.justifications_roots.get(0).ok(), Some(&root1));
    assert_eq!(new_state.justifications_roots.get(1).ok(), Some(&root2));
    
    // Verify the bitlist contains the concatenated votes
    let expected_validators = [votes1, votes2].concat();
    for (i, &expected_val) in expected_validators.iter().enumerate() {
        let actual_val = new_state.justifications_validators.get(i).map(|b| *b).unwrap_or(false);
        assert_eq!(actual_val, expected_val);
    }
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