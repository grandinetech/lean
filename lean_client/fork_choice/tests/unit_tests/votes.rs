use super::common::create_test_store;
use fork_choice::handlers::on_attestation;
use fork_choice::store::{accept_new_votes, INTERVALS_PER_SLOT};
use containers::{
    attestation::{Attestation, AttestationData},
    checkpoint::Checkpoint,
    Bytes32, Slot, Uint64, ValidatorIndex,
};

#[test]
fn test_accept_new_votes() {
    let mut store = create_test_store();

    // Setup initial known votes
    let val1 = ValidatorIndex(1);
    let val2 = ValidatorIndex(2);
    let val3 = ValidatorIndex(3);

    store.latest_known_votes.insert(val1, Checkpoint { root: store.head, slot: Slot(0) });

    // Val1 updates their vote to Slot 1
    store.latest_new_votes.insert(val1, Checkpoint { root: store.head, slot: Slot(1) });
    // Val2 casts a new vote for Slot 1
    store.latest_new_votes.insert(val2, Checkpoint { root: store.head, slot: Slot(1) });
    // Val3 casts a new vote for Slot 2
    store.latest_new_votes.insert(val3, Checkpoint { root: store.head, slot: Slot(2) });

    accept_new_votes(&mut store);

    assert_eq!(store.latest_new_votes.len(), 0);
    assert_eq!(store.latest_known_votes.len(), 3);

    assert_eq!(store.latest_known_votes[&val1].slot, Slot(1));
    assert_eq!(store.latest_known_votes[&val2].slot, Slot(1));
    assert_eq!(store.latest_known_votes[&val3].slot, Slot(2));
}

#[test]
fn test_accept_new_votes_multiple() {
    let mut store = create_test_store();
    
    for i in 0..5 {
        let checkpoint = Checkpoint {
            root: store.head, // Validators voting for the head (genesis)
            slot: Slot(i),
        };
        store.latest_new_votes.insert(ValidatorIndex(i), checkpoint);
    }
    
    assert_eq!(store.latest_new_votes.len(), 5);
    assert_eq!(store.latest_known_votes.len(), 0);
    
    accept_new_votes(&mut store);
    
    assert_eq!(store.latest_new_votes.len(), 0);
    assert_eq!(store.latest_known_votes.len(), 5);
}

#[test]
fn test_accept_new_votes_empty() {
    let mut store = create_test_store();
    let initial_known = store.latest_known_votes.len();
    
    accept_new_votes(&mut store);
    
    assert_eq!(store.latest_new_votes.len(), 0);
    assert_eq!(store.latest_known_votes.len(), initial_known);
}

#[test]
fn test_on_attestation_lifecycle() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);
    let slot_0 = Slot(0);
    let slot_1 = Slot(1);

    // 1. Attestation from network (gossip)
    let attestation_gossip = Attestation {
        validator_id: Uint64(validator_idx.0),
        data: AttestationData {
            slot: slot_0,
            head: Checkpoint::default(),
            target: Checkpoint { root: Bytes32::default(), slot: slot_0 },
            source: Checkpoint::default(),
        },
    };

    on_attestation(&mut store, attestation_gossip.clone(), false).expect("Gossip attestation valid");
    
    // Should be in new_votes, not known_votes
    assert!(store.latest_new_votes.contains_key(&validator_idx));
    assert!(!store.latest_known_votes.contains_key(&validator_idx));
    assert_eq!(store.latest_new_votes[&validator_idx].slot, slot_0);

    // 2. Same attestation included in a block
    on_attestation(&mut store, attestation_gossip, true).expect("Block attestation valid");
    
    assert!(store.latest_known_votes.contains_key(&validator_idx));
    assert_eq!(store.latest_known_votes[&validator_idx].slot, slot_0);

    // 3. Newer attestation from network
    store.time = 1 * INTERVALS_PER_SLOT; // Advance time
    let attestation_next = Attestation {
        validator_id: Uint64(validator_idx.0),
        data: AttestationData {
            slot: slot_1,
            head: Checkpoint::default(),
            target: Checkpoint { root: Bytes32::default(), slot: slot_1 },
            source: Checkpoint::default(),
        },
    };

    on_attestation(&mut store, attestation_next, false).expect("Next gossip attestation valid");

    // Should update new_votes
    assert_eq!(store.latest_new_votes[&validator_idx].slot, slot_1);
    // Known votes should still be at slot 0 until accepted
    assert_eq!(store.latest_known_votes[&validator_idx].slot, slot_0);
}

#[test]
fn test_on_attestation_future_slot() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);
    let future_slot = Slot(100); //Latter in the future
    
    let attestation = Attestation {
        validator_id: Uint64(validator_idx.0),
        data: AttestationData {
            slot: future_slot,
            head: Checkpoint::default(),
            target: Checkpoint {
                root: Bytes32::default(),
                slot: future_slot,
            },
            source: Checkpoint::default(),
        },
    };

    let result = on_attestation(&mut store, attestation, false);
    assert!(result.is_err());
}

#[test]
fn test_on_attestation_update_vote() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);
    
    // First vote at slot 0
    let attestation1 = Attestation {
        validator_id: Uint64(validator_idx.0),
        data: AttestationData {
            slot: Slot(0),
            head: Checkpoint::default(),
            target: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(0),
            },
            source: Checkpoint::default(),
        },
    };
    
    on_attestation(&mut store, attestation1, false).expect("First vote valid");
    assert_eq!(store.latest_new_votes[&validator_idx].slot, Slot(0));
    
    // Advance time to allow slot 1
    store.time = 1 * INTERVALS_PER_SLOT;
    
    // Second vote at slot 1
    let attestation2 = Attestation {
        validator_id: Uint64(validator_idx.0),
        data: AttestationData {
            slot: Slot(1),
            head: Checkpoint::default(),
            target: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(1),
            },
            source: Checkpoint::default(),
        },
    };
    
    on_attestation(&mut store, attestation2, false).expect("Second vote valid");
    assert_eq!(store.latest_new_votes[&validator_idx].slot, Slot(1));
}

#[test]
fn test_on_attestation_ignore_old_vote() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);
    
    // Advance time
    store.time = 2 * INTERVALS_PER_SLOT;
    
    // Newer vote first
    let attestation_new = Attestation {
        validator_id: Uint64(validator_idx.0),
        data: AttestationData {
            slot: Slot(2),
            head: Checkpoint::default(),
            target: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(2),
            },
            source: Checkpoint::default(),
        },
    };
    
    on_attestation(&mut store, attestation_new, false).expect("New vote valid");
    assert_eq!(store.latest_new_votes[&validator_idx].slot, Slot(2));
    
    // Older vote second
    let attestation_old = Attestation {
        validator_id: Uint64(validator_idx.0),
        data: AttestationData {
            slot: Slot(1),
            head: Checkpoint::default(),
            target: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(1),
            },
            source: Checkpoint::default(),
        },
    };
    
    on_attestation(&mut store, attestation_old, false).expect("Old vote processed but ignored");
    // Should still be slot 2
    assert_eq!(store.latest_new_votes[&validator_idx].slot, Slot(2));
}
