use super::common::create_test_store;
use containers::{
    attestation::{Attestation, AttestationData, Signature, SignedAttestation},
    checkpoint::Checkpoint,
    Bytes32, Slot, Uint64, ValidatorIndex,
};
use fork_choice::handlers::on_attestation;
use fork_choice::store::{accept_new_attestations, INTERVALS_PER_SLOT};

#[cfg(feature = "devnet1")]
fn create_signed_attestation(
    validator_id: u64,
    slot: Slot,
    head_root: Bytes32,
) -> SignedAttestation {
    SignedAttestation {
        message: Attestation {
            validator_id: Uint64(validator_id),
            data: AttestationData {
                slot,
                head: Checkpoint {
                    root: head_root,
                    slot,
                },
                target: Checkpoint {
                    root: head_root,
                    slot,
                },
                source: Checkpoint {
                    root: Bytes32::default(),
                    slot: Slot(0),
                },
            },
        },
        signature: Signature::default(),
    }
}

#[test]
#[cfg(feature = "devnet1")]
fn test_accept_new_attestations() {
    let mut store = create_test_store();

    // Setup initial known attestations
    let val1 = ValidatorIndex(1);
    let val2 = ValidatorIndex(2);
    let val3 = ValidatorIndex(3);

    store
        .latest_known_attestations
        .insert(val1, create_signed_attestation(1, Slot(0), store.head));

    // Val1 updates their attestation to Slot 1
    store
        .latest_new_attestations
        .insert(val1, create_signed_attestation(1, Slot(1), store.head));
    // Val2 casts a new attestation for Slot 1
    store
        .latest_new_attestations
        .insert(val2, create_signed_attestation(2, Slot(1), store.head));
    // Val3 casts a new attestation for Slot 2
    store
        .latest_new_attestations
        .insert(val3, create_signed_attestation(3, Slot(2), store.head));

    accept_new_attestations(&mut store);

    assert_eq!(store.latest_new_attestations.len(), 0);
    assert_eq!(store.latest_known_attestations.len(), 3);

    assert_eq!(
        store.latest_known_attestations[&val1].message.data.slot,
        Slot(1)
    );
    assert_eq!(
        store.latest_known_attestations[&val2].message.data.slot,
        Slot(1)
    );
    assert_eq!(
        store.latest_known_attestations[&val3].message.data.slot,
        Slot(2)
    );
}

#[test]
#[cfg(feature = "devnet1")]
fn test_accept_new_attestations_multiple() {
    let mut store = create_test_store();

    for i in 0..5 {
        store.latest_new_attestations.insert(
            ValidatorIndex(i),
            create_signed_attestation(i, Slot(i), store.head),
        );
    }

    assert_eq!(store.latest_new_attestations.len(), 5);
    assert_eq!(store.latest_known_attestations.len(), 0);

    accept_new_attestations(&mut store);

    assert_eq!(store.latest_new_attestations.len(), 0);
    assert_eq!(store.latest_known_attestations.len(), 5);
}

#[test]
fn test_accept_new_attestations_empty() {
    let mut store = create_test_store();
    let initial_known = store.latest_known_attestations.len();

    accept_new_attestations(&mut store);

    assert_eq!(store.latest_new_attestations.len(), 0);
    assert_eq!(store.latest_known_attestations.len(), initial_known);
}

#[test]
#[cfg(feature = "devnet1")]
fn test_on_attestation_lifecycle() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);
    let slot_0 = Slot(0);
    let slot_1 = Slot(1);

    // 1. Attestation from network (gossip)
    let signed_attestation_gossip = create_signed_attestation(1, slot_0, store.head);

    on_attestation(&mut store, signed_attestation_gossip.clone(), false)
        .expect("Gossip attestation valid");

    // Should be in new_attestations, not known_attestations
    assert!(store.latest_new_attestations.contains_key(&validator_idx));
    assert!(!store.latest_known_attestations.contains_key(&validator_idx));
    assert_eq!(
        store.latest_new_attestations[&validator_idx]
            .message
            .data
            .slot,
        slot_0
    );

    // 2. Same attestation included in a block
    on_attestation(&mut store, signed_attestation_gossip, true).expect("Block attestation valid");

    assert!(store.latest_known_attestations.contains_key(&validator_idx));
    assert_eq!(
        store.latest_known_attestations[&validator_idx]
            .message
            .data
            .slot,
        slot_0
    );

    // 3. Newer attestation from network
    store.time = 1 * INTERVALS_PER_SLOT; // Advance time
    let signed_attestation_next = create_signed_attestation(1, slot_1, store.head);

    on_attestation(&mut store, signed_attestation_next, false)
        .expect("Next gossip attestation valid");

    // Should update new_attestations
    assert_eq!(
        store.latest_new_attestations[&validator_idx]
            .message
            .data
            .slot,
        slot_1
    );
    // Known attestations should still be at slot 0 until accepted
    assert_eq!(
        store.latest_known_attestations[&validator_idx]
            .message
            .data
            .slot,
        slot_0
    );
}

#[test]
#[cfg(feature = "devnet1")]
fn test_on_attestation_future_slot() {
    let mut store = create_test_store();
    let future_slot = Slot(100); // Far in the future

    let signed_attestation = create_signed_attestation(1, future_slot, store.head);

    let result = on_attestation(&mut store, signed_attestation, false);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "devnet1")]
fn test_on_attestation_update_vote() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);

    // First attestation at slot 0
    let signed_attestation1 = create_signed_attestation(1, Slot(0), store.head);

    on_attestation(&mut store, signed_attestation1, false).expect("First attestation valid");
    assert_eq!(
        store.latest_new_attestations[&validator_idx]
            .message
            .data
            .slot,
        Slot(0)
    );

    // Advance time to allow slot 1
    store.time = 1 * INTERVALS_PER_SLOT;

    // Second attestation at slot 1
    let signed_attestation2 = create_signed_attestation(1, Slot(1), store.head);

    on_attestation(&mut store, signed_attestation2, false).expect("Second attestation valid");
    assert_eq!(
        store.latest_new_attestations[&validator_idx]
            .message
            .data
            .slot,
        Slot(1)
    );
}

#[test]
#[cfg(feature = "devnet1")]
fn test_on_attestation_ignore_old_vote() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);

    // Advance time
    store.time = 2 * INTERVALS_PER_SLOT;

    // Newer attestation first
    let signed_attestation_new = create_signed_attestation(1, Slot(2), store.head);

    on_attestation(&mut store, signed_attestation_new, false).expect("New attestation valid");
    assert_eq!(
        store.latest_new_attestations[&validator_idx]
            .message
            .data
            .slot,
        Slot(2)
    );

    // Older attestation second
    let signed_attestation_old = create_signed_attestation(1, Slot(1), store.head);

    on_attestation(&mut store, signed_attestation_old, false)
        .expect("Old attestation processed but ignored");
    // Should still be slot 2
    assert_eq!(
        store.latest_new_attestations[&validator_idx]
            .message
            .data
            .slot,
        Slot(2)
    );
}

#[test]
#[cfg(feature = "devnet1")]
fn test_on_attestation_from_block_supersedes_new() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);

    // First, add attestation via gossip
    let signed_attestation1 = create_signed_attestation(1, Slot(0), store.head);
    on_attestation(&mut store, signed_attestation1, false).expect("Gossip attestation valid");

    assert!(store.latest_new_attestations.contains_key(&validator_idx));
    assert!(!store.latest_known_attestations.contains_key(&validator_idx));

    // Then, add same attestation via block (on-chain)
    let signed_attestation2 = create_signed_attestation(1, Slot(0), store.head);
    on_attestation(&mut store, signed_attestation2, true).expect("Block attestation valid");

    // Should move from new to known
    assert!(!store.latest_new_attestations.contains_key(&validator_idx));
    assert!(store.latest_known_attestations.contains_key(&validator_idx));
}

#[test]
#[cfg(feature = "devnet1")]
fn test_on_attestation_newer_from_block_removes_older_new() {
    let mut store = create_test_store();
    let validator_idx = ValidatorIndex(1);

    // Add older attestation via gossip
    let signed_attestation_gossip = create_signed_attestation(1, Slot(0), store.head);
    on_attestation(&mut store, signed_attestation_gossip, false).expect("Gossip attestation valid");

    assert_eq!(
        store.latest_new_attestations[&validator_idx]
            .message
            .data
            .slot,
        Slot(0)
    );

    // Add newer attestation via block (on-chain)
    store.time = 1 * INTERVALS_PER_SLOT;
    let signed_attestation_block = create_signed_attestation(1, Slot(1), store.head);
    on_attestation(&mut store, signed_attestation_block, true).expect("Block attestation valid");

    // New attestation should be removed (superseded by newer on-chain one)
    assert!(!store.latest_new_attestations.contains_key(&validator_idx));
    assert_eq!(
        store.latest_known_attestations[&validator_idx]
            .message
            .data
            .slot,
        Slot(1)
    );
}
