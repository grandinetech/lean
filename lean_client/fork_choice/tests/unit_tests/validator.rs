//! Validator block production and attestation tests.
//!
//! Ported from spec/tests/lean_spec/subspecs/forkchoice/test_validator.py

use super::common::create_test_store;
use containers::{
    attestation::{Attestation, AttestationData},
    block::{Block, BlockBody},
    checkpoint::Checkpoint,
    config::Config,
    state::State,
    validator::Validator,
    Bytes32, Signature, SignatureKey, Slot, Uint64, ValidatorIndex,
};
use fork_choice::store::{
    get_vote_target, produce_block_with_signatures, update_head, Store,
};
use ssz::SszHash;

/// Build AttestationData matching the current store state for a given slot.
///
/// Equivalent of Python `store.produce_attestation_data(slot)`.
fn produce_attestation_data(store: &Store, slot: Slot) -> AttestationData {
    let head_block = &store.blocks[&store.head];
    let head_checkpoint = Checkpoint {
        root: store.head,
        slot: head_block.slot,
    };
    let vote_target = get_vote_target(store);
    AttestationData {
        slot,
        head: head_checkpoint,
        target: vote_target,
        source: store.latest_justified.clone(),
    }
}

/// Create a mock XMSS signature (all zeros).
fn make_mock_signature() -> Signature {
    Default::default()
}

// ---------------------------------------------------------------------------
// TestBlockProduction
// ---------------------------------------------------------------------------

#[test]
fn test_produce_block_basic() {
    let mut store = create_test_store();
    let initial_head = store.head;

    let slot = Slot(1);
    let validator_idx = ValidatorIndex(1);

    let (block_root, block, _signatures) =
        produce_block_with_signatures(&mut store, slot, validator_idx)
            .expect("block production should succeed");

    // Verify block structure
    assert_eq!(block.slot, slot);
    assert_eq!(block.proposer_index, validator_idx);
    assert_eq!(block.parent_root, initial_head);
    assert_ne!(block.state_root, Bytes32::default());

    // Verify block was added to store
    assert!(store.blocks.contains_key(&block_root));
    assert!(store.states.contains_key(&block_root));
}

#[test]
fn test_produce_block_unauthorized_proposer() {
    let mut store = create_test_store();
    let slot = Slot(1);
    let wrong_validator = ValidatorIndex(2); // Not proposer for slot 1

    let result = produce_block_with_signatures(&mut store, slot, wrong_validator);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("is not the proposer for slot"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_produce_block_with_attestations() {
    let mut store = create_test_store();
    let head_block = store.blocks[&store.head].clone();
    let head_checkpoint = Checkpoint {
        root: store.head,
        slot: head_block.slot,
    };
    let target = get_vote_target(&store);

    // Add attestations for validators 5 and 6
    for vid in [5u64, 6] {
        let data = AttestationData {
            slot: head_block.slot,
            head: head_checkpoint.clone(),
            target: target.clone(),
            source: store.latest_justified.clone(),
        };
        store
            .latest_known_attestations
            .insert(ValidatorIndex(vid), data.clone());

        let sig_key = SignatureKey {
            validator_id: vid,
            data_root: Bytes32(data.hash_tree_root()),
        };
        store
            .gossip_signatures
            .insert(sig_key, make_mock_signature());
    }

    let slot = Slot(2);
    let validator_idx = ValidatorIndex(2);

    let (_root, block, signatures) =
        produce_block_with_signatures(&mut store, slot, validator_idx)
            .expect("block production should succeed");

    // Block should include the 2 attestations we added (validators 5 and 6).
    // Attestations may be aggregated, so check the count matches signatures.
    assert_eq!(block.body.attestations.len_usize(), signatures.len());
    // We added 2 attestations with identical data, so they aggregate into 1.
    assert_eq!(signatures.len(), 1);

    // Verify block structure is correct
    assert_eq!(block.slot, slot);
    assert_eq!(block.proposer_index, validator_idx);
    assert_ne!(block.state_root, Bytes32::default());

    // Verify each aggregated signature proof
    let head_state = &store.states[&store.head];
    for i in 0..block.body.attestations.len_usize() {
        let agg_att = block.body.attestations.get(i as u64).unwrap();
        let proof: &containers::AggregatedSignatureProof = &signatures[i];
        assert!(
            !proof.proof_data.is_empty(),
            "aggregated signature proof must not be empty (placeholder detected)"
        );
        let participants = proof.get_participant_indices();
        let public_keys: Vec<_> = participants
            .iter()
            .map(|&vid| {
                head_state
                    .validators
                    .get(vid)
                    .expect("validator index out of range")
                    .pubkey
            })
            .collect();
        let message: [u8; 32] = agg_att.data.data_root_bytes().0.into();
        let epoch = agg_att.data.slot.0 as u32;
        proof
            .proof_data
            .verify(&public_keys, &message, epoch)
            .expect("aggregated signature proof verification failed");
    }
}

#[test]
fn test_produce_block_sequential_slots() {
    let mut store = create_test_store();

    // Produce block for slot 1
    let (block1_root, block1, _sig1) =
        produce_block_with_signatures(&mut store, Slot(1), ValidatorIndex(1))
            .expect("block1 should succeed");

    // Verify first block is properly created
    assert_eq!(block1.slot, Slot(1));
    assert_eq!(block1.proposer_index, ValidatorIndex(1));
    assert!(store.blocks.contains_key(&block1_root));
    assert!(store.states.contains_key(&block1_root));

    // Without any attestations, the forkchoice will stay on genesis.
    // This is the expected behavior: block1 exists but isn't the head.
    // So block2 should build on genesis, not block1.

    // Produce block for slot 2 (will build on genesis due to forkchoice)
    let (block2_root, block2, _sig2) =
        produce_block_with_signatures(&mut store, Slot(2), ValidatorIndex(2))
            .expect("block2 should succeed");

    // Verify block properties
    assert_eq!(block2.slot, Slot(2));
    assert_eq!(block2.proposer_index, ValidatorIndex(2));

    // The parent should be genesis (the current head), not block1
    let genesis_hash = store.head;
    assert_eq!(block2.parent_root, genesis_hash);

    // Both blocks should exist in the store
    assert!(store.blocks.contains_key(&block1_root));
    assert!(store.blocks.contains_key(&block2_root));
    assert!(store.blocks.contains_key(&genesis_hash));
}

#[test]
fn test_produce_block_empty_attestations() {
    let mut store = create_test_store();

    // Ensure no attestations in store
    store.latest_known_attestations.clear();

    let slot = Slot(3);
    let validator_idx = ValidatorIndex(3);

    let (_root, block, _sig) =
        produce_block_with_signatures(&mut store, slot, validator_idx)
            .expect("block production should succeed");

    // Should produce valid block with empty attestations
    assert_eq!(block.body.attestations.len_usize(), 0);
    assert_eq!(block.slot, slot);
    assert_eq!(block.proposer_index, validator_idx);
    assert_ne!(block.state_root, Bytes32::default());
}

#[test]
fn test_produce_block_state_consistency() {
    let mut store = create_test_store();

    // Add an attestation for validator 7
    let head_block = store.blocks[&store.head].clone();
    let head_checkpoint = Checkpoint {
        root: store.head,
        slot: head_block.slot,
    };
    let target = get_vote_target(&store);
    let data = AttestationData {
        slot: head_block.slot,
        head: head_checkpoint,
        target,
        source: store.latest_justified.clone(),
    };
    store
        .latest_known_attestations
        .insert(ValidatorIndex(7), data.clone());
    let sig_key = SignatureKey {
        validator_id: 7,
        data_root: Bytes32(data.hash_tree_root()),
    };
    store
        .gossip_signatures
        .insert(sig_key, make_mock_signature());

    let slot = Slot(4);
    let validator_idx = ValidatorIndex(4);

    let (block_root, block, signatures) =
        produce_block_with_signatures(&mut store, slot, validator_idx)
            .expect("block production should succeed");

    // Verify the stored state matches the block's state root
    let stored_state = &store.states[&block_root];
    assert_eq!(Bytes32(stored_state.hash_tree_root()), block.state_root);

    // Verify attestation count matches signature count.
    // We added 1 attestation (validator 7), so expect exactly 1.
    assert_eq!(block.body.attestations.len_usize(), signatures.len());
    assert_eq!(signatures.len(), 1);

    // Verify each aggregated signature proof
    let head_state = &store.states[&store.head];
    for i in 0..block.body.attestations.len_usize() {
        let agg_att = block.body.attestations.get(i as u64).unwrap();
        let proof: &containers::AggregatedSignatureProof = &signatures[i];
        assert!(
            !proof.proof_data.is_empty(),
            "aggregated signature proof must not be empty (placeholder detected)"
        );
        let participants = proof.get_participant_indices();
        let public_keys: Vec<_> = participants
            .iter()
            .map(|&vid| {
                head_state
                    .validators
                    .get(vid)
                    .expect("validator index out of range")
                    .pubkey
            })
            .collect();
        let message: [u8; 32] = agg_att.data.data_root_bytes().0.into();
        let epoch = agg_att.data.slot.0 as u32;
        proof
            .proof_data
            .verify(&public_keys, &message, epoch)
            .expect("aggregated signature proof verification failed");
    }
}

// ---------------------------------------------------------------------------
// TestValidatorIntegration
// ---------------------------------------------------------------------------

#[test]
fn test_block_production_then_attestation() {
    let mut store = create_test_store();

    // Proposer produces block for slot 1
    let (_root, _block, _sig) =
        produce_block_with_signatures(&mut store, Slot(1), ValidatorIndex(1))
            .expect("block should succeed");

    // Update store state after block production
    update_head(&mut store);

    // Other validator creates attestation for slot 2
    let attestor_idx = ValidatorIndex(7);
    let attestation_data = produce_attestation_data(&store, Slot(2));
    let attestation = Attestation {
        validator_id: Uint64(attestor_idx.0),
        data: attestation_data,
    };

    // Attestation should reference the new block as head (if it became head)
    assert_eq!(attestation.validator_id, Uint64(attestor_idx.0));
    assert_eq!(attestation.data.slot, Slot(2));

    // The attestation should be consistent with current forkchoice state
    assert_eq!(attestation.data.source, store.latest_justified);
}

#[test]
fn test_multiple_validators_coordination() {
    let mut store = create_test_store();

    // Validator 1 produces block for slot 1
    let (block1_root, block1, _sig1) =
        produce_block_with_signatures(&mut store, Slot(1), ValidatorIndex(1))
            .expect("block1 should succeed");
    let block1_hash = block1_root;

    // Validators 2-5 create attestations for slot 2
    // These will be based on the current forkchoice head (genesis)
    let mut attestations = Vec::new();
    for i in 2..6u64 {
        let data = produce_attestation_data(&store, Slot(2));
        let attestation = Attestation {
            validator_id: Uint64(i),
            data,
        };
        attestations.push(attestation);
    }

    // All attestations should be consistent
    let first = &attestations[0];
    for att in &attestations[1..] {
        assert_eq!(att.data.head.root, first.data.head.root);
        assert_eq!(att.data.target.root, first.data.target.root);
        assert_eq!(att.data.source.root, first.data.source.root);
    }

    // Validator 2 produces next block for slot 2
    // After processing block1, head should be block1 (fork choice walks the tree)
    // So block2 will build on block1
    let (block2_root, block2, _sig2) =
        produce_block_with_signatures(&mut store, Slot(2), ValidatorIndex(2))
            .expect("block2 should succeed");

    // Verify block properties
    assert_eq!(block2.slot, Slot(2));
    assert_eq!(block2.proposer_index, ValidatorIndex(2));

    // Both blocks should exist in the store
    assert!(store.blocks.contains_key(&block1_hash));
    assert!(store.blocks.contains_key(&block2_root));

    // block1 builds on genesis, block2 builds on block1 (current head)
    // Get the original genesis hash from the store's blocks
    let genesis_hash = store
        .blocks
        .iter()
        .filter(|(_, b)| b.slot == Slot(0))
        .map(|(root, _)| *root)
        .min()
        .expect("genesis block should exist");
    assert_eq!(block1.parent_root, genesis_hash);
    assert_eq!(block2.parent_root, block1_hash);
}

#[test]
fn test_validator_edge_cases() {
    let mut store = create_test_store();

    // Test with validator index equal to number of validators - 1
    let max_validator = ValidatorIndex(9); // Last validator (0-indexed, 10 total)
    let slot = Slot(9); // This validator's slot

    // Should be able to produce block
    let (_root, block, _sig) =
        produce_block_with_signatures(&mut store, slot, max_validator)
            .expect("max validator block should succeed");
    assert_eq!(block.proposer_index, max_validator);

    // Should be able to produce attestation
    let attestation_data = produce_attestation_data(&store, Slot(10));
    let attestation = Attestation {
        validator_id: Uint64(max_validator.0),
        data: attestation_data,
    };
    assert_eq!(attestation.validator_id, Uint64(max_validator.0));
}

#[test]
fn test_validator_operations_empty_store() {
    use containers::block::BlockWithAttestation;
    use containers::block::SignedBlockWithAttestation;
    use fork_choice::store::get_forkchoice_store;

    let config = Config { genesis_time: 1000 };

    // Create validators list with 3 validators
    let validators = vec![Validator::default(); 3];
    let state = State::generate_genesis_with_validators(Uint64(1000), validators);

    let genesis_body = BlockBody::default();
    let genesis = Block {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Bytes32::default(),
        state_root: Bytes32(state.hash_tree_root()),
        body: genesis_body,
    };

    let block_with_attestation = BlockWithAttestation {
        block: genesis.clone(),
        proposer_attestation: Attestation::default(),
    };

    let signed_block = SignedBlockWithAttestation {
        message: block_with_attestation,
        signature: Default::default(),
    };

    let mut store = get_forkchoice_store(state, signed_block, config);

    // Should be able to produce block and attestation
    let (_root, block, _sig) =
        produce_block_with_signatures(&mut store, Slot(1), ValidatorIndex(1))
            .expect("block should succeed");
    let attestation_data = produce_attestation_data(&store, Slot(1));
    let attestation = Attestation {
        validator_id: Uint64(2),
        data: attestation_data,
    };

    assert_eq!(block.slot, Slot(1));
    assert_eq!(attestation.validator_id, Uint64(2));
}

// ---------------------------------------------------------------------------
// TestValidatorErrorHandling
// ---------------------------------------------------------------------------

#[test]
fn test_produce_block_wrong_proposer() {
    let mut store = create_test_store();
    let slot = Slot(5);
    let wrong_proposer = ValidatorIndex(3); // Should be validator 5 for slot 5

    let result = produce_block_with_signatures(&mut store, slot, wrong_proposer);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("is not the proposer for slot"));
}

#[test]
fn test_produce_block_missing_parent_state() {
    let checkpoint = Checkpoint {
        root: Bytes32(ssz::H256::from_slice(&[0xab; 32])),
        slot: Slot(0),
    };

    // Create store with missing parent state
    let store = Store {
        time: 100,
        config: Config { genesis_time: 1000 },
        head: Bytes32(ssz::H256::from_slice(&[0xab; 32])),
        safe_target: Bytes32(ssz::H256::from_slice(&[0xab; 32])),
        latest_justified: checkpoint.clone(),
        latest_finalized: checkpoint,
        blocks: Default::default(),
        states: Default::default(),
        ..Default::default()
    };

    // Missing head in get_proposal_head -> KeyError equivalent
    let result = std::panic::catch_unwind(|| {
        let mut s = store;
        produce_block_with_signatures(&mut s, Slot(1), ValidatorIndex(1))
    });
    assert!(result.is_err());
}

#[test]
fn test_validator_operations_invalid_parameters() {
    let store = create_test_store();
    let genesis_hash = store.head;
    let state = &store.states[&genesis_hash];
    let num_validators = state.validators.len_u64();

    // Very large validator index (should work mathematically)
    let large_validator = ValidatorIndex(1_000_000);
    let large_slot = Slot(1_000_000);

    // is_proposer_for should work (though likely return False)
    let result = large_slot.0 % num_validators == large_validator.0;
    let _: bool = result;

    // Attestation can be created for any validator
    let attestation_data = produce_attestation_data(&store, Slot(1));
    let attestation = Attestation {
        validator_id: Uint64(large_validator.0),
        data: attestation_data,
    };
    assert_eq!(attestation.validator_id, Uint64(large_validator.0));
}
