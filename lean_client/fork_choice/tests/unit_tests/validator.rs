//! Validator block production and attestation tests.
//!
//! Ported from spec/tests/lean_spec/subspecs/forkchoice/test_validator.py

use std::collections::HashMap;

use crate::unit_tests::common::create_test_store;
use containers::{
    AggregatedSignatureProof, AggregationBits, Attestation, AttestationData, Block, BlockBody,
    Checkpoint, Config, MultiMessageAggregate, SignedBlock, Slot, State, Validator,
};
use fork_choice::block_cache::BlockCache;
use fork_choice::handlers::on_block;
use fork_choice::store::{Store, get_forkchoice_store, produce_block_with_signatures, update_head};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use ssz::{H256, SszHash};
use std::collections::HashSet;
use xmss::SecretKey;

fn apply_block(store: &mut Store, block: &Block) {
    let signed_block = SignedBlock {
        block: block.clone(),
        proof: MultiMessageAggregate::default(),
    };
    let mut cache = BlockCache::new();
    on_block(store, &mut cache, signed_block, false).expect("on_block should succeed");
}

/// Build an `AggregatedSignatureProof` for the given validator set on the
/// given AttestationData, then publish it into the proposer's input pool
/// (`store.latest_known_aggregated_payloads` + `store.attestation_data_by_root`).
/// Mirrors what an aggregator's `maybe_aggregate` would have done at runtime.
fn publish_aggregated_payload(
    store: &mut Store,
    data: &AttestationData,
    validator_ids: &[u64],
    keys: &HashMap<u64, SecretKey>,
) {
    let data_root = data.hash_tree_root();
    let head_state = store
        .states
        .get(&store.head)
        .expect("head state must exist");

    let pubkeys: Vec<_> = validator_ids
        .iter()
        .map(|&vid| {
            head_state
                .validators
                .get(vid)
                .expect("validator index out of range")
                .attestation_pubkey
                .clone()
        })
        .collect();

    let signatures: Vec<_> = validator_ids
        .iter()
        .map(|&vid| {
            keys.get(&vid)
                .expect("missing secret key")
                .sign(data_root, data.slot.0 as u32)
                .expect("XMSS signing failed")
        })
        .collect();

    let participants = AggregationBits::from_validator_indices(validator_ids);
    let proof = AggregatedSignatureProof::aggregate(
        participants,
        pubkeys,
        signatures,
        data_root,
        data.slot.0 as u32,
        1,
    )
    .expect("AggregatedSignatureProof::aggregate failed");

    store
        .attestation_data_by_root
        .insert(data_root, data.clone());
    store
        .latest_known_aggregated_payloads
        .entry(data_root)
        .or_default()
        .push(proof);
}

fn create_test_store_with_signers() -> (Store, HashMap<u64, SecretKey>) {
    let config = Config { genesis_time: 1000 };

    let mut rng = ChaChaRng::seed_from_u64(1337);
    let (validators, keys) = (0..10)
        .map(|index| {
            let (attestation_pubkey, attest_sk) = SecretKey::generate_key_pair(&mut rng, 0, 10);
            let (proposal_pubkey, _proposal_sk) = SecretKey::generate_key_pair(&mut rng, 0, 10);

            (
                Validator {
                    index,
                    attestation_pubkey,
                    proposal_pubkey,
                },
                (index, attest_sk),
            )
        })
        .unzip();

    let state = State::generate_genesis_with_validators(1000, validators);

    let block = Block {
        slot: Slot(0),
        proposer_index: 0,
        parent_root: H256::default(),
        state_root: state.hash_tree_root(),
        body: BlockBody::default(),
    };

    let signed_block = SignedBlock {
        block,
        proof: Default::default(),
    };

    (
        get_forkchoice_store(state, signed_block, config, true, 1),
        keys,
    )
}
// ---------------------------------------------------------------------------
// TestBlockProduction
// ---------------------------------------------------------------------------

#[test]
fn test_produce_block_basic() {
    let mut store = create_test_store();
    let initial_head = store.head;

    let slot = Slot(1);
    let validator_idx = 1;

    let (block_root, block, _signatures) =
        produce_block_with_signatures(&mut store, slot, validator_idx, 1)
            .expect("block production should succeed");

    // Verify block structure
    assert_eq!(block.slot, slot);
    assert_eq!(block.proposer_index, validator_idx);
    assert_eq!(block.parent_root, initial_head);
    assert_ne!(block.state_root, H256::default());

    apply_block(&mut store, &block);

    // Verify block was added to store
    assert!(store.blocks.contains_key(&block_root));
    assert!(store.states.contains_key(&block_root));
}

#[test]
fn test_produce_block_unauthorized_proposer() {
    let mut store = create_test_store();
    let slot = Slot(1);
    let wrong_validator = 2; // Not proposer for slot 1

    let result = produce_block_with_signatures(&mut store, slot, wrong_validator, 1);
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("is not the proposer for slot"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_produce_block_with_attestations() {
    let (mut store, keys) = create_test_store_with_signers();
    let head_block = store.blocks[&store.head].clone();
    let head_checkpoint = Checkpoint {
        root: store.head,
        slot: head_block.slot,
    };
    let target = store.get_attestation_target();

    // Publish a single aggregated payload covering validators 5 and 6 — this
    // mirrors what an aggregator's `maybe_aggregate` would publish via gossip
    // and what `on_aggregated_attestation` would land in the proposer's pool.
    let data = AttestationData {
        slot: head_block.slot,
        head: head_checkpoint,
        target,
        source: store.latest_justified.clone(),
    };
    publish_aggregated_payload(&mut store, &data, &[5u64, 6], &keys);

    let slot = Slot(2);
    let validator_idx = 2;

    let (_root, block, signatures) =
        produce_block_with_signatures(&mut store, slot, validator_idx, 1)
            .expect("block production should succeed");

    // Block should include the 2 attestations we added (validators 5 and 6).
    // Attestations may be aggregated, so check the count matches signatures.
    assert_eq!(block.body.attestations.len_usize(), signatures.len());
    // We added 2 attestations with identical data, so they aggregate into 1.
    assert_eq!(signatures.len(), 1);

    // Verify block structure is correct
    assert_eq!(block.slot, slot);
    assert_eq!(block.proposer_index, validator_idx);
    assert_ne!(block.state_root, H256::default());

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
                    .attestation_pubkey
                    .clone()
            })
            .collect();
        let epoch = agg_att.data.slot.0 as u32;
        proof
            .verify(public_keys, agg_att.data.hash_tree_root(), epoch)
            .expect("aggregated signature proof verification failed");
    }
}

#[test]
fn test_produce_block_sequential_slots() {
    let mut store = create_test_store();

    // Produce block for slot 1
    let (block1_root, block1, _sig1) =
        produce_block_with_signatures(&mut store, Slot(1), 1, 1).expect("block1 should succeed");

    // Verify first block is properly created
    assert_eq!(block1.slot, Slot(1));
    assert_eq!(block1.proposer_index, 1);
    apply_block(&mut store, &block1);
    assert!(store.blocks.contains_key(&block1_root));
    assert!(store.states.contains_key(&block1_root));

    // Without any attestations, the forkchoice will stay on genesis.
    // This is the expected behavior: block1 exists but isn't the head.
    // So block2 should build on genesis, not block1.

    // Produce block for slot 2 (will build on genesis due to forkchoice)
    let (block2_root, block2, _sig2) =
        produce_block_with_signatures(&mut store, Slot(2), 2, 1).expect("block2 should succeed");

    // Verify block properties
    assert_eq!(block2.slot, Slot(2));
    assert_eq!(block2.proposer_index, 2);

    // The parent should be genesis (the current head), not block1
    let genesis_hash = store.head;
    assert_eq!(block2.parent_root, genesis_hash);

    apply_block(&mut store, &block2);

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
    let validator_idx = 3;

    let (_root, block, _sig) = produce_block_with_signatures(&mut store, slot, validator_idx, 1)
        .expect("block production should succeed");

    // Should produce valid block with empty attestations
    assert_eq!(block.body.attestations.len_usize(), 0);
    assert_eq!(block.slot, slot);
    assert_eq!(block.proposer_index, validator_idx);
    assert_ne!(block.state_root, H256::default());
}

#[test]
fn test_produce_block_state_consistency() {
    let (mut store, keys) = create_test_store_with_signers();

    // Publish an aggregated payload for validator 7. Same shape as a real
    // aggregator-published payload feeding the proposer's pool.
    let head_block = store.blocks[&store.head].clone();
    let head_checkpoint = Checkpoint {
        root: store.head,
        slot: head_block.slot,
    };
    let target = store.get_attestation_target();
    let data = AttestationData {
        slot: head_block.slot,
        head: head_checkpoint,
        target,
        source: store.latest_justified.clone(),
    };
    publish_aggregated_payload(&mut store, &data, &[7u64], &keys);

    let slot = Slot(4);
    let validator_idx = 4;

    let (block_root, block, signatures) =
        produce_block_with_signatures(&mut store, slot, validator_idx, 1)
            .expect("block production should succeed");

    apply_block(&mut store, &block);

    // Verify the stored state matches the block's state root
    let stored_state = &store.states[&block_root];
    assert_eq!(stored_state.hash_tree_root(), block.state_root);

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
                    .attestation_pubkey
                    .clone()
            })
            .collect();
        let epoch = agg_att.data.slot.0 as u32;
        proof
            .proof_data
            .verify(public_keys, agg_att.data.hash_tree_root(), epoch)
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
        produce_block_with_signatures(&mut store, Slot(1), 1, 1).expect("block should succeed");

    // Update store state after block production
    update_head(&mut store);

    // Other validator creates attestation for slot 2
    let attestor_idx = 7;
    let attestation_data = store
        .produce_attestation_data(Slot(2))
        .expect("failed to produce attestation data");
    let attestation = Attestation {
        validator_id: attestor_idx,
        data: attestation_data,
    };

    // Attestation should reference the new block as head (if it became head)
    assert_eq!(attestation.validator_id, attestor_idx);
    assert_eq!(attestation.data.slot, Slot(2));

    let head_state = store
        .states
        .get(&store.head)
        .expect("head state must exist");
    let expected_source = if head_state.latest_justified.root.is_zero() {
        Checkpoint {
            root: store.head,
            slot: head_state.latest_justified.slot,
        }
    } else {
        head_state.latest_justified.clone()
    };
    assert_eq!(attestation.data.source, expected_source);
}

#[test]
fn test_multiple_validators_coordination() {
    let mut store = create_test_store();

    // Validator 1 produces block for slot 1
    let (block1_root, block1, _sig1) =
        produce_block_with_signatures(&mut store, Slot(1), 1, 1).expect("block1 should succeed");
    let block1_hash = block1_root;
    apply_block(&mut store, &block1);

    // Validators 2-5 create attestations for slot 2
    // These will be based on the current forkchoice head (genesis)
    let mut attestations = Vec::new();
    for i in 2..6u64 {
        let data = store
            .produce_attestation_data(Slot(2))
            .expect("failed to produce attestation data");
        let attestation = Attestation {
            validator_id: i,
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
        produce_block_with_signatures(&mut store, Slot(2), 2, 1).expect("block2 should succeed");

    // Verify block properties
    assert_eq!(block2.slot, Slot(2));
    assert_eq!(block2.proposer_index, 2);

    apply_block(&mut store, &block2);

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
    let max_validator = 9; // Last validator (0-indexed, 10 total)
    let slot = Slot(9); // This validator's slot

    // Should be able to produce block
    let (_root, block, _sig) = produce_block_with_signatures(&mut store, slot, max_validator, 1)
        .expect("max validator block should succeed");
    assert_eq!(block.proposer_index, max_validator);

    // Should be able to produce attestation
    let attestation_data = store
        .produce_attestation_data(Slot(10))
        .expect("failed to produce attestation data");
    let attestation = Attestation {
        validator_id: max_validator,
        data: attestation_data,
    };
    assert_eq!(attestation.validator_id, max_validator);
}

#[test]
fn test_validator_operations_empty_store() {
    let config = Config { genesis_time: 1000 };

    // Create validators list with 3 validators
    let validators = vec![Validator::default(); 3];
    let state = State::generate_genesis_with_validators(1000, validators);

    let genesis_body = BlockBody::default();
    let genesis = Block {
        slot: Slot(0),
        proposer_index: 0,
        parent_root: H256::default(),
        state_root: state.hash_tree_root(),
        body: genesis_body,
    };

    let signed_block = SignedBlock {
        block: genesis,
        proof: Default::default(),
    };

    let mut store = get_forkchoice_store(state, signed_block, config, true, 1);

    // Should be able to produce block and attestation
    let (_root, block, _sig) =
        produce_block_with_signatures(&mut store, Slot(1), 1, 1).expect("block should succeed");
    let attestation_data = store
        .produce_attestation_data(Slot(1))
        .expect("failed to produce attestation data");
    let attestation = Attestation {
        validator_id: 2,
        data: attestation_data,
    };

    assert_eq!(block.slot, Slot(1));
    assert_eq!(attestation.validator_id, 2);
}

// ---------------------------------------------------------------------------
// TestValidatorErrorHandling
// ---------------------------------------------------------------------------

#[test]
fn test_produce_block_wrong_proposer() {
    let mut store = create_test_store();
    let slot = Slot(5);
    let wrong_proposer = 3; // Should be validator 5 for slot 5

    let result = produce_block_with_signatures(&mut store, slot, wrong_proposer, 1);
    assert!(result.is_err());
    assert!(format!("{:?}", result.unwrap_err()).contains("is not the proposer for slot"));
}

#[test]
fn test_produce_block_missing_parent_state() {
    let checkpoint = Checkpoint {
        root: H256::from_slice(&[0xab; 32]),
        slot: Slot(0),
    };

    // Create store with missing parent state
    let store = Store {
        time: 100,
        config: Config { genesis_time: 1000 },
        head: H256::from_slice(&[0xab; 32]),
        safe_target: H256::from_slice(&[0xab; 32]),
        latest_justified: checkpoint.clone(),
        latest_finalized: checkpoint,
        blocks: Default::default(),
        states: Default::default(),
        ..Default::default()
    };

    let mut s = store;
    let result = produce_block_with_signatures(&mut s, Slot(1), 1, 1);
    assert!(result.is_err());
}

#[test]
fn test_validator_operations_invalid_parameters() {
    let store = create_test_store();
    let genesis_hash = store.head;
    let state = &store.states[&genesis_hash];
    let num_validators = state.validators.len_u64();

    // Very large validator index (should work mathematically)
    let large_validator = 1_000_000;
    let large_slot = Slot(1_000_000);

    // is_proposer_for should work (though likely return False)
    let result = large_slot.0 % num_validators == large_validator;
    let _: bool = result;

    // Attestation can be created for any validator
    let attestation_data = store
        .produce_attestation_data(Slot(1))
        .expect("failed to produce attestation data");
    let attestation = Attestation {
        validator_id: large_validator,
        data: attestation_data,
    };
    assert_eq!(attestation.validator_id, large_validator);
}

#[test]
fn test_produce_attestation_data_uses_head_state_justified() {
    let mut store = create_test_store();

    let head_state_justified = Checkpoint {
        root: H256::from_slice(&[0xaa; 32]),
        slot: Slot(3),
    };
    let store_only_justified = Checkpoint {
        root: H256::from_slice(&[0xff; 32]),
        slot: Slot(5),
    };

    let mut new_head_state = store.states[&store.head].as_ref().clone();
    new_head_state.latest_justified = head_state_justified.clone();
    store
        .states
        .insert(store.head, std::sync::Arc::new(new_head_state));

    store.latest_justified = store_only_justified.clone();

    let attestation_data = store
        .produce_attestation_data(Slot(1))
        .expect("produce_attestation_data failed");

    assert_eq!(attestation_data.source, head_state_justified);
    assert_ne!(attestation_data.source, store_only_justified);
}

fn produce_and_apply(
    store: &mut Store,
    cache: &mut BlockCache,
    slot: Slot,
    keys: &HashMap<u64, SecretKey>,
) -> H256 {
    let num_validators = store.states[&store.head].validators.len_u64();
    let proposer = slot.0 % num_validators;
    let _ = keys;
    let (_block_root, block, _sigs) =
        produce_block_with_signatures(store, slot, proposer, 1).expect("block production failed");
    let signed = SignedBlock {
        block,
        proof: MultiMessageAggregate::default(),
    };
    let block_root = signed.block.hash_tree_root();
    on_block(store, cache, signed, false).expect("on_block failed");
    block_root
}

#[test]
fn test_produce_block_closes_justification_gap() {
    let (mut store, keys) = create_test_store_with_signers();
    let mut cache = BlockCache::new();
    let num_validators = store.states[&store.head].validators.len_u64();
    let genesis_root = store.head;
    let genesis_ckpt = Checkpoint {
        root: genesis_root,
        slot: Slot(0),
    };

    let block_1_root = produce_and_apply(&mut store, &mut cache, Slot(1), &keys);
    let block_2_root = produce_and_apply(&mut store, &mut cache, Slot(2), &keys);
    let block_3_root = produce_and_apply(&mut store, &mut cache, Slot(3), &keys);

    let block_1_ckpt = Checkpoint {
        root: block_1_root,
        slot: Slot(1),
    };
    let block_2_ckpt = Checkpoint {
        root: block_2_root,
        slot: Slot(2),
    };
    let block_3_ckpt = Checkpoint {
        root: block_3_root,
        slot: Slot(3),
    };

    let att_target_block_1 = AttestationData {
        slot: Slot(4),
        head: block_3_ckpt.clone(),
        target: block_1_ckpt.clone(),
        source: genesis_ckpt.clone(),
    };
    publish_aggregated_payload(
        &mut store,
        &att_target_block_1,
        &[0, 1, 2, 3, 4, 5, 6],
        &keys,
    );

    let block_4_root = produce_and_apply(&mut store, &mut cache, Slot(4), &keys);
    let block_4_ckpt = Checkpoint {
        root: block_4_root,
        slot: Slot(4),
    };
    assert_eq!(store.latest_justified, block_1_ckpt);

    let att_target_block_4 = AttestationData {
        slot: Slot(5),
        head: block_4_ckpt.clone(),
        target: block_4_ckpt.clone(),
        source: block_1_ckpt.clone(),
    };
    publish_aggregated_payload(&mut store, &att_target_block_4, &[7, 8], &keys);

    let block_5_root = produce_and_apply(&mut store, &mut cache, Slot(5), &keys);
    assert_eq!(store.latest_justified, block_1_ckpt);
    assert_eq!(store.head, block_5_root);

    let att_target_block_2 = AttestationData {
        slot: Slot(6),
        head: block_3_ckpt.clone(),
        target: block_2_ckpt.clone(),
        source: genesis_ckpt.clone(),
    };
    publish_aggregated_payload(
        &mut store,
        &att_target_block_2,
        &[0, 1, 2, 3, 4, 5, 6],
        &keys,
    );

    let block_3_state = store
        .states
        .get(&block_3_root)
        .expect("block_3 state missing")
        .clone();
    let known_block_roots: HashSet<H256> = store.blocks.keys().copied().collect();
    let aggregated_payloads: HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)> =
        store
            .latest_known_aggregated_payloads
            .iter()
            .filter_map(|(root, proofs)| {
                store
                    .attestation_data_by_root
                    .get(root)
                    .map(|data| (*root, (data.clone(), proofs.clone())))
            })
            .collect();
    let proposer_6 = Slot(6).0 % num_validators;
    let (block_6, _post_state_6, _atts_6, _sigs_6) = block_3_state
        .build_block(
            Slot(6),
            proposer_6,
            block_3_root,
            &known_block_roots,
            &aggregated_payloads,
            1,
        )
        .expect("build_block for sibling block_6 failed");
    let signed_block_6 = SignedBlock {
        block: block_6,
        proof: MultiMessageAggregate::default(),
    };
    let block_6_root = signed_block_6.block.hash_tree_root();
    on_block(&mut store, &mut cache, signed_block_6, false).expect("on_block for block_6 failed");

    assert_eq!(store.latest_justified, block_2_ckpt);
    assert_eq!(store.head, block_5_root);

    let gap_closers: Vec<&AttestationData> = store
        .latest_known_aggregated_payloads
        .keys()
        .filter_map(|root| store.attestation_data_by_root.get(root))
        .filter(|d| d.target == block_2_ckpt)
        .collect();
    assert_eq!(gap_closers.len(), 1);
    assert_eq!(gap_closers[0].source, genesis_ckpt);
    assert_eq!(gap_closers[0].slot, Slot(6));

    let proposer_7 = Slot(7).0 % num_validators;
    let (_block_7_root, block_7, _sigs_7) =
        produce_block_with_signatures(&mut store, Slot(7), proposer_7, 1)
            .expect("block production for block_7 failed");

    assert_eq!(block_7.parent_root, block_5_root);

    let body_targets: Vec<Checkpoint> = (0..block_7.body.attestations.len_usize())
        .map(|i| {
            block_7
                .body
                .attestations
                .get(i as u64)
                .expect("missing attestation")
                .data
                .target
                .clone()
        })
        .collect();
    assert!(body_targets.contains(&block_2_ckpt));

    let signed_block_7 = SignedBlock {
        block: block_7,
        proof: MultiMessageAggregate::default(),
    };
    on_block(&mut store, &mut cache, signed_block_7, false).expect("on_block for block_7 failed");
    assert_eq!(store.latest_justified, block_2_ckpt);

    let _ = block_6_root;
}
