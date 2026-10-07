use std::collections::HashSet;
use std::sync::Arc;

use containers::{AggregatedSignatureProof, AggregationBits, SignedBlock, Validators};
use metrics::METRICS;
use parking_lot::RwLock;
use ssz::{H256, SszHash};
use tracing::{debug, info, warn};
use xmss::PublicKey;

use crate::store::Store;

pub const MAX_REAGGREGATIONS_PER_BLOCK: usize = 4;

pub struct ReaggregateContext {
    pubkeys_per_component: Vec<Vec<PublicKey>>,
    /// The `(message, slot)` binding of each component, index-aligned with
    /// `pubkeys_per_component`: one per attestation, then the proposer's.
    components: Vec<(H256, u32)>,
    candidates: Vec<(H256, AggregationBits)>,
}

pub fn select_candidates(
    store: &Store,
    signed_block: &SignedBlock,
    validators: &Validators,
) -> Option<ReaggregateContext> {
    let block = &signed_block.block;
    let attestations = &block.body.attestations;
    if attestations.len_u64() == 0 {
        return None;
    }

    let num_validators = validators.len_u64();

    let proposer_index = block.proposer_index;
    if proposer_index >= num_validators {
        warn!(
            proposer_index,
            "reaggregate skipped: proposer index out of range"
        );
        return None;
    }

    let mut pubkeys_per_component: Vec<Vec<PublicKey>> =
        Vec::with_capacity(attestations.len_u64() as usize + 1);
    let mut components: Vec<(H256, u32)> = Vec::with_capacity(attestations.len_u64() as usize + 1);

    for att in attestations.into_iter() {
        let validator_ids = att.aggregation_bits.to_validator_indices();
        for vid in &validator_ids {
            if *vid >= num_validators {
                warn!(vid, "reaggregate skipped: participant out of range");
                return None;
            }
        }
        let mut pks = Vec::with_capacity(validator_ids.len());
        for vid in validator_ids {
            let v = match validators.get(vid) {
                Ok(v) => v,
                Err(err) => {
                    warn!(vid, ?err, "reaggregate skipped: validator lookup failed");
                    return None;
                }
            };
            pks.push(v.attestation_pubkey.clone());
        }
        pubkeys_per_component.push(pks);
        components.push((att.data.hash_tree_root(), att.data.slot.0 as u32));
    }

    let proposer = match validators.get(proposer_index) {
        Ok(v) => v,
        Err(err) => {
            warn!(
                proposer_index,
                ?err,
                "reaggregate skipped: proposer lookup failed"
            );
            return None;
        }
    };
    pubkeys_per_component.push(vec![proposer.proposal_pubkey.clone()]);
    components.push((block.hash_tree_root(), block.slot.0 as u32));

    let latest_justified_slot = store.latest_justified.slot;
    let mut candidates: Vec<(H256, AggregationBits)> = Vec::new();

    for att in attestations.into_iter() {
        if candidates.len() >= MAX_REAGGREGATIONS_PER_BLOCK {
            break;
        }

        if att.data.target.slot <= latest_justified_slot {
            continue;
        }

        let data_root = att.data.hash_tree_root();

        let local_union: HashSet<u64> = store
            .latest_new_aggregated_payloads
            .get(&data_root)
            .map(|proofs| {
                proofs
                    .iter()
                    .flat_map(|p| p.participants.to_validator_indices())
                    .collect()
            })
            .unwrap_or_default();

        let block_participants: HashSet<u64> = att
            .aggregation_bits
            .to_validator_indices()
            .into_iter()
            .collect();

        if block_participants.is_subset(&local_union) {
            continue;
        }

        candidates.push((data_root, att.aggregation_bits.clone()));
    }

    let body_attestations = attestations.len_u64() as usize;
    let selected = candidates.len();
    let skipped_target = body_attestations.saturating_sub(selected);
    METRICS.get().map(|m| {
        m.grandine_reaggregate_candidates_selected_total
            .with_label_values(&["selected"])
            .inc_by(selected as u64);
        if skipped_target > 0 {
            m.grandine_reaggregate_candidates_selected_total
                .with_label_values(&["skipped"])
                .inc_by(skipped_target as u64);
        }
    });

    if candidates.is_empty() {
        info!(
            body_attestations,
            justified_slot = latest_justified_slot.0,
            "reaggregate: no candidates after filter"
        );
        return None;
    }

    info!(
        body_attestations,
        selected,
        justified_slot = latest_justified_slot.0,
        "reaggregate: candidates ready for split"
    );

    Some(ReaggregateContext {
        pubkeys_per_component,
        components,
        candidates,
    })
}

pub fn compute_recoveries(
    signed_block: &SignedBlock,
    context: ReaggregateContext,
    log_inv_rate: usize,
) -> Vec<(H256, AggregatedSignatureProof)> {
    let pubkeys_per_component_view: Vec<&[PublicKey]> = context
        .pubkeys_per_component
        .iter()
        .map(|v| v.as_slice())
        .collect();

    let mut recoveries = Vec::with_capacity(context.candidates.len());
    for (data_root, participants) in context.candidates {
        match signed_block.proof.split_by_message(
            &pubkeys_per_component_view,
            &context.components,
            data_root,
            log_inv_rate,
        ) {
            Ok(recovered) => {
                METRICS.get().map(|m| {
                    m.grandine_reaggregate_split_outcomes_total
                        .with_label_values(&["success"])
                        .inc()
                });
                recoveries.push((
                    data_root,
                    AggregatedSignatureProof {
                        participants,
                        proof_data: recovered,
                    },
                ));
            }
            Err(err) => {
                METRICS.get().map(|m| {
                    m.grandine_reaggregate_split_outcomes_total
                        .with_label_values(&["failure"])
                        .inc()
                });
                warn!(?err, %data_root, "reaggregate split failed for attestation");
            }
        }
    }
    recoveries
}

pub fn apply_recoveries(store: &mut Store, recoveries: Vec<(H256, AggregatedSignatureProof)>) {
    for (data_root, proof) in recoveries {
        store.add_new_aggregated_payload(data_root, proof);
    }
}

pub fn run_sync(store: &mut Store, signed_block: &SignedBlock, log_inv_rate: usize) {
    let parent_validators = match store.states.get(&signed_block.block.parent_root) {
        Some(state) => state.validators.clone(),
        None => {
            debug!(
                parent_root = %signed_block.block.parent_root,
                "reaggregate skipped: parent state missing"
            );
            return;
        }
    };
    let context = select_candidates(store, signed_block, &parent_validators);

    let context = match context {
        Some(c) => c,
        None => return,
    };

    let recoveries = compute_recoveries(signed_block, context, log_inv_rate);
    if recoveries.is_empty() {
        return;
    }

    apply_recoveries(store, recoveries);
}

pub fn run_in_executor(store: Arc<RwLock<Store>>, signed_block: SignedBlock, log_inv_rate: usize) {
    if xmss::prover_busy() {
        debug!(
            block_root = %signed_block.block.hash_tree_root(),
            "reaggregate skipped: prover busy"
        );
        METRICS.get().map(|m| {
            m.grandine_reaggregate_split_outcomes_total
                .with_label_values(&["skipped_prover_busy"])
                .inc()
        });
        return;
    }

    let context = {
        let s = store.read();
        let parent_validators = match s.states.get(&signed_block.block.parent_root) {
            Some(state) => state.validators.clone(),
            None => {
                debug!(
                    parent_root = %signed_block.block.parent_root,
                    "reaggregate skipped: parent state missing"
                );
                return;
            }
        };
        select_candidates(&s, &signed_block, &parent_validators)
    };

    let context = match context {
        Some(c) => c,
        None => return,
    };

    let recoveries = compute_recoveries(&signed_block, context, log_inv_rate);
    if recoveries.is_empty() {
        return;
    }

    apply_recoveries(&mut store.write(), recoveries);
}
