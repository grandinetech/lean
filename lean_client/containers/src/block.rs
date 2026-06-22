use std::collections::HashSet;

use crate::{Slot, State};
use anyhow::{Context, Result, ensure};
use metrics::METRICS;
use ssz::{H256, Ssz, SszHash};
use xmss::MultiMessageAggregate;

use crate::attestation::AggregatedAttestations;
use crate::state::MAX_ATTESTATIONS_DATA;

// todo(containers): default implementation doesn't make sense here.
#[derive(Clone, Debug, Ssz, Default)]
pub struct BlockBody {
    pub attestations: AggregatedAttestations,
}

#[derive(Clone, Debug, Ssz)]
pub struct BlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body_root: H256,
}

#[derive(Clone, Debug, Ssz)]
pub struct Block {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body: BlockBody,
}

#[derive(Clone, Debug, Ssz)]
pub struct SignedBlock {
    pub block: Block,
    pub proof: MultiMessageAggregate,
}

impl SignedBlock {
    /// Verify all XMSS signatures in this signed block.
    ///
    /// Verifies each aggregated attestation proof against the participant
    /// validator public keys from parent state.
    ///
    /// Returns `Ok(())` if all signatures are valid, or an error describing the failure.
    pub fn verify_signatures(&self, parent_state: &State) -> Result<()> {
        let block = &self.block;
        let aggregated_attestations = &block.body.attestations;

        ensure!(
            (aggregated_attestations.len_u64() as usize) <= MAX_ATTESTATIONS_DATA,
            "block has {} attestations; max is {MAX_ATTESTATIONS_DATA}",
            aggregated_attestations.len_u64(),
        );

        let validators = &parent_state.validators;
        let num_validators = validators.len_u64();

        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_attestation_verification_time_seconds
                .start_timer()
        });

        let attestations_len = aggregated_attestations.len_u64() as usize;
        let mut pubkeys_owned: Vec<Vec<xmss::PublicKey>> = Vec::with_capacity(attestations_len + 1);
        let mut messages: Vec<(H256, u32)> = Vec::with_capacity(attestations_len + 1);
        let mut seen_data_roots: HashSet<H256> = HashSet::with_capacity(attestations_len);

        for aggregated_attestation in aggregated_attestations {
            let validator_ids = aggregated_attestation
                .aggregation_bits
                .to_validator_indices();
            ensure!(
                !validator_ids.is_empty(),
                "attestation has empty aggregation_bits"
            );
            for validator_id in &validator_ids {
                ensure!(
                    *validator_id < num_validators,
                    "validator index {validator_id} out of range (max {num_validators})"
                );
            }
            let pubkeys = validator_ids
                .into_iter()
                .map(|id| {
                    validators
                        .get(id)
                        .map(|validator| validator.attestation_pubkey.clone())
                        .map_err(Into::into)
                })
                .collect::<Result<Vec<_>>>()?;
            pubkeys_owned.push(pubkeys);

            let data_root = aggregated_attestation.data.hash_tree_root();
            ensure!(
                seen_data_roots.insert(data_root),
                "duplicate AttestationData in block body"
            );
            messages.push((data_root, aggregated_attestation.data.slot.0 as u32));
        }

        let proposer_index = block.proposer_index;
        ensure!(
            proposer_index < num_validators,
            "proposer index {proposer_index} out of range (max {num_validators})"
        );
        let proposer = validators
            .get(proposer_index)
            .context(format!("proposer {proposer_index} not found in state"))?;
        pubkeys_owned.push(vec![proposer.proposal_pubkey.clone()]);

        let block_root = block.hash_tree_root();
        ensure!(
            !seen_data_roots.contains(&block_root),
            "block root collides with attestation data root"
        );
        messages.push((block_root, block.slot.0 as u32));

        let pubkeys_per_message: Vec<&[xmss::PublicKey]> =
            pubkeys_owned.iter().map(|v| v.as_slice()).collect();

        self.proof
            .verify(&pubkeys_per_message, &messages)
            .context("block proof verification failed")?;

        Ok(())
    }
}
