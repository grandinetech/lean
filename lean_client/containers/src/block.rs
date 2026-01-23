use crate::{Attestation, Slot, State};
use anyhow::{Context, Result, ensure};
use metrics::METRICS;
use serde::{Deserialize, Serialize};
use ssz::{H256, Ssz, SszHash};
use xmss::Signature;

use crate::attestation::{AggregatedAttestations, AttestationSignatures};

/// The body of a block, containing payload data.
///
/// Attestations are stored WITHOUT signatures. Signatures are aggregated
/// separately in BlockSignatures to match the spec architecture.
// todo(containers): default implementation doesn't make sense here.
#[derive(Clone, Debug, Ssz, Serialize, Deserialize, Default)]
pub struct BlockBody {
    #[serde(with = "crate::serde_helpers::aggregated_attestations")]
    pub attestations: AggregatedAttestations,
}

#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body_root: H256,
}

#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body: BlockBody,
}

/// Bundle containing a block and the proposer's attestation.
#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockWithAttestation {
    /// The proposed block message.
    pub block: Block,
    /// The proposer's attestation corresponding to this block.
    pub proposer_attestation: Attestation,
}

// todo(containers): default implementation doesn't make sense here
#[derive(Debug, Clone, Ssz, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BlockSignatures {
    #[serde(with = "crate::serde_helpers::attestation_signatures")]
    pub attestation_signatures: AttestationSignatures,
    pub proposer_signature: Signature,
}

/// Envelope carrying a block, an attestation from proposer, and aggregated signatures.
#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedBlockWithAttestation {
    /// The block plus an attestation from proposer being signed.
    pub message: BlockWithAttestation,
    /// Aggregated signature payload for the block.
    ///
    /// Signatures remain in attestation order followed by the proposer signature.
    pub signature: BlockSignatures,
}

/// Legacy signed block structure (kept for backwards compatibility).
#[derive(Clone, Debug, Ssz)]
pub struct SignedBlock {
    pub message: Block,
    pub signature: Signature,
}

impl SignedBlockWithAttestation {
    /// Verify all XMSS signatures in this signed block.
    ///
    /// This function ensures that every attestation included in the block
    /// (both on-chain attestations from the block body and the proposer's
    /// own attestation) is properly signed by the claimed validator using
    /// their registered XMSS public key.
    ///
    /// # XMSS Verification
    ///
    /// ## Without feature flag (default):
    /// The function performs structural validation only:
    /// - Verifies signature count matches attestation count
    /// - Validates validator indices are within bounds
    /// - Prepares all data for verification
    ///
    /// ## With `xmss-verify` feature flag:
    /// Enables cryptographic XMSS signature verification using the leanSig library.
    ///
    /// To enable: `cargo build --features xmss-verify`
    ///
    /// # Arguments
    ///
    /// * `parent_state` - The state at the parent block, used to retrieve
    ///   validator public keys and verify signatures.
    ///
    /// # Returns
    ///
    /// `true` if all signatures are cryptographically valid (or verification is disabled).
    ///
    /// # Panics
    ///
    /// Panics if validation fails:
    /// - Signature count mismatch
    /// - Validator index out of range
    /// - XMSS signature verification failure (when feature enabled)
    ///
    /// # References
    ///
    /// - Spec: <https://github.com/leanEthereum/leanSpec/blob/main/src/lean_spec/subspecs/containers/block/block.py#L35>
    /// - XMSS Library: <https://github.com/leanEthereum/leanSig>
    /// Verifies all attestation signatures using lean-multisig aggregated proofs.
    /// Each attestation has a single `MultisigAggregatedSignature` proof that covers
    /// all participating validators.
    ///
    /// Returns `Ok(())` if all signatures are valid, or an error describing the failure.
    pub fn verify_signatures(&self, parent_state: State) -> Result<()> {
        // Unpack the signed block components
        let block = &self.message.block;
        let signatures = &self.signature;
        let aggregated_attestations = &block.body.attestations;
        let attestation_signatures = &signatures.attestation_signatures;

        // Verify signature count matches aggregated attestation count
        ensure!(
            aggregated_attestations.len_u64() == attestation_signatures.len_u64(),
            "attestation signature count mismatch: {} attestations vs {} signatures",
            aggregated_attestations.len_u64(),
            attestation_signatures.len_u64()
        );

        let validators = &parent_state.validators;
        let num_validators = validators.len_u64();

        // Verify each aggregated attestation's zkVM proof
        for (aggregated_attestation, aggregated_signature) in aggregated_attestations
            .into_iter()
            .zip(attestation_signatures.into_iter())
        {
            let validator_ids = aggregated_attestation
                .aggregation_bits
                .to_validator_indices();

            // Ensure all validators exist in the active set
            for validator_id in &validator_ids {
                ensure!(
                    *validator_id < num_validators,
                    "validator index {validator_id} out of range (max {num_validators})"
                );
            }

            let attestation_data_root = aggregated_attestation.data.hash_tree_root();

            // Collect validators, returning error if any not found
            let public_keys = validator_ids
                .into_iter()
                .map(|id| {
                    validators
                        .get(id)
                        .map(|validator| validator.pubkey.clone())
                        .map_err(Into::into)
                })
                .collect::<Result<Vec<_>>>()?;

            // Verify the lean-multisig aggregated proof for this attestation
            //
            // The proof verifies that all validators in aggregation_bits signed
            // the same attestation_data_root at the given epoch (slot).
            aggregated_signature
                .verify(
                    public_keys,
                    attestation_data_root,
                    aggregated_attestation.data.slot.0 as u32,
                )
                .context("attestation aggregated signature verification failed")?;
        }

        // Verify the proposer attestation signature (outside the attestation loop)
        let proposer_attestation = &self.message.proposer_attestation;
        let proposer_signature = &signatures.proposer_signature;

        ensure!(
            proposer_attestation.validator_id < num_validators,
            "proposer index {} out of range (max {num_validators})",
            proposer_attestation.validator_id
        );

        let proposer = validators
            .get(proposer_attestation.validator_id)
            .context(format!(
                "proposer {} not found in state",
                proposer_attestation.validator_id
            ))?;

        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_signature_attestation_verification_time_seconds
                .start_timer()
        });

        proposer_signature
            .verify(
                &proposer.pubkey,
                proposer_attestation.data.slot.0 as u32,
                proposer_attestation.data.hash_tree_root(),
            )
            .context("Proposer signature verification failed")?;

        Ok(())
    }
}
