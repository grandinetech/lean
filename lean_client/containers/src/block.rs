use crate::{
    Attestation, Bytes32, MultisigAggregatedSignature, Signature, Slot, State, ValidatorIndex,
};
use serde::{Deserialize, Serialize};
use ssz::SszHash;
use ssz_derive::Ssz;

use crate::attestation::{AggregatedAttestations, AttestationSignatures};

/// The body of a block, containing payload data.
///
/// Attestations are stored WITHOUT signatures. Signatures are aggregated
/// separately in BlockSignatures to match the spec architecture.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct BlockBody {
    #[serde(with = "crate::serde_helpers::aggregated_attestations")]
    pub attestations: AggregatedAttestations,
}

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body: BlockBody,
}

/// Bundle containing a block and the proposer's attestation.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockWithAttestation {
    /// The proposed block message.
    pub block: Block,
    /// The proposer's attestation corresponding to this block.
    pub proposer_attestation: Attestation,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Ssz, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BlockSignatures {
    #[serde(with = "crate::serde_helpers::attestation_signatures")]
    pub attestation_signatures: AttestationSignatures,
    #[serde(with = "crate::serde_helpers::signature")]
    pub proposer_signature: Signature,
}

/// Envelope carrying a block, an attestation from proposer, and aggregated signatures.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct SignedBlock {
    pub message: Block,
    pub signature: Signature,
}

/// Compute the SSZ hash tree root for any type implementing `SszHash`.
pub fn hash_tree_root<T: ssz::SszHash>(value: &T) -> Bytes32 {
    let h = value.hash_tree_root();
    Bytes32(h)
}

/// Compute the canonical block root for a Block.
pub fn compute_block_root(block: &Block) -> Bytes32 {
    Bytes32(block.hash_tree_root())
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
    pub fn verify_signatures(&self, parent_state: State) -> Result<(), String> {
        // Unpack the signed block components
        let block = &self.message.block;
        let signatures = &self.signature;
        let aggregated_attestations = block.body.attestations.clone();
        let attestation_signatures = signatures.attestation_signatures.clone();

        // Verify signature count matches aggregated attestation count
        if aggregated_attestations.len_u64() != attestation_signatures.len_u64() {
            return Err(format!(
                "Attestation signature count mismatch: {} attestations vs {} signatures",
                aggregated_attestations.len_u64(),
                attestation_signatures.len_u64()
            ));
        }

        let validators = &parent_state.validators;
        let num_validators = validators.len_u64();

        // Verify each aggregated attestation's zkVM proof
        for (aggregated_attestation, _aggregated_signature_proof) in (&aggregated_attestations)
            .into_iter()
            .zip((&attestation_signatures).into_iter())
        {
            let validator_ids = aggregated_attestation
                .aggregation_bits
                .to_validator_indices();

            // Ensure all validators exist in the active set
            for validator_id in &validator_ids {
                if *validator_id >= num_validators {
                    return Err(format!(
                        "Validator index {} out of range (max {})",
                        validator_id, num_validators
                    ));
                }
            }

            let attestation_data_root: [u8; 32] =
                hash_tree_root(&aggregated_attestation.data).0.into();

            // Collect validators, returning error if any not found
            let mut collected_validators = Vec::with_capacity(validator_ids.len());
            for vid in &validator_ids {
                let validator = validators
                    .get(*vid)
                    .map_err(|_| format!("Validator {} not found in state", vid))?;
                collected_validators.push(validator);
            }

            // Verify the lean-multisig aggregated proof for this attestation
            //
            // The proof verifies that all validators in aggregation_bits signed
            // the same attestation_data_root at the given epoch (slot).
            _aggregated_signature_proof
                .proof_data
                .verify_aggregated_payload(
                    &collected_validators,
                    &attestation_data_root,
                    aggregated_attestation.data.slot.0 as u32,
                )
                .map_err(|e| {
                    format!(
                        "Attestation aggregated signature verification failed: {:?}",
                        e
                    )
                })?;
        }

        // Verify the proposer attestation signature (outside the attestation loop)
        let proposer_attestation = &self.message.proposer_attestation;
        let proposer_signature = &signatures.proposer_signature;

        if proposer_attestation.validator_id.0 >= num_validators {
            return Err(format!(
                "Proposer index {} out of range (max {})",
                proposer_attestation.validator_id.0, num_validators
            ));
        }

        let proposer = validators
            .get(proposer_attestation.validator_id.0)
            .map_err(|_| {
                format!(
                    "Proposer {} not found in state",
                    proposer_attestation.validator_id.0
                )
            })?;

        let proposer_root: [u8; 32] = hash_tree_root(&proposer_attestation.data).0.into();
        if !verify_xmss_signature(
            proposer.pubkey,
            proposer_attestation.data.slot,
            &proposer_root,
            proposer_signature,
        ) {
            return Err("Proposer attestation signature verification failed".to_string());
        }

        Ok(())
    }
}

#[cfg(feature = "xmss-verify")]
pub fn verify_xmss_signature(
    public_key: crate::public_key::PublicKey,
    slot: Slot,
    message_bytes: &[u8; 32],
    signature: &Signature,
) -> bool {
    let epoch = slot.0 as u32;

    // Create Signature from the raw bytes
    let sig = crate::signature::Signature::from(signature.as_bytes());

    sig.verify(&public_key, epoch, message_bytes)
        .unwrap_or(false)
}

#[cfg(not(feature = "xmss-verify"))]
pub fn verify_xmss_signature(
    _public_key: crate::public_key::PublicKey,
    _slot: Slot,
    _message_bytes: &[u8; 32],
    _signature: &Signature,
) -> bool {
    true
}
