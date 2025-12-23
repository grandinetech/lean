use crate::{Attestation, Attestations, Bytes32, Signature, Slot, State, ValidatorIndex};
use serde::{Deserialize, Serialize};
use ssz_derive::Ssz;

#[cfg(feature = "xmss-verify")]
use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_20::target_sum::SIGTargetSumLifetime20W2NoOff;
use ssz::{PersistentList, SszHash};
use typenum::U4096;
use crate::attestation::{AggregatedAttestations, AttestationSignatures};
use crate::validator::BlsPublicKey;

/// The body of a block, containing payload data.
///
/// Attestations are stored WITHOUT signatures. Signatures are aggregated
/// separately in BlockSignatures to match the spec architecture.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct BlockBody {
    #[cfg(feature = "devnet2")]
    pub attestations: AggregatedAttestations,
    #[cfg(feature = "devnet1")]
    #[serde(with = "crate::serde_helpers")]
    pub attestations: Attestations,
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
pub struct BlockSignatures {
    pub attestation_signatures: AttestationSignatures,
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
    #[cfg(feature = "devnet1")]
    #[serde(with = "crate::serde_helpers::block_signatures")]
    pub signature: PersistentList<Signature, U4096>,
    #[cfg(feature = "devnet2")]
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
    #[cfg(feature = "devnet1")]
    pub fn verify_signatures(&self, parent_state: State) -> bool {
        // Unpack the signed block components
        let block = &self.message.block;
        let signatures = &self.signature;

        // Combine all attestations that need verification
        //
        // This creates a single list containing both:
        // 1. Block body attestations (from other validators)
        // 2. Proposer attestation (from the block producer)
        let mut all_attestations: Vec<Attestation> = Vec::new();

        // Collect block body attestations
        let mut i: u64 = 0;
        loop {
            match block.body.attestations.get(i) {
                Ok(a) => all_attestations.push(a.clone()),
                Err(_) => break,
            }
            i += 1;
        }

        // Append proposer attestation
        all_attestations.push(self.message.proposer_attestation.clone());

        // Collect signatures into a Vec
        let mut signatures_vec: Vec<Signature> = Vec::new();
        let mut j: u64 = 0;
        loop {
            match signatures.get(j) {
                Ok(s) => signatures_vec.push(s.clone()),
                Err(_) => break,
            }
            j += 1;
        }

        // Verify signature count matches attestation count
        //
        // Each attestation must have exactly one corresponding signature.
        //
        // The ordering must be preserved:
        // 1. Block body attestations,
        // 2. The proposer attestation.
        assert_eq!(
            signatures_vec.len(),
            all_attestations.len(),
            "Number of signatures does not match number of attestations"
        );

        let validators = &parent_state.validators;
        let num_validators = validators.len_u64();

        // Verify each attestation signature
        for (attestation, signature) in all_attestations.iter().zip(signatures_vec.iter()) {
            // Ensure validator exists in the active set
            assert!(
                attestation.validator_id.0 < num_validators,
                "Validator index out of range"
            );

            let validator = validators
                .get(attestation.validator_id.0)
                .expect("validator must exist");

            // Verify the XMSS signature
            //
            // This cryptographically proves that:
            // - The validator possesses the secret key for their public key
            // - The attestation has not been tampered with
            // - The signature was created at the correct epoch (slot)

            let message_bytes: [u8; 32] = hash_tree_root(attestation).0.into();

            assert!(
                verify_xmss_signature(
                    validator.pubkey.0.as_bytes(),
                    attestation.data.slot,
                    &message_bytes,
                    &signature,
                ),
                "Attestation signature verification failed"
            );
        }

        true
    }

    #[cfg(feature = "devnet2")]
    pub fn verify_signatures(&self, parent_state: State) -> bool {
        // Unpack the signed block components
        let block = &self.message.block;
        let signatures = &self.signature;
        let aggregated_attestations = block.body.attestations.clone();
        let attestation_signatures = signatures.attestation_signatures.clone();

        // Verify signature count matches aggregated attestation count
        assert_eq!(
            aggregated_attestations.len_u64(),
            attestation_signatures.len_u64(),
            "Number of signatures does not match number of attestations"
        );

        let validators = &parent_state.validators;
        let num_validators = validators.len_u64();

        // Verify each attestation signature
        for (aggregated_attestation, aggregated_signature) in (&aggregated_attestations)
            .into_iter()
            .zip((&attestation_signatures).into_iter())
        {
            let validator_ids = aggregated_attestation
                .aggregation_bits
                .to_validator_indices();

            assert_eq!(
                aggregated_signature.len_u64(),
                validator_ids.len() as u64,
                "Aggregated attestation signature count mismatch"
            );

            let attestation_root = aggregated_attestation.data.hash_tree_root();

            // Loop through zipped validator IDs and their corresponding signatures
            // Verify each individual signature within the aggregated attestation
            for (validator_id, signature) in
                validator_ids.iter().zip(aggregated_signature.into_iter())
            {
                // Ensure validator exists in the active set
                assert!(
                    *validator_id < num_validators,
                    "Validator index out of range"
                );

                let validator = validators.get(*validator_id).expect("validator must exist");

                // Get the actual payload root for the attestation data
                let attestation_root: [u8; 32] =
                    hash_tree_root(&aggregated_attestation.data).0.into();

                // Verify the XMSS signature
                assert!(
                    verify_xmss_signature(
                        validator.pubkey.0.as_bytes(),
                        aggregated_attestation.data.slot,
                        &attestation_root,
                        signature,
                    ),
                    "Attestation signature verification failed"
                );
            }

            // Verify the proposer attestation signature
            let proposer_attestation = self.message.proposer_attestation.clone();
            let proposer_signature = signatures.proposer_signature;

            assert!(
                proposer_attestation.validator_id.0 < num_validators,
                "Proposer index out of range"
            );

            let proposer = validators
                .get(proposer_attestation.validator_id.0)
                .expect("proposer must exist");

            let proposer_root: [u8; 32] = hash_tree_root(&proposer_attestation).0.into();
            assert!(
                verify_xmss_signature(
                    proposer.pubkey.0.as_bytes(),
                    proposer_attestation.data.slot,
                    &proposer_root,
                    &proposer_signature,
                ),
                "Proposer attestation signature verification failed"
            );
        }

        true
    }
}

#[cfg(feature = "xmss-verify")]
pub fn verify_xmss_signature(
    pubkey_bytes: &[u8],
    slot: Slot,
    message_bytes: &[u8; 32],
    signature: &Signature,
) -> bool {
    use leansig::serialization::Serializable;
    use leansig::signature::SignatureScheme;

    let epoch = slot.0 as u32;

    type PubKey = <SIGTargetSumLifetime20W2NoOff as SignatureScheme>::PublicKey;
    let pubkey = match PubKey::from_bytes(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    type Sig = <SIGTargetSumLifetime20W2NoOff as SignatureScheme>::Signature;
    let sig = match Sig::from_bytes(signature.as_bytes()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    SIGTargetSumLifetime20W2NoOff::verify(&pubkey, epoch, message_bytes, &sig)
}

#[cfg(not(feature = "xmss-verify"))]
pub fn verify_xmss_signature(
    _pubkey_bytes: &[u8],
    _slot: Slot,
    _message_bytes: &[u8; 32],
    _signature: &Signature,
) -> bool {
    true
}
