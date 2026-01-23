use crate::{Checkpoint, Slot, Uint64};
use leansig::serialization::Serializable;
use serde::{Deserialize, Serialize};
use ssz::BitList;
use ssz::ByteVector;
use ssz::{SszHash, H256};
use ssz_derive::Ssz;
use std::collections::HashSet;
use typenum::{Prod, Sum, U100, U1024, U12, U31};

// Type-level number for 1 MiB (1048576 = 1024 * 1024)
type U1048576 = Prod<U1024, U1024>;

pub type U3100 = Prod<U31, U100>;

// Type-level number for 3112 bytes
pub type U3112 = Sum<U3100, U12>;

// Type alias for Signature
pub type Signature = ByteVector<U3112>;

// Type-level number for 4096 (validator registry limit)
use typenum::U4096;

/// List of validator attestations included in a block (without signatures).
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
pub type Attestations = ssz::PersistentList<Attestation, U4096>;

pub type AggregatedAttestations = ssz::PersistentList<AggregatedAttestation, U4096>;

pub type AttestationSignatures = ssz::PersistentList<AggregatedSignatureProof, U4096>;

/// Legacy naive aggregated signature type (list of individual XMSS signatures).
/// Kept for backwards compatibility but no longer used in wire format.
pub type NaiveAggregatedSignature = ssz::PersistentList<Signature, U4096>;

/// Aggregated signature proof from lean-multisig zkVM.
///
/// This is a variable-length byte list (up to 1 MiB) containing the serialized
/// proof bytes from `xmss_aggregate_signatures()`. The `#[ssz(transparent)]`
/// attribute makes this type serialize directly as a ByteList for SSZ wire format.
#[derive(Clone, Debug, PartialEq, Eq, Default, Ssz, Serialize, Deserialize)]
#[ssz(transparent)]
pub struct MultisigAggregatedSignature(
    /// The serialized zkVM proof bytes from lean-multisig aggregation.
    #[serde(with = "crate::serde_helpers::byte_list")]
    pub ssz::ByteList<U1048576>,
);

impl MultisigAggregatedSignature {
    /// Create a new MultisigAggregatedSignature from proof bytes.
    pub fn new(proof: Vec<u8>) -> Result<Self, AggregationError> {
        ssz::ByteList::try_from(proof)
            .map(Self)
            .map_err(|_| AggregationError::AggregationFailed)
    }

    /// Get the proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Check if the signature is empty (no proof).
    pub fn is_empty(&self) -> bool {
        self.0.as_bytes().is_empty()
    }

    /// Aggregate individual XMSS signatures into a single proof.
    ///
    /// Uses lean-multisig zkVM to combine multiple signatures into a compact proof.
    ///
    /// # Arguments
    /// * `public_keys` - Public keys of the signers
    /// * `signatures` - Individual XMSS signatures to aggregate
    /// * `message` - The 32-byte message that was signed (as 8 field elements)
    /// * `epoch` - The epoch/slot in which signatures were created
    ///
    /// # Returns
    /// Aggregated signature proof, or error if aggregation fails.
    pub fn aggregate(
        public_keys: &[lean_multisig::XmssPublicKey],
        signatures: &[lean_multisig::XmssSignature],
        message: [lean_multisig::F; 8],
        epoch: u64,
    ) -> Result<Self, AggregationError> {
        if public_keys.is_empty() {
            return Err(AggregationError::EmptyInput);
        }
        if public_keys.len() != signatures.len() {
            return Err(AggregationError::MismatchedLengths);
        }

        let proof_bytes =
            lean_multisig::xmss_aggregate_signatures(public_keys, signatures, message, epoch)
                .map_err(|_| AggregationError::AggregationFailed)?;

        Self::new(proof_bytes)
    }

    /// Verify the aggregated signature proof against the given public keys and message.
    ///
    /// Uses lean-multisig zkVM to verify that the aggregated proof is valid
    /// for all the given public keys signing the same message at the given epoch.
    ///
    /// # Returns
    /// `Ok(())` if the proof is valid, `Err` with the proof error otherwise.
    pub fn verify(
        &self,
        public_keys: &[lean_multisig::XmssPublicKey],
        message: [lean_multisig::F; 8],
        epoch: u64,
    ) -> Result<(), AggregationError> {
        lean_multisig::xmss_verify_aggregated_signatures(
            public_keys,
            message,
            self.0.as_bytes(),
            epoch,
        )
        .map_err(|_| AggregationError::VerificationFailed)
    }

    /// Verify the aggregated payload against validators and message.
    ///
    /// This is a convenience method that extracts public keys from validators
    /// and converts the message bytes to the field element format expected by lean-multisig.
    ///
    /// # Arguments
    /// * `validators` - Slice of validator references to extract public keys from
    /// * `message` - 32-byte message (typically attestation data root)
    /// * `epoch` - Epoch/slot for proof verification
    ///
    /// # Returns
    /// `Ok(())` if verification succeeds, `Err` otherwise.
    pub fn verify_aggregated_payload(
        &self,
        validators: &[&crate::validator::Validator],
        message: &[u8; 32],
        epoch: u64,
    ) -> Result<(), AggregationError> {
        // Extract public keys from validators
        let mut public_keys = Vec::new();
        for validator in validators {
            // Convert PublicKey to lean_multisig::XmssPublicKey
            let lean_sig_pk = validator
                .pubkey
                .as_lean_sig()
                .map_err(|_| AggregationError::VerificationFailed)?;
            let pk_bytes = lean_sig_pk.to_bytes();
            // TODO: Implement proper conversion from PublicKey bytes to lean_multisig::XmssPublicKey
            // Once lean-multisig API is clarified, convert pk_bytes to XmssPublicKey
            todo!("Convert PublicKey to lean_multisig::XmssPublicKey and implement message field conversion");
        }

        // Convert 32-byte message to 8 field elements
        // TODO: Implement proper conversion from 32 bytes to 8 field elements
        let message_fields = todo!("Convert 32-byte message to [lean_multisig::F; 8]");

        // Call verify with extracted keys and converted message
        self.verify(&public_keys, message_fields, epoch)
    }
}

/// Error types for signature aggregation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregationError {
    /// No signatures provided for aggregation.
    EmptyInput,
    /// Public keys and signatures arrays have different lengths.
    MismatchedLengths,
    /// Aggregation failed in lean-multisig.
    AggregationFailed,
    /// Verification of aggregated proof failed.
    VerificationFailed,
}

/// Aggregated signature proof with participant tracking.
///
/// This type combines the participant bitfield with the proof bytes,
/// matches Python's `AggregatedSignatureProof` container structure.
/// Used in `aggregated_payloads` to track which validators are covered by each proof.
#[derive(Clone, Debug, PartialEq, Eq, Default, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatedSignatureProof {
    /// Bitfield indicating which validators' signatures are included.
    pub participants: AggregationBits,
    /// The raw aggregated proof bytes from lean-multisig.
    pub proof_data: MultisigAggregatedSignature,
}

impl AggregatedSignatureProof {
    /// Create a new AggregatedSignatureProof.
    pub fn new(participants: AggregationBits, proof_data: MultisigAggregatedSignature) -> Self {
        Self {
            participants,
            proof_data,
        }
    }

    pub fn from_aggregation(participant_ids: &[u64], proof: MultisigAggregatedSignature) -> Self {
        Self {
            participants: AggregationBits::from_validator_indices(participant_ids),
            proof_data: proof,
        }
    }

    /// Get the validator indices covered by this proof.
    pub fn get_participant_indices(&self) -> Vec<u64> {
        self.participants.to_validator_indices()
    }
}

/// Bitlist representing validator participation in an attestation.
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
#[derive(Clone, Debug, PartialEq, Eq, Default, Ssz, Serialize, Deserialize)]
pub struct AggregationBits(#[serde(with = "crate::serde_helpers::bitlist")] pub BitList<U4096>);

impl AggregationBits {
    pub const LIMIT: u64 = 4096;

    pub fn from_validator_indices(indices: &[u64]) -> Self {
        assert!(
            !indices.is_empty(),
            "Aggregated attestation must reference at least one validator"
        );

        let max_id = *indices.iter().max().unwrap();
        assert!(
            max_id < Self::LIMIT,
            "Validator index out of range for aggregation bits"
        );

        let mut bits = BitList::<U4096>::with_length((max_id + 1) as usize);

        for i in 0..=max_id {
            bits.set(i as usize, false);
        }

        for &i in indices {
            bits.set(i as usize, true);
        }

        AggregationBits(bits)
    }

    pub fn to_validator_indices(&self) -> Vec<u64> {
        let indices: Vec<u64> = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, bit)| if *bit { Some(i as u64) } else { None })
            .collect();

        assert!(
            !indices.is_empty(),
            "Aggregated attestation must reference at least one validator"
        );

        indices
    }
}

/// Naive list of validator signatures used for aggregation placeholders.
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
pub type AggregatedSignatures = ssz::PersistentList<Signature, U4096>;

/// Attestation content describing the validator's observed chain view.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct AttestationData {
    /// The slot for which the attestation is made.
    pub slot: Slot,
    /// The checkpoint representing the head block as observed by the validator.
    pub head: Checkpoint,
    /// The checkpoint representing the target block as observed by the validator.
    pub target: Checkpoint,
    /// The checkpoint representing the source block as observed by the validator.
    pub source: Checkpoint,
}

impl AttestationData {
    /// Compute the data root bytes for signature lookup.
    /// This is the hash tree root of the attestation data.
    pub fn data_root_bytes(&self) -> crate::Bytes32 {
        crate::Bytes32(ssz::SszHash::hash_tree_root(self))
    }
}

/// Key for looking up individual validator signatures.
/// Used to index signature caches by (validator, attestation_data_root) pairs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignatureKey {
    /// The validator who produced the signature.
    pub validator_id: u64,
    /// The hash of the signed attestation data.
    pub data_root: crate::Bytes32,
}

impl SignatureKey {
    /// Create a new signature key.
    pub fn new(validator_id: u64, data_root: crate::Bytes32) -> Self {
        Self {
            validator_id,
            data_root,
        }
    }
}

/// Validator specific attestation wrapping shared attestation data.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The index of the validator making the attestation.
    pub validator_id: Uint64,
    /// The attestation data produced by the validator.
    pub data: AttestationData,
}

/// Validator attestation bundled with its signature.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub validator_id: u64,
    pub message: AttestationData,
    pub signature: Signature,
}

/// Aggregated attestation consisting of participation bits and message.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatedAttestation {
    /// Bitfield indicating which validators participated in the aggregation.
    pub aggregation_bits: AggregationBits,
    /// Combined attestation data similar to the beacon chain format.
    ///
    /// Multiple validator attestations are aggregated here without the complexity of
    /// committee assignments.
    pub data: AttestationData,
}

impl AggregatedAttestation {
    pub fn aggregate_by_data(attestations: &[Attestation]) -> Vec<AggregatedAttestation> {
        let mut groups: Vec<(AttestationData, Vec<u64>)> = Vec::new();

        for attestation in attestations {
            // Try to find an existing group with the same data
            if let Some((_, validator_ids)) = groups
                .iter_mut()
                .find(|(data, _)| *data == attestation.data)
            {
                validator_ids.push(attestation.validator_id.0);
            } else {
                // Create a new group
                groups.push((attestation.data.clone(), vec![attestation.validator_id.0]));
            }
        }

        groups
            .into_iter()
            .map(|(data, validator_ids)| AggregatedAttestation {
                aggregation_bits: AggregationBits::from_validator_indices(&validator_ids),
                data,
            })
            .collect()
    }

    /// Returns true if the provided list contains duplicate AttestationData.
    pub fn has_duplicate_data(attestations: &AggregatedAttestations) -> bool {
        let mut seen: HashSet<H256> = HashSet::new();
        for attestation in attestations {
            let root = attestation.data.hash_tree_root();
            if !seen.insert(root) {
                return true;
            }
        }
        false
    }
}

/// Aggregated attestation bundled with aggregated signatures.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct SignedAggregatedAttestation {
    /// Aggregated attestation data.
    pub message: AggregatedAttestation,
    /// Aggregated attestation plus its combined signature.
    ///
    /// Stores a naive list of validator signatures that mirrors the attestation
    /// order.
    ///
    /// TODO: this will be replaced by a SNARK in future devnets.
    pub signature: AggregatedSignatures,
}
