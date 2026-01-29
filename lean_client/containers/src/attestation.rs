use anyhow::Result;
use serde::{Deserialize, Serialize};
use ssz::{BitList, H256, PersistentList, Ssz, SszHash};
use std::collections::HashSet;
use typenum::{U4096, Unsigned as _};
use xmss::{AggregatedSignature, PublicKey, Signature};

use crate::{Checkpoint, Slot, validator::ValidatorRegistryLimit};

/// List of validator attestations included in a block (without signatures).
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
pub type Attestations = PersistentList<Attestation, ValidatorRegistryLimit>;

pub type AggregatedAttestations = PersistentList<AggregatedAttestation, ValidatorRegistryLimit>;

pub type AttestationSignatures = PersistentList<AggregatedSignatureProof, ValidatorRegistryLimit>;

/// Aggregated signature proof with participant tracking.
///
/// This type combines the participant bitfield with the proof bytes,
/// matches Python's `AggregatedSignatureProof` container structure.
/// Used in `aggregated_payloads` to track which validators are covered by each proof.
#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatedSignatureProof {
    /// Bitfield indicating which validators' signatures are included.
    participants: AggregationBits,
    /// The raw aggregated proof bytes from lean-multisig.
    pub proof_data: AggregatedSignature,
}

impl AggregatedSignatureProof {
    pub fn aggregate(
        participants: AggregationBits,
        public_keys: impl IntoIterator<Item = PublicKey>,
        signatures: impl IntoIterator<Item = Signature>,
        message: H256,
        epoch: u32,
    ) -> Result<Self> {
        Ok(Self {
            participants,
            proof_data: AggregatedSignature::aggregate(public_keys, signatures, message, epoch)?,
        })
    }

    /// Get the validator indices covered by this proof.
    pub fn get_participant_indices(&self) -> Vec<u64> {
        self.participants.to_validator_indices()
    }

    pub fn verify(
        &self,
        public_keys: impl IntoIterator<Item = PublicKey>,
        message: H256,
        epoch: u32,
    ) -> Result<()> {
        self.proof_data.verify(public_keys, message, epoch)
    }
}

/// Bitlist representing validator participation in an attestation.
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
pub struct AggregationBits(
    #[serde(with = "crate::serde_helpers::bitlist")] pub BitList<ValidatorRegistryLimit>,
);

impl AggregationBits {
    pub const LIMIT: u64 = ValidatorRegistryLimit::U64;

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
///
/// todo(containers): default implementation doesn't make sense here
#[derive(Clone, Debug, Ssz, PartialEq, Eq, Default, Serialize, Deserialize)]
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

/// Key for looking up individual validator signatures.
/// Used to index signature caches by (validator, attestation_data_root) pairs.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct SignatureKey {
    /// The validator who produced the signature.
    pub validator_id: u64,
    /// The hash of the signed attestation data.
    pub data_root: H256,
}

impl SignatureKey {
    /// Create a new signature key.
    pub fn new(validator_id: u64, data_root: H256) -> Self {
        Self {
            validator_id,
            data_root,
        }
    }
}

/// Validator specific attestation wrapping shared attestation data.
///
/// todo(containers): default implementation doesn't make sense here
#[derive(Clone, Debug, Ssz, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The index of the validator making the attestation.
    pub validator_id: u64,
    /// The attestation data produced by the validator.
    pub data: AttestationData,
}

/// Validator attestation bundled with its signature.
#[derive(Clone, Debug, Ssz)]
pub struct SignedAttestation {
    pub validator_id: u64,
    pub message: AttestationData,
    pub signature: Signature,
}

/// Aggregated attestation consisting of participation bits and message.
#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
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
                validator_ids.push(attestation.validator_id);
            } else {
                // Create a new group
                groups.push((attestation.data.clone(), vec![attestation.validator_id]));
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
#[derive(Clone, Debug, Ssz)]
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
