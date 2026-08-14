use anyhow::Result;
use ssz::{BitList, H256, PersistentList, Ssz, SszHash};
use std::collections::HashSet;
use typenum::{U4096, Unsigned as _};
use xmss::{AggregatedSignature, PublicKey, Signature};

use crate::{Checkpoint, Slot, validator::ValidatorRegistryLimit};

/// List of validator attestations included in a block (without signatures).
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
pub type Attestations = PersistentList<Attestation, ValidatorRegistryLimit>;

pub type AggregatedAttestations = PersistentList<AggregatedAttestation, ValidatorRegistryLimit>;

/// Aggregated signature proof with participant tracking.
///
/// Combines the participant bitfield with the proof bytes.
/// Used in `aggregated_payloads` to track which validators are covered by each proof.
#[derive(Clone, Debug, Ssz)]
pub struct AggregatedSignatureProof {
    /// Bitfield indicating which validators' signatures are included.
    pub participants: AggregationBits,
    /// The raw aggregated proof bytes (lz4+postcard serialized AggregatedXMSS).
    pub proof_data: AggregatedSignature,
}

impl AggregatedSignatureProof {
    pub fn aggregate(
        participants: AggregationBits,
        public_keys: impl IntoIterator<Item = PublicKey>,
        signatures: impl IntoIterator<Item = Signature>,
        message: H256,
        slot: u32,
        log_inv_rate: usize,
    ) -> Result<Self> {
        Ok(Self {
            participants,
            proof_data: AggregatedSignature::aggregate(
                public_keys,
                signatures,
                message,
                slot,
                log_inv_rate,
            )?,
        })
    }

    /// Aggregate with optional recursive child proofs for proof compaction.
    ///
    /// `children` is a list of `(public_keys_covered, child_proof)` pairs where
    /// each child proof previously aggregated the listed keys.
    pub fn aggregate_with_children(
        participants: AggregationBits,
        children: &[(&[PublicKey], &AggregatedSignatureProof)],
        public_keys: impl IntoIterator<Item = PublicKey>,
        signatures: impl IntoIterator<Item = Signature>,
        message: H256,
        slot: u32,
        log_inv_rate: usize,
    ) -> Result<Self> {
        let xmss_children: Vec<(&[PublicKey], &AggregatedSignature)> = children
            .iter()
            .map(|(pks, proof)| (*pks, &proof.proof_data))
            .collect();
        Ok(Self {
            participants,
            proof_data: AggregatedSignature::aggregate_with_children(
                &xmss_children,
                public_keys,
                signatures,
                message,
                slot,
                log_inv_rate,
            )?,
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
        slot: u32,
    ) -> Result<()> {
        self.proof_data.verify(public_keys, message, slot)
    }

    /// Greedy set-cover over a slice of proofs, returning indices of the proofs
    /// to admit in priority order. Repeatedly picks the proof covering the
    /// most uncovered validators; stops when no remaining proof adds coverage.
    /// Mirrors leanSpec `AggregatedSignatureProof.select_greedily`.
    pub fn select_greedily(proofs: &[AggregatedSignatureProof]) -> Vec<usize> {
        let mut selected: Vec<usize> = Vec::new();
        let mut covered: HashSet<u64> = HashSet::new();
        let mut remaining: HashSet<usize> = (0..proofs.len()).collect();

        while !remaining.is_empty() {
            let best = remaining
                .iter()
                .copied()
                .map(|idx| {
                    let new_count = proofs[idx]
                        .get_participant_indices()
                        .into_iter()
                        .filter(|vid| !covered.contains(vid))
                        .count();
                    (idx, new_count)
                })
                .max_by_key(|(_, n)| *n);

            let Some((best_idx, best_count)) = best else {
                break;
            };
            if best_count == 0 {
                break;
            }

            for vid in proofs[best_idx].get_participant_indices() {
                covered.insert(vid);
            }
            selected.push(best_idx);
            remaining.remove(&best_idx);
        }

        selected
    }
}

/// Bitlist representing validator participation in an attestation.
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
#[derive(Clone, Debug, Ssz)]
#[ssz(transparent)]
pub struct AggregationBits(pub BitList<ValidatorRegistryLimit>);

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

        indices
    }
}

/// Naive list of validator signatures used for aggregation placeholders.
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
pub type AggregatedSignatures = ssz::PersistentList<Signature, U4096>;

/// Attestation content describing the validator's observed chain view.
///
/// todo(containers): default implementation doesn't make sense here
#[derive(Clone, Debug, Ssz, PartialEq, Eq, Default)]
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
#[derive(Clone, Debug, Ssz, Default, PartialEq, Eq)]
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
#[derive(Clone, Debug, Ssz)]
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

/// Aggregated attestation bundled with aggregated signature proof.
#[derive(Clone, Debug, Ssz)]
pub struct SignedAggregatedAttestation {
    /// The attestation data being attested to.
    pub data: AttestationData,
    /// The aggregated signature proof covering all participants.
    pub proof: AggregatedSignatureProof,
}
