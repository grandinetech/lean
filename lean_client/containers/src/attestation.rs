use crate::{Checkpoint, Slot, Uint64};
use serde::{Deserialize, Serialize};
use ssz::BitList;
use ssz::ByteVector;
use ssz_derive::Ssz;
use typenum::{Prod, Sum, U100, U12, U31};

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

#[cfg(feature = "devnet1")]
pub type AttestationSignatures = ssz::PersistentList<SignedAttestation, U4096>;

#[cfg(feature = "devnet2")]
pub type AttestationSignatures = ssz::PersistentList<NaiveAggregatedSignature, U4096>;

#[cfg(feature = "devnet2")]
pub type NaiveAggregatedSignature = ssz::PersistentList<Signature, U4096>;

/// Bitlist representing validator participation in an attestation.
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
#[derive(Clone, Debug, PartialEq, Eq, Default, Ssz, Serialize, Deserialize)]
pub struct AggregationBits(pub BitList<U4096>);

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
    pub message: Attestation,
    /// Signature aggregation produced by the leanVM (SNARKs in the future).
    pub signature: Signature,
}

/// Aggregated attestation consisting of participation bits and message.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
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

    pub fn to_plain(&self) -> Vec<Attestation> {
        let validator_indices = self.aggregation_bits.to_validator_indices();

        validator_indices
            .into_iter()
            .map(|validator_id| Attestation {
                validator_id: Uint64(validator_id),
                data: self.data.clone(),
            })
            .collect()
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
