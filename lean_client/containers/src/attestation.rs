use crate::{Checkpoint, Slot, Uint64};
use serde::{Deserialize, Serialize};
use ssz::ByteVector;
use ssz_derive::Ssz;
use serde::{Deserialize, Serialize};
use typenum::{Prod, Sum, U100, U31, U12};

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

/// List of signatures corresponding to attestations in a block.
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
pub type BlockSignatures = ssz::PersistentList<Signature, U4096>;

/// Bitlist representing validator participation in an attestation.
/// Limit is VALIDATOR_REGISTRY_LIMIT (4096).
pub type AggregationBits = ssz::BitList<U4096>;

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
pub struct Attestation {
    /// The index of the validator making the attestation.
    pub validator_id: Uint64,
    /// The attestation data produced by the validator.
    pub data: AttestationData,
}

/// Validator attestation bundled with its signature.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The attestation message signed by the validator.
    pub message: Attestation,
    /// Signature aggregation produced by the leanVM (SNARKs in the future).
    pub signature: Signature,
}

/// Aggregated attestation consisting of participation bits and message.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct AggregatedAttestations {
    /// Bitfield indicating which validators participated in the aggregation.
    pub aggregation_bits: AggregationBits,
    /// Combined attestation data similar to the beacon chain format.
    ///
    /// Multiple validator attestations are aggregated here without the complexity of
    /// committee assignments.
    pub data: AttestationData,
}

/// Aggregated attestation bundled with aggregated signatures.
#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct SignedAggregatedAttestations {
    /// Aggregated attestation data.
    pub message: AggregatedAttestations,
    /// Aggregated attestation plus its combined signature.
    ///
    /// Stores a naive list of validator signatures that mirrors the attestation
    /// order.
    ///
    /// TODO: this will be replaced by a SNARK in future devnets.
    pub signature: AggregatedSignatures,
}
