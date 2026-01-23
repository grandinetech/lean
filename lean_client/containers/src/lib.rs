pub mod attestation;
pub mod block;
pub mod checkpoint;
pub mod config;
pub mod public_key;
pub mod serde_helpers;
pub mod signature;
pub mod slot;
pub mod state;
pub mod status;
pub mod types;
pub mod validator;

pub use attestation::{
    AggregatedAttestation, AggregatedSignatures, AggregationBits, Attestation, AttestationData,
    Attestations, Signature, SignatureKey, SignedAggregatedAttestation, SignedAttestation,
};

pub use attestation::{AggregatedSignatureProof, MultisigAggregatedSignature};
pub use block::{
    Block, BlockBody, BlockHeader, BlockWithAttestation, SignedBlock, SignedBlockWithAttestation,
};
pub use checkpoint::Checkpoint;
pub use config::{Config, GenesisConfig};
pub use slot::Slot;
pub use state::State;
pub use status::Status;
pub use types::{
    Bytes32, HistoricalBlockHashes, JustificationRoots, JustificationsValidators, JustifiedSlots,
    Uint64, ValidatorIndex, Validators,
};

pub use types::Bytes32 as Root;
// Re-export grandine ssz so tests can reference it if needed
pub use ssz;
