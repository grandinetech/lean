// tests/unit_tests/mod.rs

// Modules that work with both devnet1 and devnet2
mod attestation_aggregation;
mod state_basic;
mod state_justifications;

// TODO: Update these modules for devnet2 data structures
// (SignedAttestation now uses AttestationData directly, BlockSignatures changed, etc.)
mod common;
mod state_process;
mod state_transition;
mod attestation_aggregation;
