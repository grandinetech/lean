// tests/unit_tests/mod.rs

// Modules that work with both devnet1 and devnet2
mod state_basic;
mod state_justifications;
mod attestation_aggregation;

// Modules that are only compatible with devnet1 format
#[cfg(not(feature = "devnet2"))]
mod common;
#[cfg(not(feature = "devnet2"))]
mod state_process;
#[cfg(not(feature = "devnet2"))]
mod state_transition;
