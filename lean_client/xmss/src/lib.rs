// Enables the `bls/blst` backend feature for this crate's dependency subgraph
// (grandine `types` needs a backend selected even in solo `-p xmss` builds).
use bls as _;

mod aggregated_signature;
mod multi_message;
mod public_key;
mod secret_key;
mod signature;

#[cfg(shadow_mode)]
pub mod shadow_cost;

pub use aggregated_signature::{AggregatedSignature, set_prover_arena, setup_aggregation};
pub use multi_message::MultiMessageAggregate;
pub use public_key::PublicKey;
pub use secret_key::SecretKey;
pub use signature::Signature;
