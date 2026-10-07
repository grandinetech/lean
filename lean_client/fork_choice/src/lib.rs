pub mod block_cache;
pub mod handlers;
pub mod proto;
pub mod reaggregate;
pub mod store;
pub mod sync_state;

// The bls crate requires exactly one backend feature to be enabled; without it
// compilation fails. Force-include it here with a feature enabled so the
// dependency tree resolves correctly.
use bls as _;
