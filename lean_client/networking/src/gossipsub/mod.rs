pub mod config;
pub mod message;
pub mod topic;

use crate::compressor::Compressor;
use libp2p::gossipsub::{AllowAllSubscriptionFilter, Behaviour};

pub type GossipsubBehaviour = Behaviour<Compressor, AllowAllSubscriptionFilter>;
