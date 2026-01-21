pub mod config;
pub mod topic;

#[cfg(test)]
mod tests;

use crate::compressor::Compressor;
use libp2p::gossipsub::{AllowAllSubscriptionFilter, Behaviour};

pub type GossipsubBehaviour = Behaviour<Compressor, AllowAllSubscriptionFilter>;

// Re-export commonly used types
pub use config::{GossipsubConfig, GossipsubParameters, compute_message_id};
pub use topic::{
    ATTESTATION_TOPIC, BLOCK_TOPIC, GossipsubKind, GossipsubTopic, SSZ_SNAPPY_ENCODING_POSTFIX,
    TOPIC_PREFIX, format_topic_string, get_topics, parse_topic_string,
};
