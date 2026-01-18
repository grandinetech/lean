pub mod config;
pub mod control;
pub mod mcache;
pub mod mesh;
pub mod message;
pub mod topic;
pub mod types;

#[cfg(test)]
mod tests;

use crate::compressor::Compressor;
use libp2p::gossipsub::{AllowAllSubscriptionFilter, Behaviour};

pub type GossipsubBehaviour = Behaviour<Compressor, AllowAllSubscriptionFilter>;

// Re-export commonly used types
pub use config::{GossipsubConfig, GossipsubParameters};
pub use control::{ControlMessage, Graft, IDontWant, IHave, IWant, Prune};
pub use mcache::{CacheEntry, MessageCache, SeenCache};
pub use mesh::{FanoutEntry, MeshState, TopicMesh};
pub use message::{GossipsubMessage, RawGossipsubMessage, SnappyDecompressor};
pub use topic::{
    format_topic_string, get_topics, parse_topic_string, GossipsubKind, GossipsubTopic,
    ATTESTATION_TOPIC, BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX, TOPIC_PREFIX,
};
pub use types::{MessageId, PeerId, Timestamp, TopicId};
