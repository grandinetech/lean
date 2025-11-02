use crate::gossipsub::topic::GossipsubTopic;
use crate::types::MESSAGE_DOMAIN_VALID_SNAPPY;
use libp2p::gossipsub::{Config, ConfigBuilder, Message, MessageId, ValidationMode};
use sha2::Digest;
use sha2::Sha256;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GossipsubConfig {
    pub config: Config,
    pub topics: Vec<GossipsubTopic>,
}

impl GossipsubConfig {
    pub fn new() -> Self {
        let justification_lookback_slots = 3; // TODO: load
        let seconds_per_slot = 12; // TODO: load
        let config = ConfigBuilder::default()
            .fanout_ttl(Duration::from_secs(60))
            .history_length(5) // = mcache_len
            .history_gossip(3) // = mcache_gossip
            .duplicate_cache_time(Duration::from_secs(120)) // seen_ttl
            .mesh_n(6) // D
            .mesh_n_low(4) // D_low
            .mesh_n_high(12) // D_high
            .gossip_lazy(6) // D_lazy
            .duplicate_cache_time(Duration::from_secs(
                justification_lookback_slots * seconds_per_slot * 2,
            ))
            .validate_messages()
            .validation_mode(ValidationMode::Anonymous)
            .message_id_fn(compute_message_id)
            .build()
            .expect("Failed to build gossipsub config");

        GossipsubConfig {
            config,
            topics: Vec::new(),
        }
    }

    pub fn set_topics(&mut self, topics: Vec<GossipsubTopic>) {
        self.topics = topics;
    }
}

pub fn compute_message_id(message: &Message) -> MessageId {
    let topic_bytes = message.topic.as_str().as_bytes();

    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(MESSAGE_DOMAIN_VALID_SNAPPY.as_bytes());
    digest_input.extend_from_slice(&(topic_bytes.len()).to_le_bytes());
    digest_input.extend_from_slice(topic_bytes);
    digest_input.extend_from_slice(&message.data);

    let hash = Sha256::digest(&digest_input);

    MessageId::from(&hash[..20])
}
