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
        let justification_lookback_slots: u64 = 3;
        let seconds_per_slot: u64 = 4;

        let seen_ttl_secs = seconds_per_slot * justification_lookback_slots * 2;

        let config = ConfigBuilder::default()
            // for now, increased to 16 mb. in the future, should be handled in config
            // TODO(p2p): compute transmit size
            .max_transmit_size(16 * 1024 * 1024)
            // leanSpec: heartbeat_interval_secs = 0.7
            .heartbeat_interval(Duration::from_millis(700))
            // leanSpec: fanout_ttl_secs = 60
            .fanout_ttl(Duration::from_secs(60))
            // leanSpec: mcache_len = 6
            .history_length(6)
            // leanSpec: mcache_gossip = 3
            .history_gossip(3)
            // leanSpec: seen_ttl_secs = SECONDS_PER_SLOT * JUSTIFICATION_LOOKBACK_SLOTS * 2
            .duplicate_cache_time(Duration::from_secs(seen_ttl_secs))
            // leanSpec: d = 8
            .mesh_n(8)
            // leanSpec: d_low = 6
            .mesh_n_low(6)
            // leanSpec: d_high = 12
            .mesh_n_high(12)
            // leanSpec: d_lazy = 6
            .gossip_lazy(6)
            .validation_mode(ValidationMode::Anonymous)
            .validate_messages()
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

/// Computes the message ID according to leanSpec:
/// SHA256(domain + uint64_le(len(topic)) + topic + message_data)[:20]
pub fn compute_message_id(message: &Message) -> MessageId {
    let topic_bytes = message.topic.as_str().as_bytes();
    let topic_len = topic_bytes.len() as u64;

    let mut digest_input = Vec::new();
    // Domain: 1 byte
    digest_input.extend_from_slice(MESSAGE_DOMAIN_VALID_SNAPPY);
    // Topic length: 8 bytes (uint64 little-endian)
    digest_input.extend_from_slice(&topic_len.to_le_bytes());
    // Topic bytes
    digest_input.extend_from_slice(topic_bytes);
    // Message data
    digest_input.extend_from_slice(&message.data);

    let hash = Sha256::digest(&digest_input);

    // Return first 20 bytes
    MessageId::from(&hash[..20])
}
