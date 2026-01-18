/// Gossipsub Parameters
///
/// Configuration parameters controlling gossipsub mesh behavior.
///
/// ## Overview
///
/// Gossipsub maintains a mesh of peers for each subscribed topic.
/// These parameters tune the mesh size, timing, and caching behavior.
///
/// ## Parameter Categories
///
/// **Mesh Degree (D parameters):**
///
/// Controls how many peers are in the mesh for each topic.
///
/// ```text
/// D_low <= D <= D_high
///
/// D       Target mesh size (8 for Ethereum)
/// D_low   Minimum before grafting new peers (6)
/// D_high  Maximum before pruning excess peers (12)
/// D_lazy  Peers to gossip IHAVE messages to (6)
/// ```
///
/// **Timing:**
///
/// ```text
/// heartbeat_interval   Mesh maintenance frequency (0.7s for Ethereum)
/// fanout_ttl           How long to keep fanout peers (60s)
/// ```
///
/// **Caching:**
///
/// ```text
/// mcache_len      Total history windows kept (6)
/// mcache_gossip   Windows included in IHAVE gossip (3)
/// seen_ttl        Duplicate detection window
/// ```
///
/// ## Ethereum Values
///
/// The Ethereum consensus layer specifies:
///
/// - D = 8, D_low = 6, D_high = 12, D_lazy = 6
/// - Heartbeat = 700ms (0.7s)
/// - Message cache = 6 windows, gossip last 3
///
/// ## References
///
/// - Ethereum P2P spec: <https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md>
/// - Gossipsub v1.0: <https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md>
/// - Gossipsub v1.2: <https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.2.md>

use crate::gossipsub::topic::GossipsubTopic;
use crate::types::MESSAGE_DOMAIN_VALID_SNAPPY;
use libp2p::gossipsub::{Config, ConfigBuilder, Message, MessageId, ValidationMode};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::time::Duration;

/// Core gossipsub configuration.
///
/// Defines the mesh topology and timing parameters.
///
/// Default values follow the Ethereum consensus P2P specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipsubParameters {
    /// The protocol ID for gossip messages.
    #[serde(default = "default_protocol_id")]
    pub protocol_id: String,
    
    // -------------------------------------------------------------------------
    // Mesh Degree Parameters
    // -------------------------------------------------------------------------
    
    /// Target number of mesh peers per topic.
    ///
    /// The heartbeat procedure adjusts the mesh toward this size:
    ///
    /// - If |mesh| < D_low: graft peers up to D
    /// - If |mesh| > D_high: prune peers down to D
    #[serde(default = "default_d")]
    pub d: usize,
    
    /// Minimum mesh peers before grafting.
    ///
    /// When mesh size drops below this threshold, the heartbeat
    /// will graft new peers to reach the target D.
    #[serde(default = "default_d_low")]
    pub d_low: usize,
    
    /// Maximum mesh peers before pruning.
    ///
    /// When mesh size exceeds this threshold, the heartbeat
    /// will prune excess peers down to the target D.
    #[serde(default = "default_d_high")]
    pub d_high: usize,
    
    /// Number of non-mesh peers for IHAVE gossip.
    ///
    /// During heartbeat, IHAVE messages are sent to this many
    /// randomly selected peers outside the mesh. This enables
    /// the lazy pull protocol for reliability.
    #[serde(default = "default_d_lazy")]
    pub d_lazy: usize,
    
    // -------------------------------------------------------------------------
    // Timing Parameters
    // -------------------------------------------------------------------------
    
    /// Interval between heartbeat ticks in seconds.
    ///
    /// The heartbeat procedure runs periodically to:
    ///
    /// - Maintain mesh size (graft/prune)
    /// - Send IHAVE gossip to non-mesh peers
    /// - Clean up stale fanout entries
    /// - Shift the message cache window
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: f64,
    
    /// Time-to-live for fanout entries in seconds.
    ///
    /// Fanout peers are used when publishing to topics we don't
    /// subscribe to. Entries expire after this duration of
    /// inactivity to free resources.
    #[serde(default = "default_fanout_ttl_secs")]
    pub fanout_ttl_secs: u64,
    
    // -------------------------------------------------------------------------
    // Message Cache Parameters
    // -------------------------------------------------------------------------
    
    /// Total number of history windows in the message cache.
    ///
    /// - Messages are stored for this many heartbeat intervals.
    /// - After mcache_len heartbeats, messages are evicted.
    #[serde(default = "default_mcache_len")]
    pub mcache_len: usize,
    
    /// Number of recent windows included in IHAVE gossip.
    ///
    /// Only messages from the most recent mcache_gossip windows
    /// are advertised via IHAVE. Older cached messages can still
    /// be retrieved via IWANT but won't be actively gossiped.
    #[serde(default = "default_mcache_gossip")]
    pub mcache_gossip: usize,
    
    /// Time-to-live for seen message IDs in seconds.
    ///
    /// Message IDs are tracked to detect duplicates. This should
    /// be long enough to cover network propagation delays but
    /// short enough to bound memory usage.
    #[serde(default = "default_seen_ttl_secs")]
    pub seen_ttl_secs: u64,
    
    // -------------------------------------------------------------------------
    // IDONTWANT Optimization (v1.2)
    // -------------------------------------------------------------------------
    
    /// Minimum message size in bytes to trigger IDONTWANT.
    ///
    /// When receiving a message larger than this threshold,
    /// immediately send IDONTWANT to mesh peers to prevent
    /// redundant transmissions.
    ///
    /// Set to 1KB by default.
    #[serde(default = "default_idontwant_threshold")]
    pub idontwant_message_size_threshold: usize,
}

fn default_protocol_id() -> String {
    "/meshsub/1.3.0".to_string()
}

fn default_d() -> usize {
    8
}

fn default_d_low() -> usize {
    6
}

fn default_d_high() -> usize {
    12
}

fn default_d_lazy() -> usize {
    6
}

fn default_heartbeat_interval_secs() -> f64 {
    0.7
}

fn default_fanout_ttl_secs() -> u64 {
    60
}

fn default_mcache_len() -> usize {
    6
}

fn default_mcache_gossip() -> usize {
    3
}

fn default_seen_ttl_secs() -> u64 {
    let justification_lookback_slots: u64 = 3;
    let seconds_per_slot: u64 = 12;
    seconds_per_slot * justification_lookback_slots * 2
}

fn default_idontwant_threshold() -> usize {
    1000
}

impl Default for GossipsubParameters {
    fn default() -> Self {
        Self {
            protocol_id: default_protocol_id(),
            d: default_d(),
            d_low: default_d_low(),
            d_high: default_d_high(),
            d_lazy: default_d_lazy(),
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            fanout_ttl_secs: default_fanout_ttl_secs(),
            mcache_len: default_mcache_len(),
            mcache_gossip: default_mcache_gossip(),
            seen_ttl_secs: default_seen_ttl_secs(),
            idontwant_message_size_threshold: default_idontwant_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GossipsubConfig {
    pub config: Config,
    pub topics: Vec<GossipsubTopic>,
}

impl GossipsubConfig {
    pub fn new() -> Self {
        let params = GossipsubParameters::default();
        
        let config = ConfigBuilder::default()
            // leanSpec: heartbeat_interval_secs = 0.7
            .heartbeat_interval(Duration::from_millis(700))
            // leanSpec: fanout_ttl_secs = 60
            .fanout_ttl(Duration::from_secs(params.fanout_ttl_secs))
            // leanSpec: mcache_len = 6
            .history_length(params.mcache_len)
            // leanSpec: mcache_gossip = 3
            .history_gossip(params.mcache_gossip)
            // leanSpec: seen_ttl_secs = SECONDS_PER_SLOT * JUSTIFICATION_LOOKBACK_SLOTS * 2
            .duplicate_cache_time(Duration::from_secs(params.seen_ttl_secs))
            // leanSpec: d = 8
            .mesh_n(params.d)
            // leanSpec: d_low = 6
            .mesh_n_low(params.d_low)
            // leanSpec: d_high = 12
            .mesh_n_high(params.d_high)
            // leanSpec: d_lazy = 6
            .gossip_lazy(params.d_lazy)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_parameters() {
        let params = GossipsubParameters::default();

        // Test Ethereum spec values
        assert_eq!(params.d, 8);
        assert_eq!(params.d_low, 6);
        assert_eq!(params.d_high, 12);
        assert_eq!(params.d_lazy, 6);
        assert_eq!(params.heartbeat_interval_secs, 0.7);
        assert_eq!(params.fanout_ttl_secs, 60);
        assert_eq!(params.mcache_len, 6);
        assert_eq!(params.mcache_gossip, 3);
        assert_eq!(params.protocol_id, "/meshsub/1.3.0");
        assert_eq!(params.idontwant_message_size_threshold, 1000);

        // Test relationships
        assert!(params.d_low < params.d);
        assert!(params.d < params.d_high);
        assert!(params.d_lazy <= params.d);
        assert!(params.mcache_gossip <= params.mcache_len);
    }
}
