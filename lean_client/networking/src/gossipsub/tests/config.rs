use crate::gossipsub::config::GossipsubConfig;
use crate::gossipsub::topic::{GossipsubKind, get_topics};

#[test]
fn test_default_parameters() {
    let config = GossipsubConfig::new();

    assert!(config.config.mesh_n_low() < config.config.mesh_n());
    assert!(config.config.mesh_n() < config.config.mesh_n_high());

    assert!(config.config.gossip_lazy() <= config.config.mesh_n());

    assert!(config.config.history_gossip() <= config.config.history_length());

    assert!(config.config.heartbeat_interval() > std::time::Duration::ZERO);
    assert!(config.config.fanout_ttl() > std::time::Duration::ZERO);
    assert!(config.config.duplicate_cache_time() > std::time::Duration::ZERO); // seen_ttl
    assert!(config.config.history_length() > 0); // mcache_len
    assert!(config.config.history_gossip() > 0); // mcache_gossip

    assert_eq!(config.config.mesh_n(), 8); // d = 8
    assert_eq!(config.config.mesh_n_low(), 6); // d_low = 6
    assert_eq!(config.config.mesh_n_high(), 12); // d_high = 12
    assert_eq!(config.config.gossip_lazy(), 6); // d_lazy = 6
    assert_eq!(config.config.history_length(), 6); // mcache_len = 6
    assert_eq!(config.config.history_gossip(), 3); // mcache_gossip = 3
    assert_eq!(
        config.config.fanout_ttl(),
        std::time::Duration::from_secs(60)
    ); // fanout_ttl_secs = 60
    assert_eq!(
        config.config.heartbeat_interval(),
        std::time::Duration::from_millis(700)
    ); // heartbeat_interval_secs = 0.7

    assert!(config.topics.is_empty());
}

#[test]
fn test_set_topics() {
    let mut config = GossipsubConfig::new();
    let topics = get_topics("genesis".to_string());

    config.set_topics(topics.clone());

    assert_eq!(config.topics.len(), 2);
    assert_eq!(config.topics[0].fork, "genesis");
    assert_eq!(config.topics[0].kind, GossipsubKind::Block);
    assert_eq!(config.topics[1].fork, "genesis");
    assert_eq!(config.topics[1].kind, GossipsubKind::Attestation);
}
