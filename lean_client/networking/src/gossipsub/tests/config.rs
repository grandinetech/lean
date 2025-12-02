use crate::gossipsub::config::GossipsubConfig;
use crate::gossipsub::topic::{get_topics, GossipsubKind};

#[test]
fn test_default_parameters() {
    let config = GossipsubConfig::new();
    let _gossip_config = &config.config;

    // mesh_n_low (4) < mesh_n (6) < mesh_n_high (12)
    assert!(config.config.mesh_n_low() < config.config.mesh_n());
    assert!(config.config.mesh_n() < config.config.mesh_n_high());

    // Topics are initially empty
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
