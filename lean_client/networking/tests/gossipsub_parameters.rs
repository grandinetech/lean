use networking::gossipsub::config::GossipsubConfig;

#[test]
fn test_default_parameters() {
    let params = GossipsubConfig::new();

    assert!(
        params.config.mesh_n_low() < params.config.mesh_n() && params.config.mesh_n() < params.config.mesh_n_high()
    );
    assert!(
        params.config.gossip_lazy() <= params.config.mesh_n()
    );
    assert!(
        params.config.history_gossip() <= params.config.history_length()
    );


    assert!(params.config.heartbeat_interval().as_secs() > 0);
    assert!(params.config.fanout_ttl().as_secs() > 0);
    // TODO: seen_ttl is not implemented
    // assert!(params.config.seen_ttl().as_secs() > 0);
    assert!(params.config.history_length() > 0);
    assert!(params.config.history_gossip() > 0);
}