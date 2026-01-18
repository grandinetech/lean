use crate::gossipsub::config::GossipsubParameters;
use crate::gossipsub::mesh::{FanoutEntry, MeshState, TopicMesh};
use std::collections::HashSet;

#[test]
fn test_mesh_state_initialization() {
    let params = GossipsubParameters {
        d: 8,
        d_low: 6,
        d_high: 12,
        d_lazy: 6,
        ..Default::default()
    };
    let mesh = MeshState::new(params);
    
    assert_eq!(mesh.d(), 8);
    assert_eq!(mesh.d_low(), 6);
    assert_eq!(mesh.d_high(), 12);
    assert_eq!(mesh.d_lazy(), 6);
}

#[test]
fn test_subscribe_and_unsubscribe() {
    let mesh = &mut MeshState::new(GossipsubParameters::default());
    
    mesh.subscribe("topic1".to_string());
    assert!(mesh.is_subscribed(&"topic1".to_string()));
    assert!(!mesh.is_subscribed(&"topic2".to_string()));
    
    let peers = mesh.unsubscribe(&"topic1".to_string());
    assert!(!mesh.is_subscribed(&"topic1".to_string()));
    assert!(peers.is_empty());
}

#[test]
fn test_add_remove_mesh_peers() {
    let mesh = &mut MeshState::new(GossipsubParameters::default());
    mesh.subscribe("topic1".to_string());
    
    assert!(mesh.add_to_mesh("topic1", "peer1".to_string()));
    assert!(mesh.add_to_mesh("topic1", "peer2".to_string()));
    assert!(!mesh.add_to_mesh("topic1", "peer1".to_string())); // Already in mesh
    
    let peers = mesh.get_mesh_peers("topic1");
    assert!(peers.contains("peer1"));
    assert!(peers.contains("peer2"));
    
    assert!(mesh.remove_from_mesh("topic1", &"peer1".to_string()));
    assert!(!mesh.remove_from_mesh("topic1", &"peer1".to_string())); // Already removed
    
    let peers = mesh.get_mesh_peers("topic1");
    assert!(!peers.contains("peer1"));
    assert!(peers.contains("peer2"));
}

#[test]
fn test_gossip_peer_selection() {
    let params = GossipsubParameters {
        d_lazy: 3,
        ..Default::default()
    };
    let mesh = &mut MeshState::new(params);
    mesh.subscribe("topic1".to_string());
    mesh.add_to_mesh("topic1", "peer1".to_string());
    mesh.add_to_mesh("topic1", "peer2".to_string());
    
    let all_peers: HashSet<_> = vec!["peer1", "peer2", "peer3", "peer4", "peer5", "peer6"]
        .into_iter()
        .map(String::from)
        .collect();
    
    let gossip_peers = mesh.select_peers_for_gossip("topic1", &all_peers);
    
    let mesh_peers = mesh.get_mesh_peers("topic1");
    for peer in &gossip_peers {
        assert!(!mesh_peers.contains(peer));
    }
}

#[test]
fn test_topic_mesh_add_remove() {
    let topic_mesh = &mut TopicMesh::new();
    
    assert!(topic_mesh.add_peer("peer1".to_string()));
    assert!(!topic_mesh.add_peer("peer1".to_string())); // Already exists
    assert!(topic_mesh.peers.contains("peer1"));
    
    assert!(topic_mesh.remove_peer(&"peer1".to_string()));
    assert!(!topic_mesh.remove_peer(&"peer1".to_string())); // Already removed
    assert!(!topic_mesh.peers.contains("peer1"));
}

#[test]
fn test_fanout_entry_staleness() {
    let mut entry = FanoutEntry::new();
    entry.last_published = 1000.0;
    
    assert!(!entry.is_stale(1050.0, 60.0));
    assert!(entry.is_stale(1070.0, 60.0));
}
