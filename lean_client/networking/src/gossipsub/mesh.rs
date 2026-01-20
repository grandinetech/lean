/// Gossipsub Mesh State
///
/// Manages the mesh topology for gossipsub topics.
///
/// ## Overview
///
/// Each subscribed topic maintains a **mesh**: a set of peers for full
/// message exchange. The mesh is the core data structure enabling
/// gossipsub's eager push protocol.
///
/// - **Mesh peers**: Exchange full messages immediately (eager push)
/// - **Non-mesh peers**: Receive IHAVE advertisements, request via IWANT (lazy pull)
///
/// ## Mesh vs Fanout
///
/// | Type   | Description                                                |
/// |--------|-----------------------------------------------------------|
/// | Mesh   | Peers for topics we subscribe to                          |
/// | Fanout | Temporary peers for topics we publish to but don't        |
/// |        | subscribe to. Expires after fanout_ttl.                   |
///
/// ## Heartbeat Maintenance
///
/// The mesh is maintained through periodic heartbeat:
///
/// 1. **Graft** if |mesh| < D_low: add peers up to D
/// 2. **Prune** if |mesh| > D_high: remove peers down to D
/// 3. **Gossip**: send IHAVE to D_lazy non-mesh peers
///
/// ## References
///
/// - Gossipsub v1.0: <https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md>

use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use super::config::GossipsubParameters;
use super::types::{PeerId, TopicId};

/// Fanout state for a publish-only topic.
///
/// Tracks peers used when publishing to topics we don't subscribe to.
/// Fanout entries expire after a period of inactivity (fanout_ttl).
///
/// Unlike mesh peers, fanout peers only receive our published messages.
/// We don't receive their messages since we're not subscribed.
#[derive(Debug, Clone)]
pub struct FanoutEntry {
    /// Peers in the fanout for this topic.
    ///
    /// Selected randomly from available topic peers, up to D peers.
    pub peers: HashSet<PeerId>,
    
    /// Unix timestamp of the last publish to this topic.
    ///
    /// Used to determine if the entry has expired.
    pub last_published: f64,
}

impl FanoutEntry {
    /// Create a new empty fanout entry.
    pub fn new() -> Self {
        Self {
            peers: HashSet::new(),
            last_published: 0.0,
        }
    }
    
    /// Check if this fanout entry has expired.
    ///
    /// # Arguments
    ///
    /// * `current_time` - Current Unix timestamp
    /// * `ttl` - Time-to-live in seconds
    ///
    /// # Returns
    ///
    /// `true` if the entry hasn't been used within ttl seconds
    pub fn is_stale(&self, current_time: f64, ttl: f64) -> bool {
        current_time - self.last_published > ttl
    }
}

impl Default for FanoutEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Mesh state for a single topic.
///
/// Represents the set of peers we exchange full messages with
/// for a specific topic. Mesh membership is managed via
/// GRAFT and PRUNE control messages.
#[derive(Debug, Clone)]
pub struct TopicMesh {
    /// Peers in the mesh for this topic.
    ///
    /// These peers receive all published messages immediately
    /// and forward all received messages to us.
    pub peers: HashSet<PeerId>,
}

impl TopicMesh {
    /// Create a new empty topic mesh.
    pub fn new() -> Self {
        Self {
            peers: HashSet::new(),
        }
    }
    
    /// Add a peer to this topic's mesh.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Peer to add
    ///
    /// # Returns
    ///
    /// `true` if the peer was added, `false` if already present
    pub fn add_peer(&mut self, peer_id: PeerId) -> bool {
        self.peers.insert(peer_id)
    }
    
    /// Remove a peer from this topic's mesh.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Peer to remove
    ///
    /// # Returns
    ///
    /// `true` if the peer was removed, `false` if not present
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        self.peers.remove(peer_id)
    }
}

impl Default for TopicMesh {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete mesh state for all subscribed topics.
///
/// Central data structure managing mesh topology across all topics.
/// Provides operations for subscription management, peer tracking,
/// and gossip peer selection.
///
/// # Example
///
/// ```
/// use networking::gossipsub::mesh::MeshState;
/// use networking::gossipsub::config::GossipsubParameters;
/// use std::collections::HashSet;
///
/// let mut state = MeshState::new(GossipsubParameters::default());
///
/// // Subscribe and build mesh
/// state.subscribe("blocks".to_string());
/// state.add_to_mesh("blocks", "peer1".to_string());
/// state.add_to_mesh("blocks", "peer2".to_string());
///
/// // Get mesh peers for message forwarding
/// let peers = state.get_mesh_peers("blocks");
///
/// // Select peers for IHAVE gossip
/// let all_peers: HashSet<_> = vec!["peer1", "peer2", "peer3", "peer4"]
///     .into_iter()
///     .map(String::from)
///     .collect();
/// let gossip_peers = state.select_peers_for_gossip("blocks", &all_peers);
/// ```
#[derive(Debug, Clone)]
pub struct MeshState {
    /// Gossipsub parameters controlling mesh behavior.
    params: GossipsubParameters,
    
    /// Mesh state for each subscribed topic. Keyed by topic ID.
    meshes: HashMap<TopicId, TopicMesh>,
    
    /// Fanout state for publish-only topics. Keyed by topic ID.
    fanouts: HashMap<TopicId, FanoutEntry>,
    
    /// Set of topics we are subscribed to.
    subscriptions: HashSet<TopicId>,
}

impl MeshState {
    /// Create a new mesh state with the given parameters.
    pub fn new(params: GossipsubParameters) -> Self {
        Self {
            params,
            meshes: HashMap::new(),
            fanouts: HashMap::new(),
            subscriptions: HashSet::new(),
        }
    }
    
    /// Get the target mesh size per topic.
    pub fn d(&self) -> usize {
        self.params.d
    }
    
    /// Get the low watermark - graft when mesh is smaller.
    pub fn d_low(&self) -> usize {
        self.params.d_low
    }
    
    /// Get the high watermark - prune when mesh is larger.
    pub fn d_high(&self) -> usize {
        self.params.d_high
    }
    
    /// Get the number of peers for IHAVE gossip.
    pub fn d_lazy(&self) -> usize {
        self.params.d_lazy
    }
    
    /// Subscribe to a topic, initializing its mesh.
    ///
    /// If we have fanout peers for this topic, they are
    /// promoted to the mesh automatically.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier to subscribe to
    pub fn subscribe(&mut self, topic: TopicId) {
        if self.subscriptions.contains(&topic) {
            return;
        }
        
        self.subscriptions.insert(topic.clone());
        
        // Promote fanout peers to mesh if any
        let mut mesh = TopicMesh::new();
        if let Some(fanout) = self.fanouts.remove(&topic) {
            mesh.peers = fanout.peers;
        }
        self.meshes.insert(topic, mesh);
    }
    
    /// Unsubscribe from a topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier to unsubscribe from
    ///
    /// # Returns
    ///
    /// Set of peers that were in the mesh (need PRUNE)
    pub fn unsubscribe(&mut self, topic: &TopicId) -> HashSet<PeerId> {
        self.subscriptions.remove(topic);
        self.meshes
            .remove(topic)
            .map(|mesh| mesh.peers)
            .unwrap_or_default()
    }
    
    /// Check if subscribed to a topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier to check
    ///
    /// # Returns
    ///
    /// `true` if subscribed
    pub fn is_subscribed(&self, topic: &TopicId) -> bool {
        self.subscriptions.contains(topic)
    }
    
    /// Get mesh peers for a topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier
    ///
    /// # Returns
    ///
    /// Copy of the mesh peer set, or empty set if not subscribed
    pub fn get_mesh_peers(&self, topic: &str) -> HashSet<PeerId> {
        self.meshes
            .get(topic)
            .map(|mesh| mesh.peers.clone())
            .unwrap_or_default()
    }
    
    /// Add a peer to a topic's mesh.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier
    /// * `peer_id` - Peer to add
    ///
    /// # Returns
    ///
    /// - `true` if added,
    /// - `false` if already present or not subscribed
    pub fn add_to_mesh(&mut self, topic: &str, peer_id: PeerId) -> bool {
        if let Some(mesh) = self.meshes.get_mut(topic) {
            mesh.add_peer(peer_id)
        } else {
            false
        }
    }
    
    /// Remove a peer from a topic's mesh.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier
    /// * `peer_id` - Peer to remove
    ///
    /// # Returns
    ///
    /// - `true` if removed,
    /// - `false` if not present or not subscribed
    pub fn remove_from_mesh(&mut self, topic: &str, peer_id: &PeerId) -> bool {
        if let Some(mesh) = self.meshes.get_mut(topic) {
            mesh.remove_peer(peer_id)
        } else {
            false
        }
    }
    
    /// Get fanout peers for a topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier
    ///
    /// # Returns
    ///
    /// Copy of the fanout peer set, or empty set if none
    pub fn get_fanout_peers(&self, topic: &str) -> HashSet<PeerId> {
        self.fanouts
            .get(topic)
            .map(|fanout| fanout.peers.clone())
            .unwrap_or_default()
    }
    
    /// Update fanout for publishing to a non-subscribed topic.
    ///
    /// For subscribed topics, returns mesh peers instead.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier
    /// * `available_peers` - All known peers for this topic
    ///
    /// # Returns
    ///
    /// Peers to publish to (mesh or fanout)
    pub fn update_fanout(
        &mut self,
        topic: &str,
        available_peers: &HashSet<PeerId>,
    ) -> HashSet<PeerId> {
        if self.subscriptions.contains(topic) {
            return self.get_mesh_peers(topic);
        }
        
        let d = self.d();
        let fanout = self
            .fanouts
            .entry(topic.to_string())
            .or_insert_with(FanoutEntry::new);
        
        fanout.last_published = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        // Fill fanout up to D peers
        if fanout.peers.len() < d {
            let candidates: Vec<_> = available_peers
                .difference(&fanout.peers)
                .cloned()
                .collect();
            let needed = d - fanout.peers.len();
            let mut rng = rand::thread_rng();
            let new_peers: Vec<_> = candidates
                .choose_multiple(&mut rng, needed.min(candidates.len()))
                .cloned()
                .collect();
            fanout.peers.extend(new_peers);
        }
        
        fanout.peers.clone()
    }
    
    /// Remove expired fanout entries.
    ///
    /// # Arguments
    ///
    /// * `ttl` - Time-to-live in seconds
    ///
    /// # Returns
    ///
    /// Number of entries removed
    pub fn cleanup_fanouts(&mut self, ttl: f64) -> usize {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        let stale: Vec<_> = self
            .fanouts
            .iter()
            .filter(|(_, fanout)| fanout.is_stale(current_time, ttl))
            .map(|(topic, _)| topic.clone())
            .collect();
        
        let count = stale.len();
        for topic in stale {
            self.fanouts.remove(&topic);
        }
        
        count
    }
    
    /// Select non-mesh peers for IHAVE gossip.
    ///
    /// Randomly selects up to D_lazy peers from those not in the mesh.
    /// These peers receive IHAVE messages during heartbeat.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic identifier
    /// * `all_topic_peers` - All known peers subscribed to this topic
    ///
    /// # Returns
    ///
    /// List of peers to send IHAVE gossip to
    pub fn select_peers_for_gossip(
        &self,
        topic: &str,
        all_topic_peers: &HashSet<PeerId>,
    ) -> Vec<PeerId> {
        let mesh_peers = self.get_mesh_peers(topic);
        let candidates: Vec<_> = all_topic_peers
            .difference(&mesh_peers)
            .cloned()
            .collect();
        
        if candidates.len() <= self.d_lazy() {
            return candidates;
        }
        
        let mut rng = rand::thread_rng();
        candidates
            .choose_multiple(&mut rng, self.d_lazy())
            .cloned()
            .collect()
    }
}