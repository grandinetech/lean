/// Gossipsub Message Cache
///
/// Caches recent messages for gossip dissemination and IWANT responses.
///
/// ## Overview
///
/// The message cache enables the lazy pull protocol by storing messages
/// that can be requested via IWANT after receiving IHAVE advertisements.
///
/// ```text
/// Peer A                        Peer B (non-mesh)
///    |                              |
///    |--- IHAVE [msg1, msg2] ------>|
///    |                              |
///    |<----- IWANT [msg2] ----------|
///    |                              |
///    |--- MESSAGE [msg2] ---------->|  <- Retrieved from cache
/// ```
///
/// ## Sliding Window Design
///
/// The cache is organized as a sliding window of history buckets:
///
/// ```text
/// +----------+----------+----------+----------+
/// | Window 0 | Window 1 | Window 2 | Window 3 | ...
/// | (newest) |          |          | (oldest) |
/// +----------+----------+----------+----------+
///      ^
///      |
/// New messages go here
/// ```
///
/// Each heartbeat:
///
/// 1. Oldest window is evicted (messages cleaned up)
/// 2. New empty window is prepended
/// 3. Windows shift: 0 -> 1 -> 2 -> ...
///
/// ## Key Parameters
///
/// - **mcache_len** (6): Total windows retained
/// - **mcache_gossip** (3): Recent windows included in IHAVE
///
/// Only the first `mcache_gossip` windows are advertised via IHAVE.
/// Older messages can still be retrieved via IWANT but won't be
/// actively gossiped.
///
/// ## Seen Cache
///
/// A separate `SeenCache` tracks message IDs for deduplication
/// without storing full messages. Uses TTL-based expiry.
///
/// ## References
///
/// - Gossipsub v1.0: <https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md>

use std::collections::{HashMap, HashSet, VecDeque};

use super::message::RawGossipsubMessage;
use super::types::{MessageId, Timestamp, TopicId};

/// A single entry in the message cache.
///
/// Stores the message along with its topic for efficient retrieval
/// during IWANT responses and topic-filtered IHAVE gossip.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached gossipsub message.
    pub message: RawGossipsubMessage,
    
    /// Topic this message was published to.
    ///
    /// Used to filter messages when generating IHAVE gossip for a specific topic.
    pub topic: TopicId,
}

/// Sliding window cache for gossipsub messages.
///
/// Maintains recent messages for:
///
/// - **IWANT responses**: Retrieve full messages by ID
/// - **IHAVE gossip**: Get message IDs for advertisement
///
/// # Example
///
/// ```
/// use lean_client_networking::gossipsub::mcache::MessageCache;
/// use lean_client_networking::gossipsub::message::RawGossipsubMessage;
///
/// let mut cache = MessageCache::new(6, 3);
///
/// // Add messages
/// let msg1 = RawGossipsubMessage::new(b"topic".to_vec(), b"data1".to_vec(), None);
/// cache.put("blocks".to_string(), msg1.clone());
///
/// // Get message IDs for IHAVE
/// let ids = cache.get_gossip_ids("blocks");
///
/// // Respond to IWANT
/// let msg = cache.get(&msg1.id());
///
/// // Shift window (called each heartbeat)
/// let evicted = cache.shift();
/// ```
#[derive(Debug, Clone)]
pub struct MessageCache {
    /// Number of history windows to retain.
    ///
    /// Messages are evicted after this many heartbeat intervals.
    ///
    /// Higher values increase memory usage but improve message
    /// availability for late IWANT requests.
    mcache_len: usize,
    
    /// Number of recent windows to include in IHAVE gossip.
    ///
    /// Only messages from the most recent windows are advertised.
    /// Should be less than or equal to mcache_len.
    mcache_gossip: usize,
    
    /// Sliding window of message ID sets.
    ///
    /// Index 0 is the newest window. Each heartbeat, windows shift
    /// right and a new empty window is prepended.
    windows: VecDeque<HashSet<MessageId>>,
    
    /// Message lookup index keyed by ID.
    ///
    /// Provides O(1) retrieval for IWANT responses.
    by_id: HashMap<MessageId, CacheEntry>,
}

impl MessageCache {
    /// Create a new message cache.
    ///
    /// # Arguments
    ///
    /// * `mcache_len` - Number of history windows to retain
    /// * `mcache_gossip` - Number of recent windows to include in IHAVE gossip
    pub fn new(mcache_len: usize, mcache_gossip: usize) -> Self {
        let mut windows = VecDeque::with_capacity(mcache_len);
        windows.push_back(HashSet::new());
        
        Self {
            mcache_len,
            mcache_gossip,
            windows,
            by_id: HashMap::new(),
        }
    }
    
    /// Add a message to the cache.
    ///
    /// Messages are added to the newest window (index 0) and
    /// indexed for fast retrieval. Duplicates are ignored.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic this message belongs to
    /// * `message` - Message to cache
    ///
    /// # Returns
    ///
    /// `true` if added (not a duplicate)
    pub fn put(&mut self, topic: TopicId, message: RawGossipsubMessage) -> bool {
        let msg_id = message.id();
        
        if self.by_id.contains_key(&msg_id) {
            return false;
        }
        
        if let Some(window) = self.windows.front_mut() {
            window.insert(msg_id.clone());
        }
        
        self.by_id.insert(msg_id, CacheEntry { message, topic });
        true
    }
    
    /// Retrieve a message by ID.
    ///
    /// Used to respond to IWANT requests from peers.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - Message ID to look up
    ///
    /// # Returns
    ///
    /// The cached message, or `None` if not found/evicted
    pub fn get(&self, msg_id: &MessageId) -> Option<&RawGossipsubMessage> {
        self.by_id.get(msg_id).map(|entry| &entry.message)
    }
    
    /// Check if a message is cached.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - Message ID to check
    ///
    /// # Returns
    ///
    /// `true` if the message is in the cache
    pub fn has(&self, msg_id: &MessageId) -> bool {
        self.by_id.contains_key(msg_id)
    }
    
    /// Get message IDs for IHAVE gossip.
    ///
    /// Returns IDs from the most recent `mcache_gossip` windows
    /// that belong to the specified topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic to filter messages by
    ///
    /// # Returns
    ///
    /// List of message IDs for IHAVE advertisement
    pub fn get_gossip_ids(&self, topic: &str) -> Vec<MessageId> {
        let mut result = Vec::new();
        let windows_to_check = self.mcache_gossip.min(self.windows.len());
        
        for i in 0..windows_to_check {
            if let Some(window) = self.windows.get(i) {
                for msg_id in window {
                    if let Some(entry) = self.by_id.get(msg_id) {
                        if entry.topic == topic {
                            result.push(msg_id.clone());
                        }
                    }
                }
            }
        }
        
        result
    }
    
    /// Shift the cache window, evicting the oldest.
    ///
    /// Called at each heartbeat to age the cache:
    ///
    /// 1. If at capacity, remove oldest window and its messages
    /// 2. Prepend new empty window
    ///
    /// # Returns
    ///
    /// Number of messages evicted
    pub fn shift(&mut self) -> usize {
        let mut evicted = 0;
        
        if self.windows.len() >= self.mcache_len {
            if let Some(oldest) = self.windows.pop_back() {
                for msg_id in oldest {
                    if self.by_id.remove(&msg_id).is_some() {
                        evicted += 1;
                    }
                }
            }
        }
        
        self.windows.push_front(HashSet::new());
        evicted
    }
    
    /// Clear all cached messages.
    pub fn clear(&mut self) {
        self.windows.clear();
        self.windows.push_back(HashSet::new());
        self.by_id.clear();
    }
    
    /// Get the total number of cached messages.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }
    
    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// TTL-based cache for deduplicating messages.
///
/// Tracks message IDs that have been seen to prevent reprocessing
/// duplicates. Unlike `MessageCache`, this only stores IDs (not
/// full messages) with time-based expiry.
///
/// ## Use Cases
///
/// - Skip processing of already-seen messages
/// - Avoid forwarding duplicates to mesh peers
/// - Bound memory with automatic TTL cleanup
#[derive(Debug, Clone)]
pub struct SeenCache {
    /// Time-to-live for entries in seconds.
    ///
    /// Entries older than this are removed during cleanup.
    ///
    /// Should be:
    /// - long enough to cover network propagation,
    /// - short enough to bound memory usage.
    ttl_seconds: u64,
    
    /// Set of message IDs that have been seen.
    ///
    /// Provides O(1) membership testing.
    seen: HashSet<MessageId>,
    
    /// Timestamp when each message was first seen.
    ///
    /// Used to determine expiry during cleanup.
    timestamps: HashMap<MessageId, Timestamp>,
}

impl SeenCache {
    /// Create a new seen cache.
    ///
    /// # Arguments
    ///
    /// * `ttl_seconds` - Time-to-live for entries in seconds
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl_seconds,
            seen: HashSet::new(),
            timestamps: HashMap::new(),
        }
    }
    
    /// Mark a message as seen.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - Message ID to mark as seen
    /// * `timestamp` - Current Unix timestamp
    ///
    /// # Returns
    ///
    /// `true` if newly seen (not a duplicate)
    pub fn add(&mut self, msg_id: MessageId, timestamp: Timestamp) -> bool {
        if self.seen.contains(&msg_id) {
            return false;
        }
        
        self.seen.insert(msg_id.clone());
        self.timestamps.insert(msg_id, timestamp);
        true
    }
    
    /// Check if a message has been seen.
    ///
    /// # Arguments
    ///
    /// * `msg_id` - Message ID to check
    ///
    /// # Returns
    ///
    /// `true` if the message has been seen
    pub fn has(&self, msg_id: &MessageId) -> bool {
        self.seen.contains(msg_id)
    }
    
    /// Remove expired entries.
    ///
    /// Should be called periodically (e.g., each heartbeat)
    /// to prevent unbounded memory growth.
    ///
    /// # Arguments
    ///
    /// * `current_time` - Current Unix timestamp
    ///
    /// # Returns
    ///
    /// Number of entries removed
    pub fn cleanup(&mut self, current_time: f64) -> usize {
        let cutoff = current_time - self.ttl_seconds as f64;
        let expired: Vec<MessageId> = self
            .timestamps
            .iter()
            .filter(|(_, ts)| **ts < cutoff)
            .map(|(id, _)| id.clone())
            .collect();
        
        let count = expired.len();
        for msg_id in expired {
            self.seen.remove(&msg_id);
            self.timestamps.remove(&msg_id);
        }
        
        count
    }
    
    /// Clear all seen entries.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.timestamps.clear();
    }
    
    /// Get the number of seen message IDs.
    pub fn len(&self) -> usize {
        self.seen.len()
    }
    
    /// Check if the seen cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
