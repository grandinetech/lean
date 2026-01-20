/// Gossipsub Type Definitions
///
/// Type aliases for common gossipsub types.
use containers::Bytes20;

/// 20-byte message identifier.
///
/// Computed from message contents using SHA256:
/// `SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]`
///
/// The domain byte distinguishes valid/invalid snappy compression.
pub type MessageId = Bytes20;

/// Libp2p peer identifier.
///
/// Derived from the peer's public key as a base58-encoded multihash.
/// Uniquely identifies peers in the P2P network.
pub type PeerId = String;

/// Topic string identifier.
///
/// Follows the Ethereum consensus format:
/// `/{prefix}/{fork_digest}/{topic_name}/{encoding}`
pub type TopicId = String;

/// Unix timestamp in seconds since epoch.
///
/// Used for:
/// - Message arrival times
/// - Peer activity tracking
/// - Seen cache expiry
pub type Timestamp = f64;
