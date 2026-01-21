/// Gossipsub Topics
///
/// Topic definitions for the Lean Ethereum gossipsub network.
///
/// ## Overview
///
/// Gossipsub organizes messages by topic. Each topic identifies a specific
/// message type (blocks, attestations, etc.) within a specific fork.
///
/// ## Topic Format
///
/// Topics follow a structured format:
///
/// ```text
/// /{prefix}/{fork_digest}/{topic_name}/{encoding}
///
/// Example: /leanconsensus/0x12345678/block/ssz_snappy
/// ```
///
/// **Components:**
///
/// | Component      | Description                                              |
/// |----------------|----------------------------------------------------------|
/// | prefix         | Network identifier (`leanconsensus`)                    |
/// | fork_digest    | 4-byte fork identifier as hex (`0x12345678`)            |
/// | topic_name     | Message type (`block`, `attestation`)                   |
/// | encoding       | Serialization format (always `ssz_snappy`)              |
///
/// ## Fork Digest
///
/// The fork digest ensures peers on different forks don't exchange
/// incompatible messages. It's derived from the fork version and
/// genesis validators root.
///
/// ## Topic Types
///
/// | Topic          | Content                                                  |
/// |----------------|----------------------------------------------------------|
/// | block          | Signed beacon blocks                                     |
/// | attestation    | Signed attestations                                      |
///
/// ## References
///
/// - Ethereum P2P: <https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md>
use libp2p::gossipsub::{IdentTopic, TopicHash};

/// Network prefix for Lean consensus gossip topics.
///
/// Identifies this network in topic strings. Different networks
/// (mainnet, testnets) may use different prefixes.
pub const TOPIC_PREFIX: &str = "leanconsensus";

/// Encoding suffix for SSZ with Snappy compression.
///
/// All Ethereum consensus gossip messages use SSZ serialization
/// with Snappy compression.
pub const SSZ_SNAPPY_ENCODING_POSTFIX: &str = "ssz_snappy";

/// Topic name for block messages.
///
/// Used in the topic string to identify signed beacon block messages.
pub const BLOCK_TOPIC: &str = "block";

/// Topic name for attestation messages.
///
/// Used in the topic string to identify signed attestation messages.
pub const ATTESTATION_TOPIC: &str = "attestation";

/// Gossip topic types.
///
/// Enumerates the different message types that can be gossiped.
///
/// Each variant corresponds to a specific `topic_name` in the
/// topic string format.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq)]
pub enum GossipsubKind {
    /// Signed beacon block messages.
    Block,

    /// Signed attestation messages.
    Attestation,
}

impl std::fmt::Display for GossipsubKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipsubKind::Block => write!(f, "{BLOCK_TOPIC}"),
            GossipsubKind::Attestation => write!(f, "{ATTESTATION_TOPIC}"),
        }
    }
}

impl GossipsubKind {
    /// Get the topic name string for this kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            GossipsubKind::Block => BLOCK_TOPIC,
            GossipsubKind::Attestation => ATTESTATION_TOPIC,
        }
    }
}

/// A fully-qualified gossipsub topic.
///
/// Immutable representation of a topic that combines the message type
/// and fork digest. Can be converted to/from the string format.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct GossipsubTopic {
    /// Fork digest as 0x-prefixed hex string.
    ///
    /// Identifies the fork this topic belongs to.
    ///
    /// Peers must match on fork digest to exchange messages on a topic.
    pub fork: String,

    /// The topic type (block, attestation, etc.).
    ///
    /// Determines what kind of messages are exchanged on this topic.
    pub kind: GossipsubKind,
}

impl GossipsubTopic {
    /// Create a new gossipsub topic.
    ///
    /// # Arguments
    ///
    /// * `fork` - Fork digest as 0x-prefixed hex string
    /// * `kind` - Topic type
    pub fn new(fork: String, kind: GossipsubKind) -> Self {
        Self { fork, kind }
    }

    /// Create a block topic for the given fork.
    ///
    /// # Arguments
    ///
    /// * `fork_digest` - Fork digest as 0x-prefixed hex string
    ///
    /// # Returns
    ///
    /// GossipsubTopic for block messages
    pub fn block(fork_digest: String) -> Self {
        Self::new(fork_digest, GossipsubKind::Block)
    }

    /// Create an attestation topic for the given fork.
    ///
    /// # Arguments
    ///
    /// * `fork_digest` - Fork digest as 0x-prefixed hex string
    ///
    /// # Returns
    ///
    /// GossipsubTopic for attestation messages
    pub fn attestation(fork_digest: String) -> Self {
        Self::new(fork_digest, GossipsubKind::Attestation)
    }

    /// Parse a topic string into a GossipsubTopic.
    ///
    /// # Arguments
    ///
    /// * `topic_str` - Full topic string to parse
    ///
    /// # Returns
    ///
    /// Parsed GossipsubTopic instance
    ///
    /// # Errors
    ///
    /// Returns an error if the topic string is malformed
    ///
    /// # Example
    ///
    /// ```
    /// use networking::gossipsub::topic::GossipsubTopic;
    ///
    /// let topic = GossipsubTopic::from_string("/leanconsensus/0x12345678/block/ssz_snappy")?;
    /// # Ok::<(), String>(())
    /// ```
    pub fn from_string(topic_str: &str) -> Result<Self, String> {
        let (prefix, fork_digest, topic_name, encoding) = parse_topic_string(topic_str)?;

        if prefix != TOPIC_PREFIX {
            return Err(format!(
                "Invalid prefix: expected '{TOPIC_PREFIX}', got '{prefix}'"
            ));
        }

        if encoding != SSZ_SNAPPY_ENCODING_POSTFIX {
            return Err(format!(
                "Invalid encoding: expected '{SSZ_SNAPPY_ENCODING_POSTFIX}', got '{encoding}'"
            ));
        }

        let kind = match topic_name {
            BLOCK_TOPIC => GossipsubKind::Block,
            ATTESTATION_TOPIC => GossipsubKind::Attestation,
            other => return Err(format!("Unknown topic: '{other}'")),
        };

        Ok(Self::new(fork_digest.to_string(), kind))
    }

    /// Decode a TopicHash into a GossipsubTopic.
    ///
    /// This is the existing method for compatibility with libp2p.
    pub fn decode(topic: &TopicHash) -> Result<Self, String> {
        Self::from_string(topic.as_str())
    }

    fn split_topic(topic: &TopicHash) -> Result<Vec<&str>, String> {
        let parts: Vec<&str> = topic.as_str().trim_start_matches('/').split('/').collect();

        if parts.len() != 4 {
            return Err(format!("Invalid topic part count: {topic:?}"));
        }

        Ok(parts)
    }

    fn validate_parts(parts: &[&str], topic: &TopicHash) -> Result<(), String> {
        if parts[0] != TOPIC_PREFIX || parts[3] != SSZ_SNAPPY_ENCODING_POSTFIX {
            return Err(format!("Invalid topic parts: {topic:?}"));
        }
        Ok(())
    }

    fn extract_fork(parts: &[&str]) -> String {
        parts[1].to_string()
    }

    fn extract_kind(parts: &[&str]) -> Result<GossipsubKind, String> {
        match parts[2] {
            BLOCK_TOPIC => Ok(GossipsubKind::Block),
            ATTESTATION_TOPIC => Ok(GossipsubKind::Attestation),
            other => Err(format!("Invalid topic kind: {other:?}")),
        }
    }

    /// Convert to topic string as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

impl std::fmt::Display for GossipsubTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "/{}/{}/{}/{}",
            TOPIC_PREFIX, self.fork, self.kind, SSZ_SNAPPY_ENCODING_POSTFIX
        )
    }
}

impl From<GossipsubTopic> for IdentTopic {
    fn from(topic: GossipsubTopic) -> IdentTopic {
        IdentTopic::new(topic)
    }
}

impl From<GossipsubTopic> for String {
    fn from(topic: GossipsubTopic) -> Self {
        topic.to_string()
    }
}

impl From<GossipsubTopic> for TopicHash {
    fn from(val: GossipsubTopic) -> Self {
        TopicHash::from_raw(val.to_string())
    }
}

/// Get all topics for a given fork.
///
/// # Arguments
///
/// * `fork` - Fork digest as 0x-prefixed hex string
///
/// # Returns
///
/// Vector of all gossipsub topics for the fork
pub fn get_topics(fork: String) -> Vec<GossipsubTopic> {
    vec![
        GossipsubTopic::block(fork.clone()),
        GossipsubTopic::attestation(fork),
    ]
}

/// Format a complete gossip topic string.
///
/// Low-level function for constructing topic strings. For most cases,
/// use `GossipsubTopic` instead.
///
/// # Arguments
///
/// * `topic_name` - Message type (e.g., "block", "attestation")
/// * `fork_digest` - Fork digest as 0x-prefixed hex string
/// * `prefix` - Network prefix (defaults to TOPIC_PREFIX)
/// * `encoding` - Encoding suffix (defaults to SSZ_SNAPPY_ENCODING_POSTFIX)
///
/// # Returns
///
/// Formatted topic string
///
/// # Example
///
/// ```
/// use networking::gossipsub::topic::format_topic_string;
///
/// let topic_str = format_topic_string("block", "0x12345678", None, None);
/// assert_eq!(topic_str, "/leanconsensus/0x12345678/block/ssz_snappy");
/// ```
pub fn format_topic_string(
    topic_name: &str,
    fork_digest: &str,
    prefix: Option<&str>,
    encoding: Option<&str>,
) -> String {
    format!(
        "/{}/{}/{}/{}",
        prefix.unwrap_or(TOPIC_PREFIX),
        fork_digest,
        topic_name,
        encoding.unwrap_or(SSZ_SNAPPY_ENCODING_POSTFIX)
    )
}

/// Parse a topic string into its components.
///
/// Low-level function for deconstructing topic strings. For most cases,
/// use `GossipsubTopic::from_string()` instead.
///
/// # Arguments
///
/// * `topic_str` - Topic string to parse
///
/// # Returns
///
/// Tuple of (prefix, fork_digest, topic_name, encoding)
///
/// # Errors
///
/// Returns an error if the topic string is malformed
///
/// # Example
///
/// ```
/// use networking::gossipsub::topic::parse_topic_string;
///
/// let (prefix, fork, name, enc) = parse_topic_string("/leanconsensus/0x12345678/block/ssz_snappy")?;
/// assert_eq!(prefix, "leanconsensus");
/// assert_eq!(fork, "0x12345678");
/// assert_eq!(name, "block");
/// assert_eq!(enc, "ssz_snappy");
/// # Ok::<(), String>(())
/// ```
pub fn parse_topic_string(topic_str: &str) -> Result<(&str, &str, &str, &str), String> {
    let parts: Vec<&str> = topic_str.trim_start_matches('/').split('/').collect();

    if parts.len() != 4 {
        return Err(format!(
            "Invalid topic format: expected 4 parts, got {}",
            parts.len()
        ));
    }

    Ok((parts[0], parts[1], parts[2], parts[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gossip_topic_creation() {
        let topic = GossipsubTopic::new("0x12345678".to_string(), GossipsubKind::Block);

        assert_eq!(topic.kind, GossipsubKind::Block);
        assert_eq!(topic.fork, "0x12345678");
        assert_eq!(
            topic.to_string(),
            "/leanconsensus/0x12345678/block/ssz_snappy"
        );
    }

    #[test]
    fn test_gossip_topic_from_string() {
        let topic = GossipsubTopic::from_string("/leanconsensus/0x12345678/block/ssz_snappy")
            .expect("Failed to parse topic");

        assert_eq!(topic.kind, GossipsubKind::Block);
        assert_eq!(topic.fork, "0x12345678");
    }

    #[test]
    fn test_gossip_topic_factory_methods() {
        let block_topic = GossipsubTopic::block("0xabcd1234".to_string());
        assert_eq!(block_topic.kind, GossipsubKind::Block);

        let attestation_topic = GossipsubTopic::attestation("0xabcd1234".to_string());
        assert_eq!(attestation_topic.kind, GossipsubKind::Attestation);
    }

    #[test]
    fn test_format_topic_string() {
        let result = format_topic_string("block", "0x12345678", None, None);
        assert_eq!(result, "/leanconsensus/0x12345678/block/ssz_snappy");
    }

    #[test]
    fn test_parse_topic_string() {
        let (prefix, fork_digest, topic_name, encoding) =
            parse_topic_string("/leanconsensus/0x12345678/block/ssz_snappy")
                .expect("Failed to parse");

        assert_eq!(prefix, "leanconsensus");
        assert_eq!(fork_digest, "0x12345678");
        assert_eq!(topic_name, "block");
        assert_eq!(encoding, "ssz_snappy");
    }

    #[test]
    fn test_invalid_topic_string() {
        assert!(GossipsubTopic::from_string("/invalid/topic").is_err());
        assert!(GossipsubTopic::from_string("/wrongprefix/0x123/block/ssz_snappy").is_err());
    }

    #[test]
    fn test_topic_kind_enum() {
        assert_eq!(GossipsubKind::Block.as_str(), "block");
        assert_eq!(GossipsubKind::Attestation.as_str(), "attestation");
        assert_eq!(GossipsubKind::Block.to_string(), "block");
    }
}
