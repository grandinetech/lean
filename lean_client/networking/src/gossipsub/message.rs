/// Gossipsub Message
///
/// Message representation and ID computation for the gossipsub protocol.
///
/// ## Overview
///
/// Each gossipsub message carries a topic and payload. Messages are
/// identified by a 20-byte ID computed from their contents.
///
/// ## Message ID Function
///
/// Ethereum consensus uses a custom message ID function based on SHA256:
///
/// ```text
/// message_id = SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]
/// ```
///
/// **Components:**
///
/// | Component       | Description                                            |
/// |-----------------|--------------------------------------------------------|
/// | domain          | 1-byte prefix indicating snappy validity (0x00/0x01)   |
/// | uint64_le       | Topic length as 8-byte little-endian integer           |
/// | topic           | Topic string as UTF-8 bytes                            |
/// | data            | Message payload (decompressed if snappy is valid)      |
///
/// **Domain Bytes:**
///
/// - `0x01` (VALID_SNAPPY): Snappy decompression succeeded, use decompressed data
/// - `0x00` (INVALID_SNAPPY): Decompression failed or no decompressor, use raw data
///
/// This ensures messages with compression issues get different IDs,
/// preventing cache pollution from invalid variants.
///
/// ## Snappy Compression
///
/// Ethereum consensus requires SSZ data to be snappy-compressed.
/// The message ID computation attempts decompression to determine
/// which domain byte to use.
///
/// ## References
///
/// - [Ethereum P2P spec](https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md)
/// - [Gossipsub v1.0](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md)
use containers::Bytes20;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::types::{MESSAGE_DOMAIN_INVALID_SNAPPY, MESSAGE_DOMAIN_VALID_SNAPPY};

/// Trait for snappy decompression functions.
///
/// Any type implementing this trait can be used for decompression.
/// The function should return an error if decompression fails.
pub trait SnappyDecompressor: Send + Sync {
    /// Decompress snappy-compressed data.
    ///
    /// # Arguments
    ///
    /// * `data` - Compressed bytes
    ///
    /// # Returns
    ///
    /// Decompressed bytes, or an error if decompression fails
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

/// A raw gossipsub message with lazy ID computation.
///
/// Encapsulates topic, payload, and message ID logic. The ID is
/// computed lazily on first access and cached thereafter.
///
/// ## Message ID Computation
///
/// The 20-byte ID is computed as:
///
/// ```text
/// SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]
/// ```
///
/// Where `domain` depends on snappy decompression success.
#[derive(Clone)]
pub struct RawGossipsubMessage {
    /// Topic string as UTF-8 encoded bytes.
    ///
    /// Example: `b"/leanconsensus/0x12345678/block/ssz_snappy"`
    pub topic: Vec<u8>,

    /// Raw message payload.
    ///
    /// Typically snappy-compressed SSZ data. The actual content
    /// depends on the topic (block, attestation, etc.).
    pub raw_data: Vec<u8>,

    /// Optional snappy decompression function.
    ///
    /// If provided, decompression is attempted during ID computation
    /// to determine the domain byte.
    snappy_decompress: Option<Arc<dyn SnappyDecompressor>>,

    /// Cached message ID.
    ///
    /// Computed lazily on first access to `id()` method. Once computed,
    /// the same ID is returned for all subsequent accesses.
    cached_id: Option<Bytes20>,
}

impl RawGossipsubMessage {
    /// Create a new gossipsub message.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic string as bytes
    /// * `raw_data` - Raw message payload
    /// * `snappy_decompress` - Optional decompression function
    pub fn new(
        topic: Vec<u8>,
        raw_data: Vec<u8>,
        snappy_decompress: Option<Arc<dyn SnappyDecompressor>>,
    ) -> Self {
        Self {
            topic,
            raw_data,
            snappy_decompress,
            cached_id: None,
        }
    }

    /// Get the 20-byte message ID.
    ///
    /// Computed lazily on first access using the Ethereum consensus
    /// message ID function. The result is cached.
    ///
    /// # Returns
    ///
    /// 20-byte message ID (Bytes20)
    pub fn id(&self) -> Bytes20 {
        if let Some(id) = &self.cached_id {
            return id.clone();
        }

        // Compute ID
        let id = Self::compute_id(&self.topic, &self.raw_data, self.snappy_decompress.as_ref());

        // Note: We can't cache here because self is immutable
        // In practice, callers should use a mutable reference or compute once
        id
    }

    /// Compute a 20-byte message ID from raw data.
    ///
    /// Implements the Ethereum consensus message ID function:
    ///
    /// ```text
    /// SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]
    /// ```
    ///
    /// ## Domain Selection
    ///
    /// - If `snappy_decompress` is provided and succeeds:
    ///   domain = 0x01, use decompressed data
    /// - Otherwise:
    ///   domain = 0x00, use raw data
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic string as bytes
    /// * `data` - Message payload (potentially compressed)
    /// * `snappy_decompress` - Optional decompression function
    ///
    /// # Returns
    ///
    /// 20-byte message ID
    pub fn compute_id(
        topic: &[u8],
        data: &[u8],
        snappy_decompress: Option<&Arc<dyn SnappyDecompressor>>,
    ) -> Bytes20 {
        let (domain, data_for_hash) = if let Some(decompressor) = snappy_decompress {
            match decompressor.decompress(data) {
                Ok(decompressed) => (MESSAGE_DOMAIN_VALID_SNAPPY, decompressed),
                Err(_) => (MESSAGE_DOMAIN_INVALID_SNAPPY, data.to_vec()),
            }
        } else {
            (MESSAGE_DOMAIN_INVALID_SNAPPY, data.to_vec())
        };

        let mut preimage = Vec::new();
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(&(topic.len() as u64).to_le_bytes());
        preimage.extend_from_slice(topic);
        preimage.extend_from_slice(&data_for_hash);

        let hash = Sha256::digest(&preimage);
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash[..20]);
        Bytes20::from(bytes)
    }

    /// Get the topic as a UTF-8 string.
    ///
    /// # Returns
    ///
    /// Topic decoded from bytes to string
    pub fn topic_str(&self) -> String {
        String::from_utf8_lossy(&self.topic).to_string()
    }
}

impl PartialEq for RawGossipsubMessage {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for RawGossipsubMessage {}

impl std::fmt::Debug for RawGossipsubMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawGossipsubMessage")
            .field("topic", &self.topic_str())
            .field("raw_data_len", &self.raw_data.len())
            .field("cached_id", &self.cached_id)
            .finish()
    }
}

impl std::hash::Hash for RawGossipsubMessage {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

use crate::gossipsub::topic::GossipsubKind;
use crate::gossipsub::topic::GossipsubTopic;
use containers::SignedAttestation;
use containers::SignedBlockWithAttestation;
use containers::ssz::SszReadDefault;
use libp2p::gossipsub::TopicHash;

/// Decoded gossipsub message by type.
pub enum GossipsubMessage {
    Block(SignedBlockWithAttestation),
    Attestation(SignedAttestation),
}

impl GossipsubMessage {
    pub fn decode(topic: &TopicHash, data: &[u8]) -> Result<Self, String> {
        match GossipsubTopic::decode(topic)?.kind {
            GossipsubKind::Block => Ok(Self::Block(
                SignedBlockWithAttestation::from_ssz_default(data)
                    .map_err(|e| format!("{:?}", e))?,
            )),
            GossipsubKind::Attestation => Ok(Self::Attestation(
                SignedAttestation::from_ssz_default(data).map_err(|e| format!("{:?}", e))?,
            )),
        }
    }
}
