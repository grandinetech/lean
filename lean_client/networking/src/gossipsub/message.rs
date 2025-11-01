use std::sync::Arc;
use std::sync::OnceLock;

use crate::gossipsub::topic::GossipsubKind;
use crate::gossipsub::topic::GossipsubTopic;
use crate::types::MESSAGE_DOMAIN_INVALID_SNAPPY;
use crate::types::MESSAGE_DOMAIN_VALID_SNAPPY;
use containers::ssz::SszReadDefault;
use containers::{SignedBlock, SignedVote};
use libp2p::gossipsub::TopicHash;
use sha2::Digest;


pub enum GossipsubMessageKind {
    Block(SignedBlock),
    Vote(SignedVote),
}

pub struct GossipsubMessage {
    topic: Vec<u8>,
    raw_data: Vec<u8>,
    snappy_decompress: Option<SnappyDecompressFn>,
    message: GossipsubMessageKind,
    id: OnceLock<MessageId>,
}

/// A 20-byte ID for gossipsub messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId([u8; 20]);

impl MessageId {
    /// Creates a new MessageId from a 20-byte array.
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying 20-byte array.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Converts the MessageId into the underlying byte array.
    pub fn into_bytes(self) -> [u8; 20] {
        self.0
    }
}

impl AsRef<[u8]> for MessageId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for MessageId {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for MessageId {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 20 {
            return Err(format!(
                "MessageId must be exactly 20 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

pub type SnappyDecompressFn = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

impl GossipsubMessage {
    pub fn new(
        topic: Vec<u8>,
        raw_data: Vec<u8>,
        snappy_decompress: Option<SnappyDecompressFn>,
    ) -> Self {
        Self {
            topic,
            raw_data,
            snappy_decompress,
            message: GossipsubMessageKind::Block(SignedBlock::default()), // Placeholder
            id: OnceLock::new(),
        }
    }

    pub fn decode() -> Result<Self, String> {
        // Decoding logic here
        Ok(Self::new(vec![], vec![], None)) // Placeholder
    }

    pub fn id(&self) -> MessageId 
    {
        *self.id.get_or_init(|| {

        let (domain, message_data) = if let Some(ref decompress_fn) = self.snappy_decompress {
            match decompress_fn(&self.raw_data) {
                Ok(decompressed_data) => {
                    (MESSAGE_DOMAIN_VALID_SNAPPY.as_bytes(), decompressed_data)
                }
                Err(_) => {
                    (MESSAGE_DOMAIN_INVALID_SNAPPY.as_bytes(), self.raw_data.clone())
                }
            }
        } else {
            (MESSAGE_DOMAIN_INVALID_SNAPPY.as_bytes(), self.raw_data.clone())
        };

            MessageId::new(self.compute_raw_id(domain, &message_data))
        })
    }   

    pub fn compute_raw_id(&self, domain: &[u8], message_data: &Vec<u8>) -> [u8; 20] {
        let topic_len_bytes = self.topic.len().to_le_bytes();
        let data_to_hash = [domain, &topic_len_bytes, &self.topic, message_data].concat();
        let hash = sha2::Sha256::digest(&data_to_hash);
        let mut id_bytes = [0u8; 20];
        id_bytes.copy_from_slice(&hash[..20]);
        id_bytes
    }
}
