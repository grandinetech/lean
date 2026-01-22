use crate::gossipsub::topic::GossipsubKind;
use crate::gossipsub::topic::GossipsubTopic;
use anyhow::{Context, Result};
use containers::SignedAttestation;
use containers::SignedBlockWithAttestation;
use containers::ssz::SszReadDefault;
use libp2p::gossipsub::TopicHash;

pub enum GossipsubMessage {
    Block(SignedBlockWithAttestation),
    Attestation(SignedAttestation),
}

impl GossipsubMessage {
    pub fn decode(topic: &TopicHash, data: &[u8]) -> Result<Self> {
        match GossipsubTopic::decode(topic)?.kind {
            GossipsubKind::Block => Ok(Self::Block(
                SignedBlockWithAttestation::from_ssz_default(data)
                    .context("Failed to decode SignedBlockWithAttestation")?,
            )),
            GossipsubKind::Attestation => Ok(Self::Attestation(
                SignedAttestation::from_ssz_default(data)
                    .context("Failed to decode SignedAttestation")?,
            )),
        }
    }
}
