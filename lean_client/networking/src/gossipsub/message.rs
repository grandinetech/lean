use crate::gossipsub::topic::GossipsubKind;
use crate::gossipsub::topic::GossipsubTopic;
use containers::SignedAttestation;
use containers::SignedBlockWithAttestation;
use libp2p::gossipsub::TopicHash;
use ssz::SszReadDefault as _;

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
