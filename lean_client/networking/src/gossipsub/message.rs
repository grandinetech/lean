use crate::gossipsub::topic::GossipsubKind;
use crate::gossipsub::topic::GossipsubTopic;
use containers::{SignedAggregatedAttestation, SignedAttestation, SignedBlockWithAttestation};
use libp2p::gossipsub::TopicHash;
use ssz::SszReadDefault as _;

/// Devnet-3 gossipsub message types
pub enum GossipsubMessage {
    Block(SignedBlockWithAttestation),
    /// Attestation from a specific subnet (devnet-3)
    AttestationSubnet {
        subnet_id: u64,
        attestation: SignedAttestation,
    },
    /// Aggregated attestation (devnet-3)
    Aggregation(SignedAggregatedAttestation),
}

impl GossipsubMessage {
    pub fn decode(topic: &TopicHash, data: &[u8]) -> Result<Self, String> {
        match GossipsubTopic::decode(topic)?.kind {
            GossipsubKind::Block => Ok(Self::Block(
                SignedBlockWithAttestation::from_ssz_default(data)
                    .map_err(|e| format!("{:?}", e))?,
            )),
            GossipsubKind::AttestationSubnet(subnet_id) => Ok(Self::AttestationSubnet {
                subnet_id,
                attestation: SignedAttestation::from_ssz_default(data)
                    .map_err(|e| format!("{:?}", e))?,
            }),
            GossipsubKind::Aggregation => Ok(Self::Aggregation(
                SignedAggregatedAttestation::from_ssz_default(data)
                    .map_err(|e| format!("{:?}", e))?,
            )),
        }
    }
}
