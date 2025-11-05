use crate::gossipsub::topic::GossipsubKind;
use crate::gossipsub::topic::GossipsubTopic;
use containers::ssz::SszReadDefault;
use containers::{SignedBlock, SignedVote};
use libp2p::gossipsub::TopicHash;

pub enum GossipsubMessage {
    Block(SignedBlock),
    Vote(SignedVote),
}

impl GossipsubMessage {
    pub fn decode(topic: &TopicHash, data: &[u8]) -> Result<Self, String> {
        match GossipsubTopic::decode(topic)?.kind {
            GossipsubKind::Block => Ok(Self::Block(
                SignedBlock::from_ssz_default(data).map_err(|e| format!("{:?}", e))?,
            )),
            GossipsubKind::Vote => Ok(Self::Vote(
                SignedVote::from_ssz_default(data).map_err(|e| format!("{:?}", e))?,
            )),
        }
    }
}
