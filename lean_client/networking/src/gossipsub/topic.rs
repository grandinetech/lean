use alloy_primitives::hex::ToHexExt;
use libp2p::gossipsub::{IdentTopic, TopicHash};

pub const TOPIC_PREFIX: &str = "leanconsensus";
pub const SSZ_SNAPPY_ENCODING_POSTFIX: &str = "ssz_snappy";

pub const BLOCK_TOPIC: &str = "block";
pub const VOTE_TOPIC: &str = "vote";

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct GossipsubTopic {
    pub fork: String,
    pub kind: GossipsubKind,
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq)]
pub enum GossipsubKind {
    Block,
    Vote,
}

pub fn get_topics(fork: String) -> Vec<GossipsubTopic> {
    vec![
        GossipsubTopic {
            fork: fork.clone(),
            kind: GossipsubKind::Block,
        },
        GossipsubTopic {
            fork: fork.clone(),
            kind: GossipsubKind::Vote,
        },
    ]
}

impl GossipsubTopic {
    pub fn decode(topic: &TopicHash) -> Result<Self, String> {
        let topic_parts = Self::split_topic(topic)?;
        Self::validate_parts(&topic_parts, topic)?;
        let fork = Self::extract_fork(&topic_parts);
        let kind = Self::extract_kind(&topic_parts)?;

        Ok(GossipsubTopic { fork, kind })
    }

    fn split_topic(topic: &TopicHash) -> Result<Vec<&str>, String> {
        let parts: Vec<&str> = topic.as_str().trim_start_matches('/').split('/').collect();

        if parts.len() != 4 {
            return Err(format!(
                "Invalid topic part count: {topic:?}"
            ));
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
            VOTE_TOPIC => Ok(GossipsubKind::Vote),
            other => Err(format!("Invalid topic kind: {other:?}")),
        }
    }
}

impl std::fmt::Display for GossipsubTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "/{}/{}/{}/{}",
            TOPIC_PREFIX,
            self.fork,
            self.kind,
            SSZ_SNAPPY_ENCODING_POSTFIX
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
        let kind_str = match &val.kind {
            GossipsubKind::Block => BLOCK_TOPIC,
            GossipsubKind::Vote => VOTE_TOPIC,
        };
        TopicHash::from_raw(format!(
            "/{}/{}/{}/{}",
            TOPIC_PREFIX,
            val.fork,
            kind_str,
            SSZ_SNAPPY_ENCODING_POSTFIX
        ))
    }
}

impl std::fmt::Display for GossipsubKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipsubKind::Block => write!(f, "{BLOCK_TOPIC}"),
            GossipsubKind::Vote => write!(f, "{VOTE_TOPIC}"),
        }
    }
}
