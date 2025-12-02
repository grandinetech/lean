use crate::gossipsub::topic::{
    get_topics, GossipsubKind, GossipsubTopic, ATTESTATION_TOPIC, BLOCK_TOPIC,
    SSZ_SNAPPY_ENCODING_POSTFIX, TOPIC_PREFIX,
};
use libp2p::gossipsub::TopicHash;

#[test]
fn test_topic_decode_valid_block() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(decoded.fork, "genesis");
    assert_eq!(decoded.kind, GossipsubKind::Block);
}

#[test]
fn test_topic_decode_valid_attestation() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", ATTESTATION_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(decoded.fork, "genesis");
    assert_eq!(decoded.kind, GossipsubKind::Attestation);
}

#[test]
fn test_topic_decode_invalid_prefix() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        "wrongprefix", "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_decode_invalid_encoding() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", BLOCK_TOPIC, "wrong_encoding"
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_decode_invalid_kind() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", "invalid_kind", SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic_hash = TopicHash::from_raw(topic_str);

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_decode_invalid_part_count() {
    let topic_hash = TopicHash::from_raw("/only/two/parts");

    let result = GossipsubTopic::decode(&topic_hash);
    assert!(result.is_err());
}

#[test]
fn test_topic_to_string() {
    let topic = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Block,
    };

    let topic_str = topic.to_string();
    assert_eq!(
        topic_str,
        format!(
            "/{}/{}/{}/{}",
            TOPIC_PREFIX, "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
        )
    );
}

#[test]
fn test_topic_encoding_decoding_roundtrip() {
    let original = GossipsubTopic {
        fork: "testfork".to_string(),
        kind: GossipsubKind::Attestation,
    };

    let topic_hash: TopicHash = original.clone().into();
    let decoded = GossipsubTopic::decode(&topic_hash).unwrap();

    assert_eq!(original.fork, decoded.fork);
    assert_eq!(original.kind, decoded.kind);
}

#[test]
fn test_get_topics_all_same_fork() {
    let topics = get_topics("myfork".to_string());

    assert_eq!(topics.len(), 2);

    let kinds: Vec<_> = topics.iter().map(|t| t.kind).collect();
    assert!(kinds.contains(&GossipsubKind::Block));
    assert!(kinds.contains(&GossipsubKind::Attestation));

    // All should have the same fork
    for topic in &topics {
        assert_eq!(topic.fork, "myfork");
    }
}

#[test]
fn test_gossipsub_kind_display() {
    assert_eq!(GossipsubKind::Block.to_string(), BLOCK_TOPIC);
    assert_eq!(GossipsubKind::Attestation.to_string(), ATTESTATION_TOPIC);
}

#[test]
fn test_topic_equality() {
    let topic1 = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Block,
    };
    let topic2 = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Block,
    };
    let topic3 = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Attestation,
    };
    let topic4 = GossipsubTopic {
        fork: "genesis2".to_string(),
        kind: GossipsubKind::Attestation,
    };

    assert_eq!(topic1, topic2);
    assert_ne!(topic1, topic3);
    assert_ne!(topic1, topic4);
}

#[test]
fn test_topic_hash_conversion() {
    let topic = GossipsubTopic {
        fork: "genesis".to_string(),
        kind: GossipsubKind::Block,
    };

    let hash: TopicHash = topic.into();
    let expected = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );

    assert_eq!(hash.as_str(), expected);
}
