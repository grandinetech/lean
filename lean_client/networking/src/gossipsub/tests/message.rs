use crate::gossipsub::message::GossipsubMessage;
use crate::gossipsub::topic::{
    ATTESTATION_TOPIC, BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX, TOPIC_PREFIX,
};
use libp2p::gossipsub::TopicHash;

#[test]
fn test_message_decode_invalid_topic() {
    let topic = TopicHash::from_raw("/invalid/topic/format");
    let data = b"some_data";

    let result = GossipsubMessage::decode(&topic, data);
    assert!(result.is_err());
}

#[test]
fn test_message_decode_invalid_ssz_for_block() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic = TopicHash::from_raw(topic_str);
    let invalid_ssz = b"not_valid_ssz";

    let result = GossipsubMessage::decode(&topic, invalid_ssz);
    assert!(result.is_err());
}

#[test]
fn test_message_decode_invalid_ssz_for_attestation() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", ATTESTATION_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic = TopicHash::from_raw(topic_str);
    let invalid_ssz = b"not_valid_ssz";

    let result = GossipsubMessage::decode(&topic, invalid_ssz);
    assert!(result.is_err());
}

#[test]
fn test_message_decode_empty_data_fails() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic = TopicHash::from_raw(topic_str);

    let result = GossipsubMessage::decode(&topic, &[]);
    assert!(result.is_err());
}

#[test]
fn test_message_decode_wrong_prefix() {
    let topic = TopicHash::from_raw("/eth2/genesis/block/ssz_snappy");
    let data = b"some_data";

    let result = GossipsubMessage::decode(&topic, data);
    assert!(result.is_err());
}

#[test]
fn test_message_decode_wrong_encoding() {
    let topic_str = format!("/{}/{}/{}/json", TOPIC_PREFIX, "genesis", BLOCK_TOPIC);
    let topic = TopicHash::from_raw(topic_str);
    let data = b"some_data";

    let result = GossipsubMessage::decode(&topic, data);
    assert!(result.is_err());
}

#[test]
fn test_message_decode_unsupported_kind() {
    let topic_str = format!(
        "/{}/{}/{}/{}",
        TOPIC_PREFIX, "genesis", "voluntary_exit", SSZ_SNAPPY_ENCODING_POSTFIX
    );
    let topic = TopicHash::from_raw(topic_str);
    let data = b"some_data";

    let result = GossipsubMessage::decode(&topic, data);
    assert!(result.is_err());
}
