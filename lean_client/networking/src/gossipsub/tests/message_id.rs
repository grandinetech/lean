use crate::gossipsub::config::compute_message_id;
use crate::gossipsub::topic::{ATTESTATION_TOPIC, BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX, TOPIC_PREFIX};
use crate::types::MESSAGE_DOMAIN_VALID_SNAPPY;
use libp2p::gossipsub::{Message, TopicHash};
use sha2::{Digest, Sha256};

fn create_test_message(topic: &str, data: Vec<u8>) -> Message {
    Message {
        source: None,
        data,
        sequence_number: None,
        topic: TopicHash::from_raw(topic),
    }
}

#[test]
fn test_message_id_length_20_bytes() {
    let message = create_test_message("/test/topic", b"test_data".to_vec());
    let message_id = compute_message_id(&message);

    assert_eq!(message_id.0.len(), 20);
}

#[test]
fn test_message_id_deterministic() {
    let message1 = create_test_message("/test/topic", b"test_data".to_vec());
    let message2 = create_test_message("/test/topic", b"test_data".to_vec());

    let id1 = compute_message_id(&message1);
    let id2 = compute_message_id(&message2);

    assert_eq!(id1, id2);
}

#[test]
fn test_message_id_different_data() {
    let message1 = create_test_message("/test/topic", b"data1".to_vec());
    let message2 = create_test_message("/test/topic", b"data2".to_vec());

    let id1 = compute_message_id(&message1);
    let id2 = compute_message_id(&message2);

    assert_ne!(id1, id2);
}

#[test]
fn test_message_id_different_topics() {
    let message1 = create_test_message("/topic1", b"same_data".to_vec());
    let message2 = create_test_message("/topic2", b"same_data".to_vec());

    let id1 = compute_message_id(&message1);
    let id2 = compute_message_id(&message2);

    assert_ne!(id1, id2);
}

#[test]
fn test_message_id_edge_cases_empty() {
    let message_empty_data = create_test_message("/topic", vec![]);
    let message_empty_topic = create_test_message("", b"data".to_vec());
    let message_both_empty = create_test_message("", vec![]);

    assert_eq!(compute_message_id(&message_empty_data).0.len(), 20);
    assert_eq!(compute_message_id(&message_empty_topic).0.len(), 20);
    assert_eq!(compute_message_id(&message_both_empty).0.len(), 20);
}

#[test]
fn test_message_id_edge_cases_large_inputs() {
    let large_topic = "x".repeat(1000);
    let large_data = vec![0xFFu8; 5000];

    let message = create_test_message(&large_topic, large_data);
    let id = compute_message_id(&message);

    assert_eq!(id.0.len(), 20);
}

#[test]
fn test_message_id_edge_cases_binary_data() {
    let binary_data: Vec<u8> = (0..=255).collect();
    let message = create_test_message("/binary/topic", binary_data);
    let id = compute_message_id(&message);

    assert_eq!(id.0.len(), 20);
}

#[test]
fn test_message_id_uniqueness_and_collision_resistance() {
    let test_cases = vec![
        // Basic different inputs
        ("/topic1", b"data".to_vec()),
        ("/topic2", b"data".to_vec()),
        ("/topic", b"data1".to_vec()),
        ("/topic", b"data2".to_vec()),
        // Topic/data similarity
        ("/abc", b"def".to_vec()),
        ("/def", b"abc".to_vec()),
        // Length-based variations
        ("/ab", b"cd".to_vec()),
        ("/a", b"bcd".to_vec()),
        // Null byte insertion
        ("/topic", b"data".to_vec()),
        ("/top\x00ic", b"data".to_vec()),
    ];

    let ids: Vec<_> = test_cases
        .iter()
        .map(|(topic, data)| {
            let message = create_test_message(topic, data.clone());
            compute_message_id(&message)
        })
        .collect();

    let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(
        unique_ids.len(),
        ids.len(),
        "Expected all message IDs to be unique"
    );

    for id in &ids {
        assert_eq!(id.0.len(), 20);
    }
}

#[test]
fn test_message_id_uses_valid_snappy_domain() {
    let topic = "/test/topic";
    let data = b"test_data";

    let message = create_test_message(topic, data.to_vec());
    let computed_id = compute_message_id(&message);

    // Manually compute expected ID to verify algorithm
    let topic_bytes = topic.as_bytes();
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(MESSAGE_DOMAIN_VALID_SNAPPY.as_bytes());
    digest_input.extend_from_slice(&(topic_bytes.len()).to_le_bytes());
    digest_input.extend_from_slice(topic_bytes);
    digest_input.extend_from_slice(data);

    let hash = Sha256::digest(&digest_input);
    let expected_id: Vec<u8> = hash[..20].to_vec();

    assert_eq!(computed_id.0, expected_id);
}

#[test]
fn test_realistic_blockchain_scenarios() {
    let scenarios = vec![
        (
            format!(
                "/{}/genesis/{}/{}",
                TOPIC_PREFIX, BLOCK_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
            ),
            b"beacon_block_ssz_data".to_vec(),
        ),
        (
            format!(
                "/{}/genesis/{}/{}",
                TOPIC_PREFIX, ATTESTATION_TOPIC, SSZ_SNAPPY_ENCODING_POSTFIX
            ),
            b"aggregate_proof_ssz".to_vec(),
        ),
    ];

    // All messages should produce valid, unique IDs
    let ids: Vec<_> = scenarios
        .iter()
        .map(|(topic, data)| {
            let message = create_test_message(topic, data.clone());
            compute_message_id(&message)
        })
        .collect();

    let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique_ids.len(), ids.len());

    for id in &ids {
        assert_eq!(id.0.len(), 20);
    }
}
