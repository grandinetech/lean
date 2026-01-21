use crate::gossipsub::message::{RawGossipsubMessage, SnappyDecompressor};
use std::sync::Arc;

struct TestDecompressor;

impl SnappyDecompressor for TestDecompressor {
    fn decompress(&self, _data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(b"decompressed_test_data".to_vec())
    }
}

struct FailingDecompressor;

impl SnappyDecompressor for FailingDecompressor {
    fn decompress(&self, _data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Err("Decompression failed".into())
    }
}

#[test]
fn test_message_id_computation_no_snappy() {
    let topic = b"test_topic";
    let raw_data = b"raw_test_data";

    let message = RawGossipsubMessage::new(topic.to_vec(), raw_data.to_vec(), None);
    let message_id = message.id();

    assert_eq!(message_id.0.len(), 20);
}

#[test]
fn test_message_id_computation_with_snappy() {
    let topic = b"test_topic";
    let raw_data = b"raw_test_data";

    let message = RawGossipsubMessage::new(
        topic.to_vec(),
        raw_data.to_vec(),
        Some(Arc::new(TestDecompressor)),
    );
    let message_id = message.id();

    assert_eq!(message_id.0.len(), 20);
}

#[test]
fn test_message_id_computation_snappy_fails() {
    let topic = b"test_topic";
    let raw_data = b"raw_test_data";

    let message = RawGossipsubMessage::new(
        topic.to_vec(),
        raw_data.to_vec(),
        Some(Arc::new(FailingDecompressor)),
    );
    let message_id = message.id();

    assert_eq!(message_id.0.len(), 20);
}

#[test]
fn test_message_id_determinism() {
    let topic = b"test_topic";
    let data = b"test_data";

    let message1 = RawGossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        Some(Arc::new(TestDecompressor)),
    );
    let message2 = RawGossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        Some(Arc::new(TestDecompressor)),
    );

    assert_eq!(message1.id(), message2.id());
}

#[test]
fn test_message_uniqueness() {
    let test_cases = vec![
        (b"topic1".to_vec(), b"data".to_vec()),
        (b"topic2".to_vec(), b"data".to_vec()),
        (b"topic".to_vec(), b"data1".to_vec()),
        (b"topic".to_vec(), b"data2".to_vec()),
    ];

    let messages: Vec<_> = test_cases
        .into_iter()
        .map(|(topic, data)| RawGossipsubMessage::new(topic, data, None))
        .collect();

    let ids: Vec<_> = messages.iter().map(|msg| msg.id()).collect();
    let unique_ids: std::collections::HashSet<_> = ids.iter().collect();

    assert_eq!(ids.len(), unique_ids.len());
}
