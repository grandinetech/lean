use std::sync::Arc;
use networking::gossipsub::message::{GossipsubMessage, SnappyDecompressFn};


#[test]
fn test_realistic_blockchain_scenarios() {
    let scenarios: Vec<(&[u8], &[u8])> = vec![
        (b"/eth2/beacon_block/ssz_snappy" as &[u8], b"beacon_block_ssz_data" as &[u8]),
        (b"/eth2/beacon_aggregate_and_proof/ssz_snappy" as &[u8], b"aggregate_proof_ssz" as &[u8]),
        (b"/eth2/voluntary_exit/ssz_snappy" as &[u8], b"voluntary_exit_message" as &[u8]),
    ];

    let mock_snappy_decompress: SnappyDecompressFn = Arc::new(move |input: &[u8]| {
        // Mock decompression logic for testing
        let mut result = input.to_vec();
        result.extend_from_slice(b"_decompressed");
        Ok(result) // In real tests, this would decompress the input
    });

    let mut messages = Vec::new();
    for (topic, data) in scenarios {
        let msg_with_snappy = GossipsubMessage::new(
            topic.to_vec(),
            data.to_vec(),
            Some(mock_snappy_decompress.clone()),
        );
        let msg_no_snappy = GossipsubMessage::new(
            topic.to_vec(),
            data.to_vec(),
            None,
        );
        messages.extend([msg_with_snappy, msg_no_snappy]);
    }

    let ids = messages.iter().map(|msg| msg.id()).collect::<Vec<_>>();

    assert!(ids.len() == ids.iter().collect::<std::collections::HashSet<_>>().len());
    for msg_id in ids {
        assert!(msg_id.as_bytes().len() == 20);
    }

    for i in (0..messages.len()).step_by(2) {
        let with_snappy_id = messages[i].id();
        let without_snappy_id = messages[i + 1].id();
        assert_ne!(with_snappy_id, without_snappy_id);
    }
}
