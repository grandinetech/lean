use rstest::rstest;
use networking::gossipsub::message::{GossipsubMessage, SnappyDecompressFn};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

const MESSAGE_DOMAIN_INVALID_SNAPPY: &[u8] = b"\x00\x00\x00\x00";
const MESSAGE_DOMAIN_VALID_SNAPPY: &[u8] = b"\x01\x00\x00\x00";

#[rstest]
#[case(false, false, MESSAGE_DOMAIN_INVALID_SNAPPY)]
#[case(true, true, MESSAGE_DOMAIN_VALID_SNAPPY)]
#[case(true, false, MESSAGE_DOMAIN_INVALID_SNAPPY)]
fn test_message_id_computation(
    #[case] has_snappy: bool,
    #[case] decompress_succeeds: bool,
    #[case] expected_domain: &[u8],
) {
    use networking::gossipsub::message::GossipsubMessage;

    let topic = b"test_topic";
    let data = b"test_data";
    let decompressed_data = b"decompressed_test_data";

    let mut snappy_decompress = None;

    if has_snappy {
        if decompress_succeeds {
            let decompress_fn: SnappyDecompressFn = Arc::new(move |_input: &[u8]| {
                Ok(decompressed_data.to_vec())
            });
            snappy_decompress = Some(decompress_fn);
        } else {

            let decompress_fn: SnappyDecompressFn = Arc::new(move |_input: &[u8]| {
                Err("Decompression failed".to_string())
            });
            snappy_decompress = Some(decompress_fn);
        }
    }

    let message = GossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        snappy_decompress.clone(),
    );
    let message_id = message.id();

    assert!(message_id.as_bytes().len() == 20);

    let message2 = GossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        snappy_decompress,
    );
    let message_id2 = message2.id();
    assert_eq!(message_id, message_id2);

    if has_snappy {
        let msg_no_snappy = GossipsubMessage::new(
            topic.to_vec(),
            data.to_vec(),
            None,
        );
        if decompress_succeeds {
            assert_ne!(message_id, msg_no_snappy.id());
        } else {
            assert!(msg_no_snappy.id().as_bytes().len() == 20)
        }
    }
}

#[test]
fn test_message_id_caching() {
    // Test that the message ID is cached after the first computation
    let topic = b"test_topic";
    let data = b"test_data";

    let decompress_calls = Arc::new(AtomicUsize::new(0));
    let decompress_calls_clone = decompress_calls.clone();


    let counting_decompress: SnappyDecompressFn = Arc::new(move |_input: &[u8]| {
        decompress_calls_clone.fetch_add(1, Ordering::SeqCst);
        Ok(b"decompressed_test_data".to_vec())
    });

    let message = GossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        Some(counting_decompress),
    );

    let first_id = message.id();
    let second_id = message.id();

    assert!(decompress_calls.load(Ordering::SeqCst) == 1);

    assert_eq!(first_id, second_id);

    let message2 = GossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        None,
    );
    let message3 = GossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        None,
    );
    assert_eq!(message2.id(), message3.id());
}

#[rstest]
#[case::empty_topic_and_data(b"", b"", "empty topic and data")]
#[case::basic_case_1(b"topic", b"data1", "basic case 1")]
#[case::basic_case_2(b"topic", b"data2", "basic case 2")]
#[case::different_topic_1(b"topic1", b"data", "different topic")]
#[case::different_topic_2(b"topic2", b"data", "different topic")]
#[case::large_inputs(&[b'x'; 1000], &[b'y'; 5000], "large inputs")]
#[case::binary_data(b"\x00\xff\x01\xfe", &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], "binary data")]
fn test_message_id_edge_cases(
    #[case] topic: &[u8],
    #[case] data: &[u8],
    #[case] description: &str,
) {
    let message = GossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        None,
    );
    let message_id = message.id();

    assert!(message_id.as_bytes().len() == 20);

    let message2 = GossipsubMessage::new(
        topic.to_vec(),
        data.to_vec(),
        None,
    );
    assert!(message_id == message2.id());
}

#[test]
fn test_message_uniqueness_and_collision_resistance() {
    // Test cases designed to catch collision vulnerabilities
    let test_cases: Vec<(&[u8], &[u8])> = vec![
        // Basic different inputs
        (b"topic1", b"data"),
        (b"topic2", b"data"),
        (b"topic", b"data1"),
        (b"topic", b"data2"),
        // Topic/data swapping
        (b"abc", b"def"),
        (b"def", b"abc"),
        // Length-based attacks
        (b"ab", b"cd"),
        (b"a", b"bcd"),
        // Null byte insertion
        (b"topic", b"data"),
        (b"top\x00ic", b"data"),
    ];

    let messages : Vec<GossipsubMessage> = test_cases
        .iter()
        .map(|(topic, data)| GossipsubMessage::new(topic.to_vec(), data.to_vec(), None))
        .collect();
    let ids = messages
        .iter()
        .map(|msg| msg.id())
        .collect::<Vec<_>>();

    assert!(ids.len() == ids.iter().collect::<std::collections::HashSet<_>>().len());

    for id in &ids {
        assert!(id.as_bytes().len() == 20);
    }
}