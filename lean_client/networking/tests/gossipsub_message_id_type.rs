use networking::gossipsub::message::MessageId;

#[test]
fn test_message_id_validation() {
    let invalid_cases: &[(&[u8], &str)] = &[
        (b"" as &[u8], "empty bytes"),
        (b"short" as &[u8], "too short"),
        (b"too_long_message_id_bytes" as &[u8], "too long"),
    ];

    for (input, description) in invalid_cases {
        let result = MessageId::try_from(*input);
        assert!(result.is_err(), "Expected error for {}: {:?}", description, result);
    }
}
