use crate::gossipsub::control::{ControlMessage, Graft, IDontWant, IHave, IWant, Prune};
use containers::Bytes20;

#[test]
fn test_graft_creation() {
    let graft = Graft {
        topic_id: "test_topic".to_string(),
    };
    assert_eq!(graft.topic_id, "test_topic");
}

#[test]
fn test_prune_creation() {
    let prune = Prune {
        topic_id: "test_topic".to_string(),
    };
    assert_eq!(prune.topic_id, "test_topic");
}

#[test]
fn test_ihave_creation() {
    let msg_ids = vec![Bytes20::from([1u8; 20]), Bytes20::from([2u8; 20])];
    let ihave = IHave {
        topic_id: "test_topic".to_string(),
        message_ids: msg_ids.clone(),
    };

    assert_eq!(ihave.topic_id, "test_topic");
    assert_eq!(ihave.message_ids.len(), 2);
}

#[test]
fn test_iwant_creation() {
    let msg_ids = vec![Bytes20::from([1u8; 20])];
    let iwant = IWant {
        message_ids: msg_ids,
    };

    assert_eq!(iwant.message_ids.len(), 1);
}

#[test]
fn test_idontwant_creation() {
    let msg_ids = vec![Bytes20::from([1u8; 20])];
    let idontwant = IDontWant {
        message_ids: msg_ids,
    };

    assert_eq!(idontwant.message_ids.len(), 1);
}

#[test]
fn test_control_message_aggregation() {
    let graft = Graft {
        topic_id: "topic1".to_string(),
    };
    let prune = Prune {
        topic_id: "topic2".to_string(),
    };

    let control = ControlMessage {
        grafts: vec![graft],
        prunes: vec![prune],
        ihaves: vec![],
        iwants: vec![],
        idontwants: vec![],
    };

    assert_eq!(control.grafts.len(), 1);
    assert_eq!(control.prunes.len(), 1);
    assert!(!control.is_empty());
}

#[test]
fn test_control_message_empty_check() {
    let empty_control = ControlMessage::default();
    assert!(empty_control.is_empty());

    let non_empty = ControlMessage {
        grafts: vec![Graft {
            topic_id: "topic".to_string(),
        }],
        ..Default::default()
    };
    assert!(!non_empty.is_empty());
}
