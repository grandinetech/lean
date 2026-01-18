use crate::gossipsub::mcache::{MessageCache, SeenCache};
use crate::gossipsub::message::RawGossipsubMessage;
use containers::Bytes20;

#[test]
fn test_cache_put_and_get() {
    let mut cache = MessageCache::new(6, 3);
    let message = RawGossipsubMessage::new(b"topic".to_vec(), b"data".to_vec(), None);
    
    assert!(cache.put("topic".to_string(), message.clone()));
    assert!(!cache.put("topic".to_string(), message.clone())); // Duplicate
    
    let retrieved = cache.get(&message.id());
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id(), message.id());
}

#[test]
fn test_cache_has() {
    let mut cache = MessageCache::new(6, 3);
    let message = RawGossipsubMessage::new(b"topic".to_vec(), b"data".to_vec(), None);
    
    assert!(!cache.has(&message.id()));
    cache.put("topic".to_string(), message.clone());
    assert!(cache.has(&message.id()));
}

#[test]
fn test_cache_shift() {
    let mut cache = MessageCache::new(3, 2);
    
    let mut messages = Vec::new();
    for i in 0..5 {
        let msg = RawGossipsubMessage::new(
            b"topic".to_vec(),
            format!("data{}", i).into_bytes(),
            None,
        );
        cache.put("topic".to_string(), msg.clone());
        messages.push(msg);
        cache.shift();
    }
    
    // Old messages should be evicted
    assert!(!cache.has(&messages[0].id()));
    assert!(!cache.has(&messages[1].id()));
}

#[test]
fn test_get_gossip_ids() {
    let mut cache = MessageCache::new(6, 3);
    
    let msg1 = RawGossipsubMessage::new(b"topic1".to_vec(), b"data1".to_vec(), None);
    let msg2 = RawGossipsubMessage::new(b"topic2".to_vec(), b"data2".to_vec(), None);
    let msg3 = RawGossipsubMessage::new(b"topic1".to_vec(), b"data3".to_vec(), None);
    
    cache.put("topic1".to_string(), msg1.clone());
    cache.put("topic2".to_string(), msg2.clone());
    cache.put("topic1".to_string(), msg3.clone());
    
    let gossip_ids = cache.get_gossip_ids("topic1");
    
    assert!(gossip_ids.contains(&msg1.id()));
    assert!(!gossip_ids.contains(&msg2.id()));
    assert!(gossip_ids.contains(&msg3.id()));
}

#[test]
fn test_seen_cache_add_and_check() {
    let mut cache = SeenCache::new(60);
    let msg_id = Bytes20::new([1u8; 20]);
    
    assert!(!cache.has(&msg_id));
    assert!(cache.add(msg_id.clone(), 1000.0));
    assert!(cache.has(&msg_id));
    assert!(!cache.add(msg_id.clone(), 1001.0)); // Duplicate
}

#[test]
fn test_seen_cache_cleanup() {
    let mut cache = SeenCache::new(10);
    let msg_id = Bytes20::new([1u8; 20]);
    
    cache.add(msg_id.clone(), 1000.0);
    assert!(cache.has(&msg_id));
    
    let removed = cache.cleanup(1015.0);
    assert_eq!(removed, 1);
    assert!(!cache.has(&msg_id));
}
