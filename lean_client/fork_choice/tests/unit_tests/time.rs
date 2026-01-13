use super::common::create_test_store;
use fork_choice::handlers::on_tick;
use fork_choice::store::{tick_interval, INTERVALS_PER_SLOT, SECONDS_PER_SLOT};
use containers::Slot;
use containers::types::Uint64;

#[test]
fn test_on_tick_basic() {
    let mut store = create_test_store();
    let initial_time = store.time;
    let target_time = store.config.genesis_time + 200; 

    on_tick(&mut store, target_time, true);
    assert!(store.time > initial_time);
}

#[test]
fn test_on_tick_no_proposal() {
    let mut store = create_test_store();
    let initial_time = store.time;
    let target_time = store.config.genesis_time + 100;

    on_tick(&mut store, target_time, false);
    assert!(store.time >= initial_time);
}

#[test]
fn test_on_tick_already_current() {
    let mut store = create_test_store();
    let initial_time = store.time;
    let current_target = store.config.genesis_time + initial_time;

    on_tick(&mut store, current_target, true);
    assert_eq!(store.time, initial_time);
}

#[test]
fn test_tick_interval_actions_by_phase() {
    let mut store = create_test_store();
    store.time = 0;

    for interval in 0..INTERVALS_PER_SLOT {
        let has_proposal = interval == 0;
        tick_interval(&mut store, has_proposal);

        let current_interval = store.time % INTERVALS_PER_SLOT;
        let expected_interval = (interval + 1) % INTERVALS_PER_SLOT;
        assert_eq!(current_interval, expected_interval);
    }
}

#[test]
fn test_time_to_slot_conversion() {
    let genesis_time = 1000;
    let time_after_five_slots = genesis_time + 5 * SECONDS_PER_SLOT;
    let slot_5 = (time_after_five_slots - genesis_time) / SECONDS_PER_SLOT;
    assert_eq!(slot_5, 5);
}