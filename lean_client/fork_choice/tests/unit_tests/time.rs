use super::common::create_test_store;
use fork_choice::handlers::on_tick;
use fork_choice::store::{
    INTERVALS_PER_SLOT, MILLIS_PER_INTERVAL, SECONDS_PER_SLOT, tick_interval,
};

#[test]
fn test_on_tick_basic() {
    let mut store = create_test_store();
    let initial_time = store.time;
    // on_tick now expects milliseconds (devnet-3)
    let target_time_millis = (store.config.genesis_time + 200) * 1000;

    on_tick(&mut store, target_time_millis, true);

    assert!(store.time > initial_time);
}

#[test]
fn test_on_tick_no_proposal() {
    let mut store = create_test_store();
    let initial_time = store.time;
    // on_tick now expects milliseconds (devnet-3)
    let target_time_millis = (store.config.genesis_time + 100) * 1000;

    on_tick(&mut store, target_time_millis, false);

    assert!(store.time >= initial_time);
}

#[test]
fn test_on_tick_already_current() {
    let mut store = create_test_store();
    let initial_time = store.time;
    // on_tick now expects milliseconds (devnet-3)
    // Convert initial_time (in intervals) to seconds, then to milliseconds
    let current_target_millis =
        (store.config.genesis_time * 1000) + (initial_time * MILLIS_PER_INTERVAL);

    // Try to advance to current time
    on_tick(&mut store, current_target_millis, true);

    // Should not change significantly
    assert_eq!(store.time, initial_time);
}

#[test]
fn test_on_tick_small_increment() {
    let mut store = create_test_store();
    let initial_time = store.time;
    // on_tick now expects milliseconds (devnet-3)
    // Advance by just 1 second (1000ms)
    let target_time_millis =
        (store.config.genesis_time * 1000) + (initial_time * MILLIS_PER_INTERVAL) + 1000;

    on_tick(&mut store, target_time_millis, false);

    // Should advance or stay same depending on interval rounding, but definitely not go back
    assert!(store.time >= initial_time);
}

#[test]
fn test_tick_interval_basic() {
    let mut store = create_test_store();
    let initial_time = store.time;

    tick_interval(&mut store, false);

    assert_eq!(store.time, initial_time + 1);
}

#[test]
fn test_tick_interval_with_proposal() {
    let mut store = create_test_store();
    let initial_time = store.time;

    tick_interval(&mut store, true);

    assert_eq!(store.time, initial_time + 1);
}

#[test]
fn test_tick_interval_sequence() {
    let mut store = create_test_store();
    let initial_time = store.time;

    for i in 0..5 {
        tick_interval(&mut store, i % 2 == 0);
    }

    assert_eq!(store.time, initial_time + 5);
}

#[test]
fn test_tick_interval_actions_by_phase() {
    let mut store = create_test_store();

    // Reset store time to 0 relative to genesis for clean testing
    store.time = 0;

    // Tick through a complete slot cycle
    for interval in 0..INTERVALS_PER_SLOT {
        let has_proposal = interval == 0; // Proposal only in first interval
        tick_interval(&mut store, has_proposal);

        let current_interval = store.time % INTERVALS_PER_SLOT;
        let expected_interval = (interval + 1) % INTERVALS_PER_SLOT;
        assert_eq!(current_interval, expected_interval);
    }
}

#[test]
fn test_slot_time_calculations() {
    let genesis_time = 1000;

    // Slot 0
    let slot_0_time = genesis_time + (0 * SECONDS_PER_SLOT);
    assert_eq!(slot_0_time, genesis_time);

    // Slot 1
    let slot_1_time = genesis_time + (1 * SECONDS_PER_SLOT);
    assert_eq!(slot_1_time, genesis_time + SECONDS_PER_SLOT);

    // Slot 10
    let slot_10_time = genesis_time + (10 * SECONDS_PER_SLOT);
    assert_eq!(slot_10_time, genesis_time + 10 * SECONDS_PER_SLOT);
}

#[test]
fn test_time_to_slot_conversion() {
    let genesis_time = 1000;

    // Time at genesis should be slot 0
    let time_at_genesis = genesis_time;
    let slot_0 = (time_at_genesis - genesis_time) / SECONDS_PER_SLOT;
    assert_eq!(slot_0, 0);

    // Time after one slot duration should be slot 1
    let time_after_one_slot = genesis_time + SECONDS_PER_SLOT;
    let slot_1 = (time_after_one_slot - genesis_time) / SECONDS_PER_SLOT;
    assert_eq!(slot_1, 1);

    // Time after multiple slots
    let time_after_five_slots = genesis_time + 5 * SECONDS_PER_SLOT;
    let slot_5 = (time_after_five_slots - genesis_time) / SECONDS_PER_SLOT;
    assert_eq!(slot_5, 5);
}

#[test]
fn test_interval_calculations() {
    // Test interval arithmetic
    let total_intervals = 10;
    let slot_number = total_intervals / INTERVALS_PER_SLOT;
    let interval_in_slot = total_intervals % INTERVALS_PER_SLOT;

    // INTERVALS_PER_SLOT is 5 (devnet-3)
    // 10 intervals = 2 slots (10 intervals) + 0 intervals
    assert_eq!(slot_number, 2);
    assert_eq!(interval_in_slot, 0);

    // Test with 8 intervals
    let total_8 = 8;
    let slot_8 = total_8 / INTERVALS_PER_SLOT;
    let interval_8 = total_8 % INTERVALS_PER_SLOT;
    // 8 intervals = 1 slot (5 intervals) + 3 intervals
    assert_eq!(slot_8, 1);
    assert_eq!(interval_8, 3);

    // Test boundary cases
    let boundary_intervals = INTERVALS_PER_SLOT;
    let boundary_slot = boundary_intervals / INTERVALS_PER_SLOT;
    let boundary_interval = boundary_intervals % INTERVALS_PER_SLOT;

    assert_eq!(boundary_slot, 1); // Start of next slot
    assert_eq!(boundary_interval, 0); // First interval of slot
}

#[test]
fn test_millis_per_interval() {
    // Devnet-3: 4 seconds per slot, 5 intervals = 800ms per interval
    assert_eq!(MILLIS_PER_INTERVAL, 800);

    // Verify no integer truncation: 4 * 1000 = 5 * 800
    assert_eq!(
        SECONDS_PER_SLOT * 1000,
        MILLIS_PER_INTERVAL * INTERVALS_PER_SLOT
    );
}

#[test]
fn test_devnet3_interval_schedule() {
    // Test that 5 intervals are properly cycled through
    let mut store = create_test_store();
    store.time = 0;

    // Tick through a complete slot (5 intervals)
    for i in 0..5 {
        tick_interval(&mut store, i == 0);
    }

    // After 5 ticks, we should be at interval 0 of the next slot
    assert_eq!(store.time, 5);
    assert_eq!(store.time % INTERVALS_PER_SLOT, 0);
}
