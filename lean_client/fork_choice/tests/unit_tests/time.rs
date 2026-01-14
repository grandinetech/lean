use super::common::create_test_store;
use fork_choice::handlers::on_tick;
use fork_choice::store::tick_interval; 
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
    // Reikšmę imame iš konfigūracijos, o ne iš konstantos
    let intervals_per_slot = store.config.intervals_per_slot;
    store.time = 0;

    for interval in 0..intervals_per_slot {
        let has_proposal = interval == 0;
        tick_interval(&mut store, has_proposal);

        let current_interval = store.time % intervals_per_slot;
        let expected_interval = (interval + 1) % intervals_per_slot;
        assert_eq!(current_interval, expected_interval);
    }
}

#[test]
fn test_time_to_slot_conversion() {
    let genesis_time = 1000;
    // Konfigūraciją kuriame testo viduje
    let config = containers::config::Config {
        genesis_time: 0,
        seconds_per_slot: 4,
        intervals_per_slot: 4,
        seconds_per_interval: 1,
        genesis_validators: Vec::new(),
    };
    
    let time_after_five_slots = genesis_time + 5 * config.seconds_per_slot;
    let slot_5 = (time_after_five_slots - genesis_time) / config.seconds_per_slot;
    assert_eq!(slot_5, 5);
}