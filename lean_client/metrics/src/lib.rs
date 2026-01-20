pub mod server;

use prometheus::{Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    peers: IntGauge,
    validators_total: IntGauge,
    validators_active: IntGauge,
    peer_connection_events: IntCounterVec,
    peer_disconnection_events: IntCounterVec,
    // Fork-Choice
    current_slot: IntGauge,
    safe_target_slot: IntGauge,
    fork_choice_block_processing_time: HistogramVec,
    attestations_valid: IntCounterVec,
    attestations_invalid: IntCounterVec,
    attestation_validation_time: HistogramVec,
    fork_choice_reorgs: IntCounterVec,
    fork_choice_reorg_depth: HistogramVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let peers = IntGauge::with_opts(Opts::new("network_peers_connected", "Number of connected peers")).unwrap();
        registry.register(Box::new(peers.clone())).unwrap();

        let validators_total = IntGauge::with_opts(Opts::new("validators_total", "Number of validators in registry")).unwrap();
        registry.register(Box::new(validators_total.clone())).unwrap();

        let validators_active = IntGauge::with_opts(Opts::new("validators_active", "Number of active validators")).unwrap();
        registry.register(Box::new(validators_active.clone())).unwrap();

        // Network
        let peer_connection_events = IntCounterVec::new(
            Opts::new("lean_peer_connection_events_total", "Total number of peer connection events"),
            &["direction", "result"],
        ).unwrap();
        registry.register(Box::new(peer_connection_events.clone())).unwrap();

        let peer_disconnection_events = IntCounterVec::new(
            Opts::new("lean_peer_disconnection_events_total", "Total number of peer disconnection events"),
            &["direction", "reason"],
        ).unwrap();
        registry.register(Box::new(peer_disconnection_events.clone())).unwrap();

        // Fork-Choice
        let current_slot = IntGauge::with_opts(Opts::new("lean_current_slot", "Current slot of the lean chain")).unwrap();
        registry.register(Box::new(current_slot.clone())).unwrap();

        let safe_target_slot = IntGauge::with_opts(Opts::new("lean_safe_target_slot", "Safe target slot")).unwrap();
        registry.register(Box::new(safe_target_slot.clone())).unwrap();

        let fork_choice_block_processing_time = HistogramVec::new(
            HistogramOpts::new("lean_fork_choice_block_processing_time_seconds", "Time taken to process block")
                .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]),
            &[],
        ).unwrap();
        registry.register(Box::new(fork_choice_block_processing_time.clone())).unwrap();

        let attestations_valid = IntCounterVec::new(
            Opts::new("lean_attestations_valid_total", "Total number of valid attestations"),
            &["source"],
        ).unwrap();
        registry.register(Box::new(attestations_valid.clone())).unwrap();

        let attestations_invalid = IntCounterVec::new(
            Opts::new("lean_attestations_invalid_total", "Total number of invalid attestations"),
            &["source"],
        ).unwrap();
        registry.register(Box::new(attestations_invalid.clone())).unwrap();

        let attestation_validation_time = HistogramVec::new(
            HistogramOpts::new("lean_attestation_validation_time_seconds", "Time taken to validate attestation")
                .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]),
            &[],
        ).unwrap();
        registry.register(Box::new(attestation_validation_time.clone())).unwrap();

        let fork_choice_reorgs = IntCounterVec::new(
            Opts::new("lean_fork_choice_reorgs_total", "Total number of fork choice reorgs"),
            &[],
        ).unwrap();
        registry.register(Box::new(fork_choice_reorgs.clone())).unwrap();

        let fork_choice_reorg_depth = HistogramVec::new(
            HistogramOpts::new("lean_fork_choice_reorg_depth", "Depth of fork choice reorgs (in blocks)")
                .buckets(vec![1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 20.0, 30.0, 50.0, 100.0]),
            &[],
        ).unwrap();
        registry.register(Box::new(fork_choice_reorg_depth.clone())).unwrap();

        Self {
            registry,
            peers,
            validators_total,
            validators_active,
            peer_connection_events,
            peer_disconnection_events,
            current_slot,
            safe_target_slot,
            fork_choice_block_processing_time,
            attestations_valid,
            attestations_invalid,
            attestation_validation_time,
            fork_choice_reorgs,
            fork_choice_reorg_depth,
        }
    }

    pub fn gather(&self) -> String {
        let metric_families = self.registry.gather();
        let mut buffer = Vec::<u8>::new();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).expect("failed to encode metrics");
        String::from_utf8(buffer).expect("metrics not utf8")
    }

    pub fn set_peers(&self, v: i64) {
        self.peers.set(v);
    }

    pub fn set_validators_total(&self, v: i64) {
        self.validators_total.set(v);
    }

    pub fn set_validators_active(&self, v: i64) {
        self.validators_active.set(v);
    }

    // Network
    pub fn inc_peer_connection(&self, direction: &str, result: &str) {
        self.peer_connection_events.with_label_values(&[direction, result]).inc();
    }

    pub fn inc_peer_disconnection(&self, direction: &str, reason: &str) {
        self.peer_disconnection_events.with_label_values(&[direction, reason]).inc();
    }

    // Fork-Choice
    pub fn set_current_slot(&self, v: i64) {
        self.current_slot.set(v);
    }

    pub fn set_safe_target_slot(&self, v: i64) {
        self.safe_target_slot.set(v);
    }

    pub fn observe_block_processing_time(&self, duration: f64) {
        self.fork_choice_block_processing_time.with_label_values::<&str>(&[]).observe(duration);
    }

    pub fn inc_attestations_valid(&self, source: &str) {
        self.attestations_valid.with_label_values(&[source]).inc();
    }

    pub fn inc_attestations_invalid(&self, source: &str) {
        self.attestations_invalid.with_label_values(&[source]).inc();
    }

    pub fn observe_attestation_validation_time(&self, duration: f64) {
        self.attestation_validation_time.with_label_values::<&str>(&[]).observe(duration);
    }

    pub fn inc_fork_choice_reorgs(&self) {
        self.fork_choice_reorgs.with_label_values::<&str>(&[]).inc();
    }

    pub fn observe_fork_choice_reorg_depth(&self, depth: f64) {
        self.fork_choice_reorg_depth.with_label_values::<&str>(&[]).observe(depth);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

pub type SharedMetrics = Arc<Metrics>;
