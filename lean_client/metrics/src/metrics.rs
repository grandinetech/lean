use std::{sync::Arc, time::SystemTime};

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use prometheus::{
    GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    histogram_opts, opts,
};

pub static METRICS: OnceCell<Arc<Metrics>> = OnceCell::new();

#[derive(Debug)]
pub struct Metrics {
    /// Node information: name and version
    lean_node_info: GaugeVec,

    /// Start timestamp
    lean_node_start_time_seconds: IntGauge,

    // PQ Signature metrics
    /// Total number of individual attestation signatures
    pub lean_pq_sig_attestation_signatures_total: IntCounter,

    /// Total number of valid individual attestation signatures
    pub lean_pq_sig_attestation_signatures_valid_total: IntCounter,

    /// Total number of invalid individual attestation signatures
    pub lean_pq_sig_attestation_signatures_invalid_total: IntCounter,

    /// Time taken to sign an attestation
    pub lean_pq_sig_attestation_signing_time_seconds: Histogram,

    /// Time taken to verify an attestation signature
    pub lean_pq_sig_attestation_verification_time_seconds: Histogram,

    /// Total number of aggregated signatures
    pub lean_pq_sig_aggregated_signatures_total: IntCounter,

    /// Total number of attestations included into aggregated signatures
    pub lean_pq_sig_attestations_in_aggregated_signatures_total: IntCounter,

    /// Time taken to build an aggregated attestation signature
    pub lean_pq_sig_aggregated_signatures_building_time_seconds: Histogram,

    /// Time taken to verify an aggregated attestation signature
    pub lean_pq_sig_aggregated_signatures_verification_time_seconds: Histogram,

    /// Total number of valid aggregated signatures
    pub lean_pq_sig_aggregated_signatures_valid_total: IntCounter,

    /// Total number of invalid aggregated signatures
    pub lean_pq_sig_aggregated_signatures_invalid_total: IntCounter,

    // Fork-Choice Metrics
    /// Latest slot of the lean chain
    pub lean_head_slot: IntGauge,

    /// Current slot of the lean chain
    pub lean_current_slot: IntGauge,

    /// Safe target slot
    pub lean_safe_target_slot: IntGauge,

    /// Time taken to process block
    pub lean_fork_choice_block_processing_time_seconds: Histogram,

    /// Total number of valid attestations
    pub lean_aggregator_skipped_total: IntCounterVec,
    pub lean_chain_message_drop_total: IntCounterVec,
    pub lean_attestations_valid_total: IntCounterVec,

    /// Total number of invalid attestations
    pub lean_attestations_invalid_total: IntCounterVec,

    /// Time taken to validate attestation
    pub lean_attestation_validation_time_seconds: Histogram,

    /// Time taken to produce attestations
    pub lean_attestations_production_time_seconds: Histogram,

    /// Total number of fork choice reorgs
    pub lean_fork_choice_reorgs_total: IntCounter,

    /// Depth of fork choice reorgs (in blocks)
    pub lean_fork_choice_reorg_depth: Histogram,

    /// Elapsed time between consecutive chain-task tick intervals
    pub lean_tick_interval_duration_seconds: Histogram,

    // State Transition Metrics
    /// Latest justified slot
    pub lean_latest_justified_slot: IntGauge,

    /// Latest finalized slot
    pub lean_latest_finalized_slot: IntGauge,

    /// Total number of finalization attempts
    pub lean_finalizations_total: IntCounterVec,

    /// Time to process state transition
    pub lean_state_transition_time_seconds: Histogram,

    /// Total number of processed slots
    pub lean_state_transition_slots_processed_total: IntCounter,

    /// Time taken to process slots
    pub lean_state_transition_slots_processing_time_seconds: Histogram,

    /// Time taken to process block
    pub lean_state_transition_block_processing_time_seconds: Histogram,

    /// Total number of processed attestations
    pub lean_state_transition_attestations_processed_total: IntCounter,

    /// Time taken to process attestations
    pub lean_state_transition_attestations_processing_time_seconds: Histogram,

    // Validator metrics
    /// Number of validators managed by a node
    pub lean_validators_count: IntGauge,

    // Network Metrics
    /// Number of connected peers
    pub lean_connected_peers: IntGaugeVec,

    /// Number of peers in the gossipsub mesh
    pub lean_gossip_mesh_peers: IntGaugeVec,

    /// Total number of peer connection events
    lean_peer_connection_events_total: IntCounterVec,

    /// Total number of peer disconnection events
    lean_peer_disconnection_events_total: IntCounterVec,

    /// Number of gossip signatures in fork-choice store
    pub lean_gossip_signatures: IntGauge,

    /// Inbound gossipsub messages that failed snappy decompression, by topic kind
    pub lean_gossip_decompress_failures_total: IntCounterVec,

    /// Number of new aggregated payload items
    pub lean_latest_new_aggregated_payloads: IntGauge,

    /// Number of known aggregated payload items
    pub lean_latest_known_aggregated_payloads: IntGauge,

    /// Time taken to aggregate committee signatures
    pub lean_committee_signatures_aggregation_time_seconds: Histogram,

    /// Validator's is_aggregator status (1=true, 0=false)
    pub lean_is_aggregator: IntGauge,

    /// Node's attestation committee subnet
    pub lean_attestation_committee_subnet: IntGauge,

    /// Number of attestation committees (ATTESTATION_COMMITTEE_COUNT)
    pub lean_attestation_committee_count: IntGauge,

    // OOM Detection Metrics
    /// Number of entries in the attestation_data_by_root secondary index
    pub grandine_attestation_data_by_root: IntGauge,

    /// Number of block roots queued for BlocksByRoot fetch (missing-block backlog)
    pub grandine_pending_fetch_roots: IntGauge,

    /// Number of orphan blocks held in the backfill BlockCache (hard-capped at 1024)
    pub grandine_block_cache_size: IntGauge,

    /// Number of attestations queued waiting for a missing block to arrive
    pub grandine_pending_attestations_size: IntGauge,

    /// Number of aggregated attestations queued waiting for a missing block to arrive
    pub grandine_pending_aggregated_attestations_size: IntGauge,

    /// Signed blocks in the networking-layer cache (hard-capped at 1024)
    pub grandine_signed_block_provider_size: IntGauge,

    /// Gap between the network's current slot and the node's head slot (backfill depth)
    pub grandine_slots_behind: IntGauge,

    /// Validators with finalized (known) attestations currently in the fork-choice store
    pub grandine_fork_choice_known_attestations: IntGauge,

    /// Validators with pending (new/gossip) attestations in the fork-choice store
    pub grandine_fork_choice_new_attestations: IntGauge,

    /// XMSS verifications skipped because the signature was already cached
    pub grandine_xmss_verify_skipped_total: IntCounter,

    pub grandine_chain_message_channel_depth: IntGauge,
    pub grandine_validator_chain_message_channel_depth: IntGauge,
    pub grandine_verify_result_channel_depth: IntGauge,
    pub grandine_cpu_normal_executor_tasks_in_flight: IntGauge,
    pub grandine_cpu_snark_executor_tasks_in_flight: IntGauge,
    pub grandine_cpu_verify_executor_tasks_in_flight: IntGauge,
    pub grandine_cpu_aggregation_executor_tasks_in_flight: IntGauge,
    pub grandine_reaggregate_candidates_selected_total: IntCounterVec,
    pub grandine_reaggregate_split_outcomes_total: IntCounterVec,

    /// Wall-clock time of the aggregation snapshot deep-clone. After V2, the
    /// clone runs on the aggregation worker thread (not the chain task), so this
    /// no longer reflects chain-task wall-clock; it reflects how expensive a
    /// single Store deep-clone is at the moment the aggregation worker picks up
    /// a trigger.
    pub lean_aggregation_snapshot_clone_seconds: Histogram,

    /// Total number of times the chain task triggered an aggregation snapshot.
    /// Compare against `lean_aggregation_snapshot_clone_seconds_count` to derive
    /// dropped-trigger count (watch channel overwrites unconsumed values).
    pub lean_aggregation_snapshots_triggered_total: IntCounter,

    /// Number of payload entries dropped at proposal time because the
    /// `attestation_data_by_root` secondary index has no AttestationData for
    /// the data_root present in `latest_known_aggregated_payloads`. Drift
    /// between the two maps would silently shrink the proposer's pool.
    pub lean_build_block_pool_missing_att_data: IntCounter,
    pub lean_build_block_fixed_point_no_converge_total: IntCounter,
    pub lean_block_proposal_attestation_build_phase_seconds: HistogramVec,
    pub lean_block_proposal_attestation_builds_total: IntCounter,
    pub lean_block_proposal_child_payloads_consumed_total: IntCounter,
    pub lean_block_proposal_attestation_data_selected: Histogram,
    pub lean_block_proposal_aggregates_selected: Histogram,

    /// Snapshot size at clone time, measured in total entries across the largest
    /// Store maps (blocks + states + gossip_signatures + known_aggregated_payloads
    /// + new_aggregated_payloads + attestation_data_by_root). Used to correlate
    /// snapshot wall-clock and aggregator memory growth with chain length.
    pub lean_aggregation_snapshot_size_entries: Histogram,

    /// Number of aggregation snapshots currently held in memory by the worker
    /// thread (inc when `spawn_blocking` task starts, dec when it returns).
    /// Should oscillate 0..=1 with the watch-channel design; sustained values
    /// of 1 mean the worker is continuously busy (XMSS slower than slot rate).
    pub lean_aggregation_in_flight_snapshots: IntGauge,

    /// Per-job pre-SNARK setup wall-clock: children_arg construction, validator
    /// index sort/dedup, participants bitfield, raw pubkey/sig cloning.
    /// Observed once per job in `maybe_aggregate` right before the SNARK call.
    pub grandine_aggregation_job_setup_seconds: Histogram,

    /// Time the chain task spends processing one `ChainMessage` (block,
    /// attestation, aggregated attestation, etc.). Captures total work done
    /// inside the `chain_message_receiver.recv() => { … }` select arm body
    /// regardless of message kind. Bimodal distribution expected: spawn-only
    /// path for blocks vs full write-locked attestation processing.
    pub lean_chain_task_chain_message_seconds: Histogram,

    /// Time the chain task spends inside the `verify_result_rx.recv() => { … }`
    /// arm body — i.e. Phase 3 apply work (apply_verified_block + post-apply
    /// bookkeeping + cascade respawn). Used to compare apply cost against the
    /// snapshot/message-processing costs.
    pub lean_chain_task_apply_seconds: Histogram,
    pub grandine_store_blocks_size: IntGauge,
    pub grandine_store_states_size: IntGauge,
    pub grandine_store_gossip_signatures_size: IntGauge,
    pub grandine_store_known_aggregated_payloads_size: IntGauge,
    pub grandine_store_new_aggregated_payloads_size: IntGauge,
    pub grandine_pending_blocks_by_root_size: IntGauge,

    pub lean_block_building_time_seconds: Histogram,
    pub lean_block_building_payload_aggregation_time_seconds: Histogram,
    pub lean_block_aggregated_payloads: Histogram,
    pub lean_block_building_success_total: IntCounter,
    pub lean_block_building_failures_total: IntCounter,
    pub lean_node_sync_status: GaugeVec,
    pub lean_gossip_block_size_bytes: Histogram,
    pub lean_gossip_attestation_size_bytes: Histogram,
    pub lean_gossip_aggregation_size_bytes: Histogram,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            lean_node_info: GaugeVec::new(
                opts!("lean_node_info", "Node information"),
                &["name", "version"],
            )?,
            lean_node_start_time_seconds: IntGauge::new(
                "lean_node_start_time_seconds",
                "Start timestamp",
            )?,

            // PQ Signature metrics
            lean_pq_sig_attestation_signatures_total: IntCounter::new(
                "lean_pq_sig_attestation_signatures_total",
                "Total number of individual attestation signatures",
            )?,
            lean_pq_sig_attestation_signatures_valid_total: IntCounter::new(
                "lean_pq_sig_attestation_signatures_valid_total",
                "Total number of valid individual attestation signatures",
            )?,
            lean_pq_sig_attestation_signatures_invalid_total: IntCounter::new(
                "lean_pq_sig_attestation_signatures_invalid_total",
                "Total number of invalid individual attestation signatures",
            )?,
            lean_pq_sig_attestation_signing_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_pq_sig_attestation_signing_time_seconds",
                "Time taken to sign an attestation",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0],
            ))?,
            lean_pq_sig_attestation_verification_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_pq_sig_attestation_verification_time_seconds",
                    "Time taken to verify an attestation signature",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0],
                ),
            )?,
            lean_pq_sig_aggregated_signatures_total: IntCounter::new(
                "lean_pq_sig_aggregated_signatures_total",
                "Total number of aggregated signatures",
            )?,
            lean_pq_sig_attestations_in_aggregated_signatures_total: IntCounter::new(
                "lean_pq_sig_attestations_in_aggregated_signatures_total",
                "Total number of attestations included into aggregated signatures",
            )?,
            lean_pq_sig_aggregated_signatures_building_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_pq_sig_aggregated_signatures_building_time_seconds",
                    "Time taken to build an aggregated attestation signature",
                    vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 4.0]
                ),
            )?,
            lean_pq_sig_aggregated_signatures_verification_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_pq_sig_aggregated_signatures_verification_time_seconds",
                    "Time taken to verify an aggregated attestation signature",
                    vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 4.0]
                ),
            )?,
            lean_pq_sig_aggregated_signatures_valid_total: IntCounter::new(
                "lean_pq_sig_aggregated_signatures_valid_total",
                "Total number of valid aggregated signatures",
            )?,
            lean_pq_sig_aggregated_signatures_invalid_total: IntCounter::new(
                "lean_pq_sig_aggregated_signatures_invalid_total",
                "Total number of invalid aggregated signatures",
            )?,

            // Fork-Choice Metrics
            lean_head_slot: IntGauge::new("lean_head_slot", "Latest slot of the lean chain")?,
            lean_current_slot: IntGauge::new(
                "lean_current_slot",
                "Current slot of the lean chain",
            )?,
            lean_safe_target_slot: IntGauge::new("lean_safe_target_slot", "Safe target slot")?,
            lean_fork_choice_block_processing_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_fork_choice_block_processing_time_seconds",
                "Time taken to process block",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0, 1.25, 1.5, 2.0, 4.0]
            ))?,
            lean_aggregator_skipped_total: IntCounterVec::new(
                opts!(
                    "lean_aggregator_skipped_total",
                    "Aggregation submissions skipped, by reason",
                ),
                &["reason"],
            )?,
            lean_chain_message_drop_total: IntCounterVec::new(
                opts!(
                    "lean_chain_message_drop_total",
                    "Chain-message channel drops on full, by protocol",
                ),
                &["protocol"],
            )?,
            lean_attestations_valid_total: IntCounterVec::new(
                opts!(
                    "lean_attestations_valid_total",
                    "Total number of valid attestations",
                ),
                &["source"],
            )?,
            lean_attestations_invalid_total: IntCounterVec::new(
                opts!(
                    "lean_attestations_invalid_total",
                    "Total number of invalid attestations",
                ),
                &["source"],
            )?,
            lean_attestation_validation_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_attestation_validation_time_seconds",
                "Time taken to validate attestation",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
            ))?,
            lean_attestations_production_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_attestations_production_time_seconds",
                "Time taken to produce attestations",
                vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0]
            ))?,
            lean_fork_choice_reorgs_total: IntCounter::new(
                "lean_fork_choice_reorgs_total",
                "Total number of fork choice reorgs",
            )?,
            lean_fork_choice_reorg_depth: Histogram::with_opts(histogram_opts!(
                "lean_fork_choice_reorg_depth",
                "Depth of fork choice reorgs (in blocks)",
                vec![1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 20.0, 30.0, 50.0, 100.0]
            ))?,
            lean_tick_interval_duration_seconds: Histogram::with_opts(histogram_opts!(
                "lean_tick_interval_duration_seconds",
                "Elapsed time between clock ticks in seconds",
                vec![
                    0.4, 0.6, 0.75, 0.8, 0.805, 0.81, 0.815, 0.82, 0.825, 0.85, 0.9, 1.0, 1.2, 1.6,
                ]
            ))?,

            // State Transition Metrics
            lean_latest_justified_slot: IntGauge::new(
                "lean_latest_justified_slot",
                "Latest justified slot",
            )?,
            lean_latest_finalized_slot: IntGauge::new(
                "lean_latest_finalized_slot",
                "Latest finalized slot",
            )?,
            lean_finalizations_total: IntCounterVec::new(
                opts!(
                    "lean_finalizations_total",
                    "Total number of finalization attempts",
                ),
                &["result"],
            )?,
            lean_state_transition_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_state_transition_time_seconds",
                "Time to process state transition",
                vec![0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 4.0]
            ))?,
            lean_state_transition_slots_processed_total: IntCounter::new(
                "lean_state_transition_slots_processed_total",
                "Total number of processed slots",
            )?,
            lean_state_transition_slots_processing_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_state_transition_slots_processing_time_seconds",
                    "Time taken to process slots",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
                ),
            )?,
            lean_state_transition_block_processing_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_state_transition_block_processing_time_seconds",
                    "Time taken to process block",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
                ),
            )?,
            lean_state_transition_attestations_processed_total: IntCounter::new(
                "lean_state_transition_attestations_processed_total",
                "Total number of processed attestations",
            )?,
            lean_state_transition_attestations_processing_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_state_transition_attestations_processing_time_seconds",
                    " Time taken to process attestations",
                    vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
                ),
            )?,

            // Validator metrics
            lean_validators_count: IntGauge::new(
                "lean_validators_count",
                "Number of validators managed by a node",
            )?,

            // Network Metrics
            lean_connected_peers: IntGaugeVec::new(
                opts!("lean_connected_peers", "Number of connected peers",),
                &["client"],
            )?,
            lean_gossip_mesh_peers: IntGaugeVec::new(
                opts!(
                    "lean_gossip_mesh_peers",
                    "Number of peers in the gossipsub mesh",
                ),
                &["client"],
            )?,
            lean_peer_connection_events_total: IntCounterVec::new(
                opts!(
                    "lean_peer_connection_events_total",
                    "Total number of peer connection events",
                ),
                &["direction", "result"],
            )?,
            lean_peer_disconnection_events_total: IntCounterVec::new(
                opts!(
                    "lean_peer_disconnection_events_total",
                    "Total number of peer disconnection events",
                ),
                &["direction", "reason"],
            )?,

            lean_gossip_signatures: IntGauge::new(
                "lean_gossip_signatures",
                "Number of gossip signatures in fork-choice store",
            )?,
            lean_gossip_decompress_failures_total: IntCounterVec::new(
                opts!(
                    "lean_gossip_decompress_failures_total",
                    "Inbound gossipsub messages that failed snappy decompression, by topic kind",
                ),
                &["topic_kind"],
            )?,
            lean_latest_new_aggregated_payloads: IntGauge::new(
                "lean_latest_new_aggregated_payloads",
                "Number of new aggregated payload items",
            )?,
            lean_latest_known_aggregated_payloads: IntGauge::new(
                "lean_latest_known_aggregated_payloads",
                "Number of known aggregated payload items",
            )?,
            lean_committee_signatures_aggregation_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_committee_signatures_aggregation_time_seconds",
                    "Time taken to aggregate committee signatures",
                    vec![0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0]
                ),
            )?,

            lean_is_aggregator: IntGauge::new(
                "lean_is_aggregator",
                "Validator's is_aggregator status (1=true, 0=false)",
            )?,

            lean_attestation_committee_subnet: IntGauge::new(
                "lean_attestation_committee_subnet",
                "Node's attestation committee subnet",
            )?,
            lean_attestation_committee_count: IntGauge::new(
                "lean_attestation_committee_count",
                "Number of attestation committees (ATTESTATION_COMMITTEE_COUNT)",
            )?,

            // OOM Detection Metrics
            grandine_attestation_data_by_root: IntGauge::new(
                "grandine_attestation_data_by_root",
                "Number of entries in attestation_data_by_root secondary index",
            )?,
            grandine_pending_fetch_roots: IntGauge::new(
                "grandine_pending_fetch_roots",
                "Block roots queued for BlocksByRoot fetch (missing-block backlog)",
            )?,
            grandine_block_cache_size: IntGauge::new(
                "grandine_block_cache_size",
                "Orphan blocks in backfill BlockCache (hard cap 1024)",
            )?,
            grandine_pending_attestations_size: IntGauge::new(
                "grandine_pending_attestations_size",
                "Attestations queued waiting for a missing block to arrive",
            )?,
            grandine_pending_aggregated_attestations_size: IntGauge::new(
                "grandine_pending_aggregated_attestations_size",
                "Aggregated attestations queued waiting for a missing block to arrive",
            )?,
            grandine_signed_block_provider_size: IntGauge::new(
                "grandine_signed_block_provider_size",
                "Signed blocks in the networking-layer cache (hard cap 1024)",
            )?,
            grandine_slots_behind: IntGauge::new(
                "grandine_slots_behind",
                "Current slot minus head slot — backfill depth and primary OOM risk indicator",
            )?,
            grandine_fork_choice_known_attestations: IntGauge::new(
                "grandine_fork_choice_known_attestations",
                "Validators with known attestations in the fork-choice store",
            )?,
            grandine_fork_choice_new_attestations: IntGauge::new(
                "grandine_fork_choice_new_attestations",
                "Validators with new gossip attestations in the fork-choice store",
            )?,
            grandine_xmss_verify_skipped_total: IntCounter::new(
                "grandine_xmss_verify_skipped_total",
                "XMSS verifications skipped (signature already cached) — root cause 4 indicator",
            )?,
            grandine_chain_message_channel_depth: IntGauge::new(
                "grandine_chain_message_channel_depth",
                "Pending ChainMessage queue depth",
            )?,
            grandine_validator_chain_message_channel_depth: IntGauge::new(
                "grandine_validator_chain_message_channel_depth",
                "Pending ValidatorChainMessage queue depth",
            )?,
            grandine_verify_result_channel_depth: IntGauge::new(
                "grandine_verify_result_channel_depth",
                "Pending verify-result queue depth (verified blocks awaiting apply on chain task)",
            )?,
            grandine_cpu_normal_executor_tasks_in_flight: IntGauge::new(
                "grandine_cpu_normal_executor_tasks_in_flight",
                "Active tasks on cpu_normal DedicatedExecutor (XMSS block verify + attestation signing combined)",
            )?,
            grandine_cpu_snark_executor_tasks_in_flight: IntGauge::new(
                "grandine_cpu_snark_executor_tasks_in_flight",
                "Active tasks on cpu_snark DedicatedExecutor (propose-build + propose-sign)",
            )?,
            grandine_cpu_verify_executor_tasks_in_flight: IntGauge::new(
                "grandine_cpu_verify_executor_tasks_in_flight",
                "Active tasks on cpu_verify DedicatedExecutor (reaggregate split + cascade-verify + gossip-block-verify + gossip-agg-att-verify)",
            )?,
            grandine_cpu_aggregation_executor_tasks_in_flight: IntGauge::new(
                "grandine_cpu_aggregation_executor_tasks_in_flight",
                "Active tasks on cpu_aggregation DedicatedExecutor (aggregation worker, isolated from propose)",
            )?,
            grandine_reaggregate_candidates_selected_total: IntCounterVec::new(
                opts!(
                    "grandine_reaggregate_candidates_selected_total",
                    "Reaggregate candidate-selection outcomes per block",
                ),
                &["outcome"],
            )?,
            grandine_reaggregate_split_outcomes_total: IntCounterVec::new(
                opts!(
                    "grandine_reaggregate_split_outcomes_total",
                    "Reaggregate Type-2 split_by_message outcomes",
                ),
                &["outcome"],
            )?,
            lean_aggregation_snapshot_clone_seconds: Histogram::with_opts(histogram_opts!(
                "lean_aggregation_snapshot_clone_seconds",
                "Wall-clock time of the aggregation snapshot deep-clone (runs on aggregation worker thread)",
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0],
            ))?,
            lean_aggregation_snapshots_triggered_total: IntCounter::new(
                "lean_aggregation_snapshots_triggered_total",
                "Total aggregation snapshot triggers issued by the chain task (aggregator nodes only)",
            )?,
            lean_build_block_pool_missing_att_data: IntCounter::new(
                "lean_build_block_pool_missing_att_data",
                "Total payload entries dropped at proposal time because attestation_data_by_root has no entry for the data_root",
            )?,
            lean_build_block_fixed_point_no_converge_total: IntCounter::new(
                "lean_build_block_fixed_point_no_converge_total",
                "Total build_block calls where the produced block's latest_justified did not reach the store's latest_justified",
            )?,
            lean_block_proposal_attestation_build_phase_seconds: HistogramVec::new(
                histogram_opts!(
                    "lean_block_proposal_attestation_build_phase_seconds",
                    "Phase-level time in block-proposal attestation selection (build_block): select_payloads, compact, stf_simulate",
                    vec![
                        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0
                    ]
                ),
                &["phase"],
            )?,
            lean_block_proposal_attestation_builds_total: IntCounter::new(
                "lean_block_proposal_attestation_builds_total",
                "Completed block-proposal attestation selection runs (one per proposal attempt)",
            )?,
            lean_block_proposal_child_payloads_consumed_total: IntCounter::new(
                "lean_block_proposal_child_payloads_consumed_total",
                "Child aggregated payloads selected during greedy proof picking (before recursive compaction)",
            )?,
            lean_block_proposal_attestation_data_selected: Histogram::with_opts(histogram_opts!(
                "lean_block_proposal_attestation_data_selected",
                "Distinct AttestationData entries in the proposal block body",
                vec![0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0]
            ))?,
            lean_block_proposal_aggregates_selected: Histogram::with_opts(histogram_opts!(
                "lean_block_proposal_aggregates_selected",
                "Aggregated signature proofs in the proposal result after compaction",
                vec![0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0]
            ))?,
            lean_aggregation_snapshot_size_entries: Histogram::with_opts(histogram_opts!(
                "lean_aggregation_snapshot_size_entries",
                "Total entries across all major Store maps at snapshot clone time",
                vec![
                    100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0, 500000.0
                ],
            ))?,
            lean_aggregation_in_flight_snapshots: IntGauge::new(
                "lean_aggregation_in_flight_snapshots",
                "Snapshots currently held by the aggregation spawn_blocking worker (0 or 1 expected)",
            )?,
            grandine_aggregation_job_setup_seconds: Histogram::with_opts(histogram_opts!(
                "grandine_aggregation_job_setup_seconds",
                "Per-job pre-SNARK setup wall-clock in maybe_aggregate before aggregate_with_children",
                vec![
                    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5
                ],
            ))?,
            lean_chain_task_chain_message_seconds: Histogram::with_opts(histogram_opts!(
                "lean_chain_task_chain_message_seconds",
                "Wall-clock time the chain task spends inside one ChainMessage select-arm body",
                vec![
                    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0
                ],
            ))?,
            lean_chain_task_apply_seconds: Histogram::with_opts(histogram_opts!(
                "lean_chain_task_apply_seconds",
                "Wall-clock time the chain task spends inside one verify_result (Phase 3 apply) select-arm body",
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0],
            ))?,
            grandine_store_blocks_size: IntGauge::new(
                "grandine_store_blocks_size",
                "Entries in store.blocks",
            )?,
            grandine_store_states_size: IntGauge::new(
                "grandine_store_states_size",
                "Entries in store.states",
            )?,
            grandine_store_gossip_signatures_size: IntGauge::new(
                "grandine_store_gossip_signatures_size",
                "Entries in store.gossip_signatures",
            )?,
            grandine_store_known_aggregated_payloads_size: IntGauge::new(
                "grandine_store_known_aggregated_payloads_size",
                "Entries in latest_known_aggregated_payloads",
            )?,
            grandine_store_new_aggregated_payloads_size: IntGauge::new(
                "grandine_store_new_aggregated_payloads_size",
                "Entries in latest_new_aggregated_payloads",
            )?,
            grandine_pending_blocks_by_root_size: IntGauge::new(
                "grandine_pending_blocks_by_root_size",
                "In-flight BlocksByRoot requests",
            )?,

            // Block Production Metrics
            lean_block_building_time_seconds: Histogram::with_opts(histogram_opts!(
                "lean_block_building_time_seconds",
                "Time taken to build a block",
                vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0]
            ))?,
            lean_block_building_payload_aggregation_time_seconds: Histogram::with_opts(
                histogram_opts!(
                    "lean_block_building_payload_aggregation_time_seconds",
                    "Time taken to build aggregated_payloads during block building",
                    vec![0.1, 0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0]
                ),
            )?,
            lean_block_aggregated_payloads: Histogram::with_opts(histogram_opts!(
                "lean_block_aggregated_payloads",
                "Number of aggregated_payloads in a produced block",
                vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0]
            ))?,
            lean_block_building_success_total: IntCounter::new(
                "lean_block_building_success_total",
                "Total successful block builds",
            )?,
            lean_block_building_failures_total: IntCounter::new(
                "lean_block_building_failures_total",
                "Total failed block builds",
            )?,

            // Node Status
            lean_node_sync_status: GaugeVec::new(
                opts!(
                    "lean_node_sync_status",
                    "Node sync status (idle/syncing/synced)"
                ),
                &["status"],
            )?,

            // Gossip Size Metrics
            lean_gossip_block_size_bytes: Histogram::with_opts(histogram_opts!(
                "lean_gossip_block_size_bytes",
                "Bytes size of a gossip block message",
                vec![
                    10_000.0,
                    50_000.0,
                    100_000.0,
                    250_000.0,
                    500_000.0,
                    1_000_000.0,
                    2_000_000.0,
                    5_000_000.0,
                ]
            ))?,
            lean_gossip_attestation_size_bytes: Histogram::with_opts(histogram_opts!(
                "lean_gossip_attestation_size_bytes",
                "Bytes size of a gossip attestation message",
                vec![512.0, 1_024.0, 2_048.0, 4_096.0, 8_192.0, 16_384.0]
            ))?,
            lean_gossip_aggregation_size_bytes: Histogram::with_opts(histogram_opts!(
                "lean_gossip_aggregation_size_bytes",
                "Bytes size of a gossip aggregated attestation message",
                vec![
                    1_024.0,
                    4_096.0,
                    16_384.0,
                    65_536.0,
                    131_072.0,
                    262_144.0,
                    524_288.0,
                    1_048_576.0,
                ]
            ))?,
        })
    }

    pub fn register_with_default_metrics(&self) -> Result<()> {
        let default_registry = prometheus::default_registry();

        default_registry.register(Box::new(self.lean_node_info.clone()))?;
        default_registry.register(Box::new(self.lean_node_start_time_seconds.clone()))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_signatures_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_signatures_valid_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_signatures_invalid_total
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_signing_time_seconds.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestation_verification_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_attestations_in_aggregated_signatures_total
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_building_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_verification_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_valid_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_pq_sig_aggregated_signatures_invalid_total.clone(),
        ))?;
        default_registry.register(Box::new(self.lean_head_slot.clone()))?;
        default_registry.register(Box::new(self.lean_current_slot.clone()))?;
        default_registry.register(Box::new(self.lean_safe_target_slot.clone()))?;
        default_registry.register(Box::new(
            self.lean_fork_choice_block_processing_time_seconds.clone(),
        ))?;
        default_registry.register(Box::new(self.lean_aggregator_skipped_total.clone()))?;
        default_registry.register(Box::new(self.lean_chain_message_drop_total.clone()))?;
        for &protocol in &["blocks_by_root", "blocks_by_range"] {
            self.lean_chain_message_drop_total
                .with_label_values(&[protocol])
                .inc_by(0);
        }
        for &reason in &[
            "not_aggregator",
            "not_synced",
            "missing_state",
            "spawn_failed",
            "other",
        ] {
            self.lean_aggregator_skipped_total
                .with_label_values(&[reason])
                .inc_by(0);
        }
        default_registry.register(Box::new(self.lean_attestations_valid_total.clone()))?;
        default_registry.register(Box::new(self.lean_attestations_invalid_total.clone()))?;
        default_registry.register(Box::new(
            self.lean_attestation_validation_time_seconds.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_attestations_production_time_seconds.clone(),
        ))?;
        default_registry.register(Box::new(self.lean_fork_choice_reorgs_total.clone()))?;
        default_registry.register(Box::new(self.lean_fork_choice_reorg_depth.clone()))?;
        default_registry.register(Box::new(self.lean_tick_interval_duration_seconds.clone()))?;
        default_registry.register(Box::new(self.lean_latest_justified_slot.clone()))?;
        default_registry.register(Box::new(self.lean_latest_finalized_slot.clone()))?;
        default_registry.register(Box::new(self.lean_finalizations_total.clone()))?;
        default_registry.register(Box::new(self.lean_state_transition_time_seconds.clone()))?;
        default_registry.register(Box::new(
            self.lean_state_transition_slots_processed_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_state_transition_slots_processing_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_state_transition_block_processing_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_state_transition_attestations_processed_total
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_state_transition_attestations_processing_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(self.lean_validators_count.clone()))?;
        default_registry.register(Box::new(self.lean_connected_peers.clone()))?;
        default_registry.register(Box::new(self.lean_gossip_mesh_peers.clone()))?;
        default_registry.register(Box::new(self.lean_peer_connection_events_total.clone()))?;
        default_registry.register(Box::new(self.lean_peer_disconnection_events_total.clone()))?;

        // Additional Fork-Choice Metrics
        default_registry.register(Box::new(self.lean_gossip_signatures.clone()))?;
        default_registry.register(Box::new(self.lean_gossip_decompress_failures_total.clone()))?;
        default_registry.register(Box::new(self.lean_latest_new_aggregated_payloads.clone()))?;
        default_registry.register(Box::new(self.lean_latest_known_aggregated_payloads.clone()))?;
        default_registry.register(Box::new(
            self.lean_committee_signatures_aggregation_time_seconds
                .clone(),
        ))?;

        default_registry.register(Box::new(self.lean_is_aggregator.clone()))?;

        default_registry.register(Box::new(self.lean_attestation_committee_subnet.clone()))?;
        default_registry.register(Box::new(self.lean_attestation_committee_count.clone()))?;

        // OOM Detection Metrics
        default_registry.register(Box::new(self.grandine_attestation_data_by_root.clone()))?;
        default_registry.register(Box::new(self.grandine_pending_fetch_roots.clone()))?;
        default_registry.register(Box::new(self.grandine_block_cache_size.clone()))?;
        default_registry.register(Box::new(self.grandine_pending_attestations_size.clone()))?;
        default_registry.register(Box::new(
            self.grandine_pending_aggregated_attestations_size.clone(),
        ))?;
        default_registry.register(Box::new(self.grandine_signed_block_provider_size.clone()))?;
        default_registry.register(Box::new(self.grandine_slots_behind.clone()))?;
        default_registry.register(Box::new(
            self.grandine_fork_choice_known_attestations.clone(),
        ))?;
        default_registry.register(Box::new(self.grandine_fork_choice_new_attestations.clone()))?;
        default_registry.register(Box::new(self.grandine_xmss_verify_skipped_total.clone()))?;
        default_registry.register(Box::new(self.grandine_chain_message_channel_depth.clone()))?;
        default_registry.register(Box::new(
            self.grandine_validator_chain_message_channel_depth.clone(),
        ))?;
        default_registry.register(Box::new(self.grandine_verify_result_channel_depth.clone()))?;
        default_registry.register(Box::new(
            self.grandine_cpu_normal_executor_tasks_in_flight.clone(),
        ))?;
        default_registry.register(Box::new(
            self.grandine_cpu_snark_executor_tasks_in_flight.clone(),
        ))?;
        default_registry.register(Box::new(
            self.grandine_cpu_verify_executor_tasks_in_flight.clone(),
        ))?;
        default_registry.register(Box::new(
            self.grandine_cpu_aggregation_executor_tasks_in_flight
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.grandine_reaggregate_candidates_selected_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.grandine_reaggregate_split_outcomes_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_aggregation_snapshot_clone_seconds.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_aggregation_snapshots_triggered_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_build_block_pool_missing_att_data.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_build_block_fixed_point_no_converge_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_block_proposal_attestation_build_phase_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_block_proposal_attestation_builds_total.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_block_proposal_child_payloads_consumed_total
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_block_proposal_attestation_data_selected.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_block_proposal_aggregates_selected.clone(),
        ))?;
        default_registry.register(Box::new(
            self.lean_aggregation_snapshot_size_entries.clone(),
        ))?;
        default_registry.register(Box::new(self.lean_aggregation_in_flight_snapshots.clone()))?;
        default_registry.register(Box::new(
            self.grandine_aggregation_job_setup_seconds.clone(),
        ))?;
        default_registry.register(Box::new(self.lean_chain_task_chain_message_seconds.clone()))?;
        default_registry.register(Box::new(self.lean_chain_task_apply_seconds.clone()))?;
        default_registry.register(Box::new(self.grandine_store_blocks_size.clone()))?;
        default_registry.register(Box::new(self.grandine_store_states_size.clone()))?;
        default_registry.register(Box::new(self.grandine_store_gossip_signatures_size.clone()))?;
        default_registry.register(Box::new(
            self.grandine_store_known_aggregated_payloads_size.clone(),
        ))?;
        default_registry.register(Box::new(
            self.grandine_store_new_aggregated_payloads_size.clone(),
        ))?;
        default_registry.register(Box::new(self.grandine_pending_blocks_by_root_size.clone()))?;

        // Block Production Metrics
        default_registry.register(Box::new(self.lean_block_building_time_seconds.clone()))?;
        default_registry.register(Box::new(
            self.lean_block_building_payload_aggregation_time_seconds
                .clone(),
        ))?;
        default_registry.register(Box::new(self.lean_block_aggregated_payloads.clone()))?;
        default_registry.register(Box::new(self.lean_block_building_success_total.clone()))?;
        default_registry.register(Box::new(self.lean_block_building_failures_total.clone()))?;

        // Node Status
        default_registry.register(Box::new(self.lean_node_sync_status.clone()))?;

        // Gossip Size Metrics
        default_registry.register(Box::new(self.lean_gossip_block_size_bytes.clone()))?;
        default_registry.register(Box::new(self.lean_gossip_attestation_size_bytes.clone()))?;
        default_registry.register(Box::new(self.lean_gossip_aggregation_size_bytes.clone()))?;

        Ok(())
    }

    pub fn set_client_version(&self, name: String, version: String) {
        self.lean_node_info
            .with_label_values(&[name, version])
            .set(1.0);
    }

    pub fn set_start_time(&self, timestamp: SystemTime) -> Result<()> {
        let timestamp = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("failed to calculate timestamp")?
            .as_secs()
            .try_into()
            .context("sorry, grandine support ended ~292 billion years ago")?;
        self.lean_node_start_time_seconds.set(timestamp);

        Ok(())
    }

    /// Sets the node sync status gauge. Exactly one of idle/syncing/synced is set to 1.
    pub fn set_sync_status(&self, status: &str) {
        for s in &["idle", "syncing", "synced"] {
            self.lean_node_sync_status
                .with_label_values(&[s])
                .set(if *s == status { 1.0 } else { 0.0 });
        }
    }

    /// Increments successfull peer connection event count metric.
    pub fn register_peer_connection_success(&self, is_inbound: bool) -> Result<()> {
        let direction = if is_inbound { "inbound" } else { "outbound" };
        let metric = self
            .lean_peer_connection_events_total
            .get_metric_with_label_values(&[direction, "success"])?;
        metric.inc();
        Ok(())
    }

    /// Increments peer connection failure event count metric.
    pub fn register_peer_connection_failure(&self, is_inbound: bool) -> Result<()> {
        let direction = if is_inbound { "inbound" } else { "outbound" };
        let metric = self
            .lean_peer_connection_events_total
            .get_metric_with_label_values(&[direction, "failure"])?;
        metric.inc();
        Ok(())
    }

    /// Increments peer connection timeout event count metric.
    pub fn register_peer_connection_timeout(&self, is_inbound: bool) -> Result<()> {
        let direction = if is_inbound { "inbound" } else { "outbound" };
        let metric = self
            .lean_peer_connection_events_total
            .get_metric_with_label_values(&[direction, "timeout"])?;
        metric.inc();
        Ok(())
    }

    pub fn register_peer_disconnect(
        &self,
        is_inbound: bool,
        reason: DisconnectReason,
    ) -> Result<()> {
        let direction = if is_inbound { "inbound" } else { "outbound" };
        let reason = match reason {
            DisconnectReason::Timeout => "timeout",
            DisconnectReason::RemoteClose => "remote_close",
            DisconnectReason::LocalClose => "local_close",
            DisconnectReason::Error => "error",
        };
        let metric = self
            .lean_peer_disconnection_events_total
            .get_metric_with_label_values(&[direction, reason])?;

        metric.inc();

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum DisconnectReason {
    Timeout,
    RemoteClose,
    LocalClose,
    Error,
}
