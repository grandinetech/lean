// Lean validator client with XMSS signing support
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;

use anyhow::{Context, Result, anyhow, bail};
use containers::{
    AggregatedSignatureProof, AggregationBits, AttestationData, Block, MultiMessageAggregate,
    SignatureKey, SignedAggregatedAttestation, SignedAttestation, SignedBlock, Slot, Validators,
};
use dedicated_executor::DedicatedExecutor;
use fork_choice::store::{INTERVALS_PER_SLOT, Store};
use futures::stream::{FuturesUnordered, StreamExt};
use metrics::METRICS;
use ssz::H256;
use ssz::SszHash;
use tracing::{info, warn};
use try_from_iterator::TryFromIterator as _;

pub mod keys;

use keys::KeyManager;
use xmss::{AggregatedSignature, PublicKey, Signature};

pub struct AggregationJob {
    pub data_root: H256,
    pub attestation_data: AttestationData,
    pub children: Vec<(Vec<PublicKey>, AggregatedSignatureProof)>,
    pub accepted_child_ids: Vec<u64>,
    pub raw_pubkeys: Vec<PublicKey>,
    pub raw_sigs: Vec<Signature>,
    pub raw_ids: Vec<u64>,
}

pub struct AggregationSnapshot {
    pub jobs: Vec<AggregationJob>,
    /// data_roots whose gossip raw signatures were dropped from job.raw_ids
    /// because a stored child proof already covers them. Callers must remove
    /// those gossip signatures from `store.gossip_signatures` alongside the
    /// per-job consumed set to prevent unbounded pool growth.
    pub settled_data_roots: HashSet<H256>,
}

pub const AGGREGATION_SLOT_LOOKBACK: u64 = 1;

pub fn snapshot_aggregation_inputs(store: &Store) -> Option<AggregationSnapshot> {
    if store.gossip_signatures.is_empty() && store.latest_new_aggregated_payloads.is_empty() {
        return None;
    }

    let head_state = store.states.get(&store.head)?;
    let head_validators = &head_state.validators;

    let current_slot = store.time / INTERVALS_PER_SLOT;
    let min_eligible_slot = current_slot.saturating_sub(AGGREGATION_SLOT_LOOKBACK);

    let mut gossip_groups: HashMap<H256, Vec<(u64, Signature)>> = HashMap::new();
    for (sig_key, signature) in &store.gossip_signatures {
        gossip_groups
            .entry(sig_key.data_root)
            .or_default()
            .push((sig_key.validator_id, signature.clone()));
    }

    let mut all_data_roots: HashSet<H256> = gossip_groups.keys().copied().collect();
    for data_root in store.latest_new_aggregated_payloads.keys() {
        all_data_roots.insert(*data_root);
    }

    let mut jobs: Vec<AggregationJob> = Vec::with_capacity(all_data_roots.len());
    let mut settled_data_roots: HashSet<H256> = HashSet::new();

    for data_root in all_data_roots {
        let Some(attestation_data) = store.attestation_data_by_root.get(&data_root) else {
            continue;
        };

        if attestation_data.slot.0 < min_eligible_slot {
            continue;
        }

        let mut children_refs: Vec<&AggregatedSignatureProof> = Vec::new();
        let mut covered_by_children: HashSet<u64> = HashSet::new();
        extend_children_greedily(
            store
                .latest_new_aggregated_payloads
                .get(&data_root)
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            &mut children_refs,
            &mut covered_by_children,
        );
        extend_children_greedily(
            store
                .latest_known_aggregated_payloads
                .get(&data_root)
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            &mut children_refs,
            &mut covered_by_children,
        );

        let raw_input = gossip_groups.get(&data_root).cloned().unwrap_or_default();
        let mut entries: Vec<(u64, Signature)> = raw_input
            .iter()
            .filter(|(vid, _)| {
                !covered_by_children.contains(vid) && head_validators.get(*vid).is_ok()
            })
            .cloned()
            .collect();
        if !raw_input.is_empty() && entries.is_empty() {
            settled_data_roots.insert(data_root);
        }
        entries.sort_by_key(|(vid, _)| *vid);

        let mut raw_ids: Vec<u64> = Vec::with_capacity(entries.len());
        let mut raw_pubkeys: Vec<PublicKey> = Vec::with_capacity(entries.len());
        let mut raw_sigs: Vec<Signature> = Vec::with_capacity(entries.len());
        for (vid, sig) in entries {
            let validator = head_validators.get(vid).unwrap();
            raw_ids.push(vid);
            raw_pubkeys.push(validator.attestation_pubkey.clone());
            raw_sigs.push(sig);
        }

        if raw_ids.is_empty() && children_refs.len() < 2 {
            continue;
        }

        let mut children: Vec<(Vec<PublicKey>, AggregatedSignatureProof)> =
            Vec::with_capacity(children_refs.len());
        for child in &children_refs {
            let pks: Vec<PublicKey> = child
                .participants
                .to_validator_indices()
                .into_iter()
                .filter_map(|vid| {
                    head_validators
                        .get(vid)
                        .ok()
                        .map(|v| v.attestation_pubkey.clone())
                })
                .collect();
            children.push((pks, (*child).clone()));
        }

        let mut accepted_child_ids: Vec<u64> = covered_by_children.into_iter().collect();
        accepted_child_ids.sort();

        info!(
            data_root = %data_root,
            raw_sigs = raw_ids.len(),
            children = children_refs.len(),
            "aggregation job built"
        );

        jobs.push(AggregationJob {
            data_root,
            attestation_data: attestation_data.clone(),
            children,
            accepted_child_ids,
            raw_pubkeys,
            raw_sigs,
            raw_ids,
        });
    }

    if jobs.is_empty() && settled_data_roots.is_empty() {
        return None;
    }

    Some(AggregationSnapshot {
        jobs,
        settled_data_roots,
    })
}

/// Entry in an annotated_validators.yaml file.
/// Each validator index has two entries: one for the attester key and one for the proposer key,
/// distinguished by the filename containing "attester" or "proposer".
/// Single-key format (e.g. validator_N_sk.ssz with neither keyword) is also accepted and
/// uses the same file for both attestation and proposal.
#[derive(Debug, Clone, Deserialize)]
pub struct AnnotatedValidatorEntry {
    pub index: u64,
    pub pubkey_hex: String,
    pub privkey_file: String,
}

pub type ValidatorRegistry = HashMap<String, Vec<AnnotatedValidatorEntry>>;

#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub node_id: String,
    pub validator_indices: Vec<u64>,
    /// Maps validator index → (attestation_privkey_filename, proposal_privkey_filename).
    /// Populated from annotated_validators.yaml; empty when constructed manually (tests).
    pub key_files: HashMap<u64, (String, String)>,
}

impl ValidatorConfig {
    pub fn load_from_file(path: impl AsRef<Path>, node_id: &str) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let registry: ValidatorRegistry = serde_yaml::from_reader(file)?;

        let entries = registry
            .get(node_id)
            .ok_or_else(|| anyhow!("Node `{node_id}` not found in validator registry"))?;

        // Group entries by validator index, mapping attester/proposer filenames by keyword.
        let mut file_map: HashMap<u64, (Option<String>, Option<String>)> = HashMap::new();
        for entry in entries {
            let slot = file_map.entry(entry.index).or_default();
            if entry.privkey_file.contains("attester") {
                slot.0 = Some(entry.privkey_file.clone());
            } else if entry.privkey_file.contains("proposer") {
                slot.1 = Some(entry.privkey_file.clone());
            } else {
                // Single-key format: same file for both keys.
                slot.0 = Some(entry.privkey_file.clone());
                slot.1 = Some(entry.privkey_file.clone());
            }
        }

        let mut key_files: HashMap<u64, (String, String)> = HashMap::new();
        for (idx, (att, prop)) in file_map {
            let att = att.ok_or_else(|| anyhow!("No attester privkey_file for validator {idx}"))?;
            let prop =
                prop.ok_or_else(|| anyhow!("No proposer privkey_file for validator {idx}"))?;
            key_files.insert(idx, (att, prop));
        }

        let mut validator_indices: Vec<u64> = key_files.keys().cloned().collect();
        validator_indices.sort_unstable();

        info!(node_id = %node_id, indices = ?validator_indices, "Validator config loaded...");

        Ok(ValidatorConfig {
            node_id: node_id.to_string(),
            validator_indices,
            key_files,
        })
    }

    pub fn is_assigned(&self, index: u64) -> bool {
        self.validator_indices.contains(&index)
    }
}

pub struct ValidatorService {
    pub config: ValidatorConfig,
    pub num_validators: u64,
    /// Wrapped in `Arc` so each per-validator XMSS signing job can be moved
    /// into a `DedicatedExecutor` task without cloning the secret keys.
    key_manager: Option<Arc<KeyManager>>,
    /// Shared CPU pool used for offloading XMSS attestation signing off the
    /// validator task / chain task.
    cpu_normal_executor: Arc<DedicatedExecutor>,
    /// Pool used for non-aggregation SNARK verify work (block-verify,
    /// reaggregate, gossip-verify). Kept for symmetry with the main executor
    /// split — not used by block-signing, which lives on `cpu_snark_executor`.
    cpu_verify_executor: Arc<DedicatedExecutor>,
    /// Pool used for the SNARK-heavy block-signing work
    /// (Type-1 wrap + Type-2 merge inside `sign_block_with_data`). Same pool as
    /// aggregation; the propose/aggregation timelines never overlap (interval 0
    /// vs interval 2), so co-tenancy here doesn't queue.
    cpu_snark_executor: Arc<DedicatedExecutor>,
    /// Whether this node performs aggregation duties (devnet-3).
    /// Uses `AtomicBool` for interior mutability so the admin API can toggle
    /// the flag at runtime without requiring `&mut self` or a write lock.
    is_aggregator: AtomicBool,
}

/// Greedily extend `children` with proofs from `candidates` that maximally cover
/// validators not yet in `covered`.
///
/// Mirrors the spec's `select_greedily`:
/// each iteration picks the candidate covering the most uncovered validators,
/// until no candidate adds new coverage. `covered` is updated in place so
/// callers can chain two passes (new payloads first, then known payloads).
fn extend_children_greedily<'a>(
    candidates: &'a [AggregatedSignatureProof],
    children: &mut Vec<&'a AggregatedSignatureProof>,
    covered: &mut HashSet<u64>,
) {
    // Track which candidates are still eligible (not yet selected).
    let mut remaining: Vec<&'a AggregatedSignatureProof> = candidates.iter().collect();

    loop {
        // Find the candidate that covers the most uncovered validators.
        let best = remaining
            .iter()
            .enumerate()
            .map(|(pos, proof)| {
                let new_cov = proof
                    .participants
                    .to_validator_indices()
                    .into_iter()
                    .filter(|vid| !covered.contains(vid))
                    .count();
                (pos, new_cov)
            })
            .max_by_key(|&(_, new_cov)| new_cov);

        let Some((pos, new_cov)) = best else { break };
        if new_cov == 0 {
            // No remaining candidate adds coverage — done.
            break;
        }

        let proof = remaining.remove(pos);
        for vid in proof.participants.to_validator_indices() {
            covered.insert(vid);
        }
        children.push(proof);
    }
}

impl ValidatorService {
    pub fn new(
        config: ValidatorConfig,
        num_validators: u64,
        cpu_normal_executor: Arc<DedicatedExecutor>,
        cpu_verify_executor: Arc<DedicatedExecutor>,
        cpu_snark_executor: Arc<DedicatedExecutor>,
    ) -> Self {
        Self::new_with_aggregator(
            config,
            num_validators,
            cpu_normal_executor,
            cpu_verify_executor,
            cpu_snark_executor,
            false,
        )
    }

    pub fn new_with_aggregator(
        config: ValidatorConfig,
        num_validators: u64,
        cpu_normal_executor: Arc<DedicatedExecutor>,
        cpu_verify_executor: Arc<DedicatedExecutor>,
        cpu_snark_executor: Arc<DedicatedExecutor>,
        is_aggregator: bool,
    ) -> Self {
        info!(
            node_id = %config.node_id,
            indices = ?config.validator_indices,
            total_validators = num_validators,
            is_aggregator = is_aggregator,
            "VALIDATOR INITIALIZED SUCCESSFULLY"
        );

        METRICS.get().map(|metrics| {
            metrics
                .lean_validators_count
                .set(config.validator_indices.len() as i64)
        });

        Self {
            config,
            num_validators,
            key_manager: None,
            cpu_normal_executor,
            cpu_verify_executor,
            cpu_snark_executor,
            is_aggregator: AtomicBool::new(is_aggregator),
        }
    }

    pub fn new_with_keys(
        config: ValidatorConfig,
        num_validators: u64,
        keys_dir: impl AsRef<Path>,
        cpu_normal_executor: Arc<DedicatedExecutor>,
        cpu_verify_executor: Arc<DedicatedExecutor>,
        cpu_snark_executor: Arc<DedicatedExecutor>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_keys_and_aggregator(
            config,
            num_validators,
            keys_dir,
            cpu_normal_executor,
            cpu_verify_executor,
            cpu_snark_executor,
            false,
        )
    }

    pub fn new_with_keys_and_aggregator(
        config: ValidatorConfig,
        num_validators: u64,
        keys_dir: impl AsRef<Path>,
        cpu_normal_executor: Arc<DedicatedExecutor>,
        cpu_verify_executor: Arc<DedicatedExecutor>,
        cpu_snark_executor: Arc<DedicatedExecutor>,
        is_aggregator: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut key_manager = KeyManager::new(&keys_dir)?;

        // Load keys for all assigned validators.
        // When annotated_validators.yaml was used, key_files carries explicit filenames;
        // otherwise fall back to the legacy convention-based paths.
        for &idx in &config.validator_indices {
            if let Some((attest_file, proposal_file)) = config.key_files.get(&idx) {
                let attest_path = keys_dir.as_ref().join(attest_file);
                let proposal_path = keys_dir.as_ref().join(proposal_file);
                key_manager.load_keys_from_files(idx, &attest_path, &proposal_path)?;
            } else {
                key_manager.load_keys(idx)?;
            }
        }

        info!(
            node_id = %config.node_id,
            indices = ?config.validator_indices,
            total_validators = num_validators,
            keys_loaded = config.validator_indices.len(),
            is_aggregator = is_aggregator,
            "VALIDATOR INITIALIZED WITH XMSS KEYS"
        );

        METRICS.get().map(|metrics| {
            metrics
                .lean_validators_count
                .set(config.validator_indices.len() as i64)
        });

        Ok(Self {
            config,
            num_validators,
            key_manager: Some(Arc::new(key_manager)),
            cpu_normal_executor,
            cpu_verify_executor,
            cpu_snark_executor,
            is_aggregator: AtomicBool::new(is_aggregator),
        })
    }

    pub fn get_proposer_for_slot(&self, slot: Slot) -> Option<u64> {
        if self.num_validators == 0 {
            return None;
        }
        let proposer = slot.0 % self.num_validators;

        if self.config.is_assigned(proposer) {
            Some(proposer)
        } else {
            None
        }
    }

    /// Check if this node is an aggregator for the given slot (devnet-3)
    /// For devnet-3, aggregator selection is simplified: a node is an aggregator
    /// if it has validator duties and is_aggregator is enabled via config
    pub fn is_aggregator_for_slot(&self, _slot: Slot) -> bool {
        self.is_aggregator.load(Ordering::Relaxed) && !self.config.validator_indices.is_empty()
    }

    /// Return the current aggregator flag value.
    pub fn get_is_aggregator(&self) -> bool {
        self.is_aggregator.load(Ordering::Relaxed)
    }

    /// Set the aggregator flag at runtime.
    ///
    /// Called by `AggregatorController` when an admin API request toggles
    /// the role.  Uses `Relaxed` ordering because the flag is coordinated
    /// under the controller's `tokio::sync::Mutex` before this is called.
    pub fn set_is_aggregator(&self, enabled: bool) {
        self.is_aggregator.store(enabled, Ordering::Relaxed);
    }

    /// Perform aggregation duty if this node is an aggregator.
    ///
    /// Implements the spec's three-phase `aggregate()` function:
    ///   1. **Select** — greedily pick existing proofs (new payloads first, then known)
    ///      that maximise validator coverage (`select_greedily(new, known)`).
    ///   2. **Fill** — collect raw gossip sigs for validators not covered by children.
    ///   3. **Aggregate** — produce a single recursive XMSS proof.
    ///
    /// Returns `Some((attestations, consumed_data_roots))` where `consumed_data_roots`
    /// is the set of data_roots whose gossip signatures were incorporated into a proof.
    /// The caller must remove those keys from `store.gossip_signatures` to prevent
    /// re-aggregation in future rounds (spec: "consumed gossip signatures are removed").
    ///
    /// Returns `None` if this node has no aggregation duty or nothing to aggregate.
    pub fn maybe_aggregate(
        &self,
        snapshot: &AggregationSnapshot,
        slot: Slot,
        log_inv_rate: usize,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Option<(Vec<SignedAggregatedAttestation>, HashSet<H256>)> {
        if !self.is_aggregator_for_slot(slot) {
            return None;
        }

        if snapshot.jobs.is_empty() && snapshot.settled_data_roots.is_empty() {
            return None;
        }

        let mut aggregated_attestations: Vec<SignedAggregatedAttestation> =
            Vec::with_capacity(snapshot.jobs.len());
        let mut consumed_data_roots: HashSet<H256> =
            HashSet::with_capacity(snapshot.jobs.len() + snapshot.settled_data_roots.len());
        consumed_data_roots.extend(snapshot.settled_data_roots.iter().copied());

        let _session_timer = METRICS.get().map(|m| {
            m.lean_committee_signatures_aggregation_time_seconds
                .start_timer()
        });

        for job in &snapshot.jobs {
            if cancel.load(Ordering::Relaxed) {
                let remaining = snapshot.jobs.len() - aggregated_attestations.len();
                warn!(
                    slot = slot.0,
                    completed = aggregated_attestations.len(),
                    remaining,
                    "Aggregation cancelled after deadline; surfacing partial results"
                );
                METRICS.get().map(|m| {
                    m.lean_aggregator_skipped_total
                        .with_label_values(&["other"])
                        .inc_by(remaining as u64)
                });
                break;
            }

            let all_participants;
            let children_arg: Vec<(&[PublicKey], &AggregatedSignatureProof)>;
            {
                let _setup_timer = METRICS
                    .get()
                    .map(|m| m.grandine_aggregation_job_setup_seconds.start_timer());
                children_arg = job
                    .children
                    .iter()
                    .map(|(pks, proof)| (pks.as_slice(), proof))
                    .collect();

                let mut all_validator_ids: Vec<u64> = job.accepted_child_ids.clone();
                all_validator_ids.extend_from_slice(&job.raw_ids);
                all_validator_ids.sort();
                all_validator_ids.dedup();
                all_participants = AggregationBits::from_validator_indices(&all_validator_ids);
            }

            let type1_start = std::time::Instant::now();
            let proof = match AggregatedSignatureProof::aggregate_with_children(
                all_participants,
                &children_arg,
                job.raw_pubkeys.clone(),
                job.raw_sigs.clone(),
                job.data_root,
                job.attestation_data.slot.0 as u32,
                log_inv_rate,
            ) {
                Ok(p) => {
                    info!(
                        slot = slot.0,
                        raws = job.raw_ids.len(),
                        children = job.children.len(),
                        duration_ms = type1_start.elapsed().as_millis() as u64,
                        "type1_prove",
                    );
                    p
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        data_root = %format!("0x{:x}", job.data_root),
                        "Aggregated signature build failed"
                    );
                    continue;
                }
            };

            info!(
                slot = slot.0,
                validators = job.raw_ids.len() + job.accepted_child_ids.len(),
                children = job.children.len(),
                data_root = %format!("0x{:x}", job.data_root),
                "Created aggregated attestation"
            );

            aggregated_attestations.push(SignedAggregatedAttestation {
                data: job.attestation_data.clone(),
                proof,
            });

            if !job.raw_ids.is_empty() {
                consumed_data_roots.insert(job.data_root);
            }
        }

        if aggregated_attestations.is_empty() && consumed_data_roots.is_empty() {
            return None;
        }

        Some((aggregated_attestations, consumed_data_roots))
    }

    /// Sign a block given pre-fetched attestation data.
    ///
    /// Unlike `sign_block`, this method does not need a `&Store` reference.
    /// The validator task calls `BuildAttestationData` on the chain task first,
    /// receives the `AttestationData` via oneshot, then calls this method.
    /// This keeps XMSS signing (~170ms) entirely off the chain task's thread.
    pub async fn sign_block_with_data(
        &self,
        block: Block,
        validator_index: u64,
        attestation_signatures: Vec<AggregatedSignatureProof>,
        validators: Validators,
        log_inv_rate: usize,
    ) -> Result<SignedBlock> {
        let Some(key_manager) = self.key_manager.as_ref() else {
            bail!("unable to sign block - keymanager not configured");
        };

        let exec = self.cpu_snark_executor.clone();
        let km = Arc::clone(key_manager);

        let job = exec.spawn(async move {
            let block_root = block.hash_tree_root();
            let block_slot = block.slot.0 as u32;

            let proposer = validators
                .get(validator_index)
                .context(format!("proposer {validator_index} not found in state"))?;
            let proposer_proposal_pubkey = proposer.proposal_pubkey.clone();

            let proposer_raw_signature = km
                .sign_proposal(validator_index, block_slot, block_root)
                .context("failed to sign block root")?;

            let proposer_type1 = AggregatedSignature::aggregate(
                [proposer_proposal_pubkey.clone()],
                [proposer_raw_signature],
                block_root,
                block_slot,
                log_inv_rate,
            )
            .context("failed to wrap proposer signature into Type-1 aggregate")?;

            let mut pubkeys_owned: Vec<Vec<xmss::PublicKey>> =
                Vec::with_capacity(attestation_signatures.len() + 1);
            for sig in &attestation_signatures {
                let mut pks = Vec::new();
                for vid in sig.participants.to_validator_indices() {
                    let v = validators
                        .get(vid)
                        .context(format!("attester {vid} not found in state"))?;
                    pks.push(v.attestation_pubkey.clone());
                }
                pubkeys_owned.push(pks);
            }
            pubkeys_owned.push(vec![proposer_proposal_pubkey]);

            let mut parts: Vec<(&AggregatedSignature, &[xmss::PublicKey])> =
                Vec::with_capacity(attestation_signatures.len() + 1);
            for (i, sig) in attestation_signatures.iter().enumerate() {
                parts.push((&sig.proof_data, pubkeys_owned[i].as_slice()));
            }
            parts.push((
                &proposer_type1,
                pubkeys_owned[attestation_signatures.len()].as_slice(),
            ));

            let type2_start = std::time::Instant::now();
            let proof = MultiMessageAggregate::aggregate(&parts, log_inv_rate)
                .context("failed to assemble Type-2 block proof")?;
            info!(
                block_slot,
                parts = parts.len(),
                duration_ms = type2_start.elapsed().as_millis() as u64,
                "type2_prove",
            );

            Ok(SignedBlock { block, proof })
        });

        job.await.unwrap_or_else(|e| Err(anyhow!("executor: {e}")))
    }

    /// Create and sign attestations for all validators given pre-fetched attestation data.
    ///
    /// Unlike `create_attestations`, this method does not need a `&Store` reference.
    /// The validator task calls `BuildAttestationData` on the chain task first,
    /// receives the `AttestationData` via oneshot, then calls this method.
    /// This keeps XMSS signing entirely off the chain task's thread.
    pub async fn create_attestations_from_data(
        &self,
        slot: Slot,
        attestation_data: AttestationData,
    ) -> Vec<SignedAttestation> {
        if attestation_data.target.slot < attestation_data.source.slot {
            warn!(
                target_slot = attestation_data.target.slot.0,
                source_slot = attestation_data.source.slot.0,
                "Skipping attestation: target slot must be >= source slot"
            );
            return vec![];
        }

        let _production_timer = METRICS.get().map(|metrics| {
            metrics
                .lean_attestations_production_time_seconds
                .start_timer()
        });

        // No keys: return zero-signature attestations directly (test / passive mode).
        let Some(key_manager) = self.key_manager.as_ref() else {
            return self
                .config
                .validator_indices
                .iter()
                .map(|&idx| {
                    info!(
                        slot = slot.0,
                        validator = idx,
                        "Created attestation with zero signature"
                    );
                    SignedAttestation {
                        validator_id: idx,
                        message: attestation_data.clone(),
                        signature: Signature::default(),
                    }
                })
                .collect();
        };

        let message = attestation_data.hash_tree_root();
        let epoch = slot.0 as u32;
        let target_slot = attestation_data.target.slot.0;
        let source_slot = attestation_data.source.slot.0;

        // Fan out signing across the executor's worker threads so we get
        // concurrent XMSS signing instead of one-at-a-time on this task.
        let mut sign_jobs = FuturesUnordered::new();
        for &idx in &self.config.validator_indices {
            let exec = self.cpu_normal_executor.clone();
            let km = Arc::clone(key_manager);
            sign_jobs.push(async move {
                let job = exec.spawn(async move {
                    let _timer = METRICS.get().map(|metrics| {
                        metrics
                            .lean_pq_sig_attestation_signing_time_seconds
                            .start_timer()
                    });
                    km.sign_attestation(idx, epoch, message)
                });
                let result = job.await.unwrap_or_else(|e| Err(anyhow!("executor: {e}")));
                (idx, result)
            });
        }

        let mut attestations = Vec::with_capacity(self.config.validator_indices.len());
        while let Some((idx, sig_result)) = sign_jobs.next().await {
            match sig_result {
                Ok(signature) => {
                    METRICS.get().map(|metrics| {
                        metrics.lean_pq_sig_attestation_signatures_total.inc();
                    });
                    info!(
                        slot = slot.0,
                        validator = idx,
                        target_slot,
                        source_slot,
                        "Created signed attestation"
                    );
                    attestations.push(SignedAttestation {
                        validator_id: idx,
                        message: attestation_data.clone(),
                        signature,
                    });
                }
                Err(e) => warn!(
                    validator = idx,
                    error = %e,
                    "Failed to sign attestation, skipping"
                ),
            }
        }
        attestations
    }
}
