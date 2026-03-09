// Lean validator client with XMSS signing support
use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use containers::{
    AggregatedSignatureProof, AggregationBits, Attestation, AttestationData, AttestationSignatures,
    Block, BlockSignatures, BlockWithAttestation, Checkpoint, SignatureKey,
    SignedAggregatedAttestation, SignedAttestation, SignedBlockWithAttestation, Slot,
};
use fork_choice::store::{Store, produce_block_with_signatures};
use metrics::{METRICS, stop_and_discard, stop_and_record};
use ssz::H256;
use ssz::SszHash;
use tracing::{info, warn};
use try_from_iterator::TryFromIterator as _;

pub mod keys;

use keys::KeyManager;
use xmss::Signature;

pub type ValidatorRegistry = HashMap<String, Vec<u64>>;
// Node
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub node_id: String,
    pub validator_indices: Vec<u64>,
}

impl ValidatorConfig {
    // load validator index
    pub fn load_from_file(path: impl AsRef<Path>, node_id: &str) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let registry: ValidatorRegistry = serde_yaml::from_reader(file)?;

        let indices = registry
            .get(node_id)
            .ok_or_else(|| anyhow!("Node `{node_id}` not found in validator registry"))?
            .clone();

        info!(node_id = %node_id, indices = ?indices, "Validator config loaded...");

        Ok(ValidatorConfig {
            node_id: node_id.to_string(),
            validator_indices: indices,
        })
    }

    pub fn is_assigned(&self, index: u64) -> bool {
        self.validator_indices.contains(&index)
    }
}

pub struct ValidatorService {
    pub config: ValidatorConfig,
    pub num_validators: u64,
    key_manager: Option<KeyManager>,
    /// Whether this node performs aggregation duties (devnet-3)
    is_aggregator: bool,
}

impl ValidatorService {
    pub fn new(config: ValidatorConfig, num_validators: u64) -> Self {
        Self::new_with_aggregator(config, num_validators, false)
    }

    pub fn new_with_aggregator(
        config: ValidatorConfig,
        num_validators: u64,
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
            is_aggregator,
        }
    }

    pub fn new_with_keys(
        config: ValidatorConfig,
        num_validators: u64,
        keys_dir: impl AsRef<Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_keys_and_aggregator(config, num_validators, keys_dir, false)
    }

    pub fn new_with_keys_and_aggregator(
        config: ValidatorConfig,
        num_validators: u64,
        keys_dir: impl AsRef<Path>,
        is_aggregator: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut key_manager = KeyManager::new(keys_dir)?;

        // Load keys for all assigned validators
        for &idx in &config.validator_indices {
            key_manager.load_key(idx)?;
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
            key_manager: Some(key_manager),
            is_aggregator,
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
        self.is_aggregator && !self.config.validator_indices.is_empty()
    }

    /// Perform aggregation duty if this node is an aggregator (devnet-3)
    /// Collects signatures from gossip_signatures and creates aggregated attestations
    /// Returns None if not an aggregator or no signatures to aggregate
    pub fn maybe_aggregate(
        &self,
        store: &Store,
        slot: Slot,
    ) -> Option<Vec<SignedAggregatedAttestation>> {
        if !self.is_aggregator_for_slot(slot) {
            return None;
        }

        // Get the head state to access validator public keys
        let head_state = store.states.get(&store.head)?;

        // Group signatures by data_root
        // SignatureKey contains (validator_id, data_root)
        let mut groups: HashMap<H256, Vec<(u64, Signature)>> = HashMap::new();

        for (sig_key, signature) in &store.gossip_signatures {
            groups
                .entry(sig_key.data_root)
                .or_default()
                .push((sig_key.validator_id, signature.clone()));
        }

        if groups.is_empty() {
            info!(slot = slot.0, "No signatures to aggregate");
            return None;
        }

        let mut aggregated_attestations = Vec::new();

        for (data_root, validator_sigs) in groups {
            // Look up attestation data by its hash (data_root)
            // This ensures we get the exact attestation that was signed,
            // matching ream's attestation_data_by_root_provider approach
            let Some(attestation_data) = store.attestation_data_by_root.get(&data_root).cloned()
            else {
                warn!(
                    data_root = %format!("0x{:x}", data_root),
                    "Could not find attestation data for aggregation group"
                );
                continue;
            };

            // Only aggregate attestations for the current slot
            if attestation_data.slot != slot {
                continue;
            }

            // Collect validator IDs, public keys, and signatures
            // IMPORTANT: Must sort by validator_id to match ream/zeam behavior.
            // The participants bitfield is iterated in ascending order during verification,
            // so the proof must be created with public_keys/signatures in the same order.
            let mut entries: Vec<(u64, Signature)> = validator_sigs
                .into_iter()
                .filter(|(vid, _)| head_state.validators.get(*vid).is_ok())
                .collect();
            entries.sort_by_key(|(vid, _)| *vid);

            let mut validator_ids = Vec::new();
            let mut public_keys = Vec::new();
            let mut signatures = Vec::new();

            for (vid, sig) in entries {
                // Get public key from state validators (already filtered above)
                let validator = head_state.validators.get(vid).unwrap();
                validator_ids.push(vid);
                public_keys.push(validator.pubkey.clone());
                signatures.push(sig);
            }

            if validator_ids.is_empty() {
                continue;
            }

            // Create aggregation bits from validator IDs
            let participants = AggregationBits::from_validator_indices(&validator_ids);

            // Create the aggregated signature proof
            // Uses attestation_data.slot as epoch (matches ream's approach)
            let proof = match AggregatedSignatureProof::aggregate(
                participants,
                public_keys,
                signatures,
                data_root,
                attestation_data.slot.0 as u32,
            ) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "Failed to create aggregated signature proof");
                    continue;
                }
            };

            info!(
                slot = slot.0,
                validators = validator_ids.len(),
                data_root = %format!("0x{:x}", data_root),
                "Created aggregated attestation"
            );

            // Create SignedAggregatedAttestation matching ream/zeam structure
            aggregated_attestations.push(SignedAggregatedAttestation {
                data: attestation_data,
                proof,
            });
        }

        if aggregated_attestations.is_empty() {
            None
        } else {
            Some(aggregated_attestations)
        }
    }

    /// Build a block proposal for the given slot
    pub fn build_block_proposal(
        &self,
        store: &mut Store,
        slot: Slot,
        proposer_index: u64,
    ) -> Result<SignedBlockWithAttestation> {
        info!(
            slot = slot.0,
            proposer = proposer_index,
            "Building block proposal"
        );

        let (_, block, signatures) = produce_block_with_signatures(store, slot, proposer_index)
            .context("failed to produce block")?;

        let signed_block = self.sign_block(store, block, proposer_index, signatures)?;

        Ok(signed_block)
    }

    fn sign_block(
        &self,
        store: &Store,
        block: Block,
        validator_index: u64,
        attestation_signatures: Vec<AggregatedSignatureProof>,
    ) -> Result<SignedBlockWithAttestation> {
        let proposer_attestation_data = store.produce_attestation_data(block.slot)?;

        let proposer_attestation = Attestation {
            validator_id: validator_index,
            data: proposer_attestation_data,
        };

        let Some(key_manager) = self.key_manager.as_ref() else {
            bail!("unable to sign block - keymanager not configured");
        };

        let proposer_signature = {
            let sign_timer = METRICS.get().map(|metrics| {
                metrics
                    .lean_pq_sig_attestation_signing_time_seconds
                    .start_timer()
            });

            key_manager
                .sign(
                    validator_index,
                    block.slot.0 as u32,
                    proposer_attestation.data.hash_tree_root(),
                )
                .context("failed to sign block")
                .inspect_err(|_| stop_and_discard(sign_timer))?
        };

        let message = BlockWithAttestation {
            block,
            proposer_attestation,
        };

        let signature = BlockSignatures {
            attestation_signatures: AttestationSignatures::try_from_iter(attestation_signatures)
                .context("invalid attestation signatures")?,
            proposer_signature,
        };

        Ok(SignedBlockWithAttestation { message, signature })
    }

    /// Create attestations for all our validators for the given slot
    pub fn create_attestations(&self, store: &Store, slot: Slot) -> Vec<SignedAttestation> {
        let vote_target = store.get_attestation_target();

        // Skip attestation creation if target slot is less than source slot
        // At genesis, both target and source are slot 0, which is valid
        if vote_target.slot < store.latest_justified.slot {
            warn!(
                target_slot = vote_target.slot.0,
                source_slot = store.latest_justified.slot.0,
                "Skipping attestation: target slot must be >= source slot"
            );
            return vec![];
        }

        let head_block = match store.blocks.get(&store.head) {
            Some(b) => b,
            None => {
                warn!("WARNING: Attestation skipped. (Reason: HEAD BLOCK NOT FOUND)");
                return vec![];
            }
        };

        let head_checkpoint = Checkpoint {
            root: store.head,
            slot: head_block.slot,
        };

        self.config
            .validator_indices
            .iter()
            .filter_map(|&idx| {
                let attestation = AttestationData {
                    slot,
                    head: head_checkpoint.clone(),
                    target: vote_target.clone(),
                    source: store.latest_justified.clone(),
                };

                let signature = if let Some(ref key_manager) = self.key_manager {
                    let _timer = METRICS.get().map(|metrics| {
                        metrics
                            .lean_pq_sig_attestation_signing_time_seconds
                            .start_timer()
                    });

                    // Sign with XMSS
                    let message = attestation.hash_tree_root();
                    let epoch = slot.0 as u32;

                    let _timer = METRICS.get().map(|metrics| {
                        metrics
                            .lean_pq_sig_attestation_signing_time_seconds
                            .start_timer()
                    });
                    match key_manager.sign(idx, epoch, message) {
                        Ok(sig) => {
                            info!(
                                slot = slot.0,
                                validator = idx,
                                target_slot = vote_target.slot.0,
                                source_slot = store.latest_justified.slot.0,
                                "Created signed attestation"
                            );
                            sig
                        }
                        Err(e) => {
                            warn!(
                                validator = idx,
                                error = %e,
                                "Failed to sign attestation, skipping"
                            );
                            return None;
                        }
                    }
                } else {
                    // No key manager - use zero signature
                    info!(
                        slot = slot.0,
                        validator = idx,
                        target_slot = vote_target.slot.0,
                        source_slot = store.latest_justified.slot.0,
                        "Created attestation with zero signature"
                    );
                    Signature::default()
                };

                Some(SignedAttestation {
                    validator_id: idx,
                    message: attestation,
                    signature,
                })
            })
            .collect()
    }
}
