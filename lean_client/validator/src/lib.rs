// Lean validator client with XMSS signing support
use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use containers::{
    Attestation, AttestationData, BlockSignatures, BlockWithAttestation, Checkpoint,
    SignedAttestation, SignedBlockWithAttestation, Slot,
};
use ethereum_types::H256;
use fork_choice::store::{Store, get_proposal_head, get_vote_target};
use metrics::METRICS;
use ssz::SszHash;
use tracing::{info, warn};

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
}

impl ValidatorService {
    pub fn new(config: ValidatorConfig, num_validators: u64) -> Self {
        info!(
            node_id = %config.node_id,
            indices = ?config.validator_indices,
            total_validators = num_validators,
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
        }
    }

    pub fn new_with_keys(
        config: ValidatorConfig,
        num_validators: u64,
        keys_dir: impl AsRef<Path>,
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

        let parent_root = get_proposal_head(store, slot);

        info!(
            parent_root = %format!("0x{:x}", parent_root),
            store_head = %format!("0x{:x}", store.head),
            "Using parent root for block proposal"
        );

        let parent_state = store
            .states
            .get(&parent_root)
            .ok_or_else(|| anyhow!("Couldn't find parent state {:?}", parent_root))?;

        let vote_target = get_vote_target(store);

        // Validate that target slot is greater than or equal to source slot
        // At genesis, both target and source are slot 0, which is valid
        ensure!(
            vote_target.slot >= store.latest_justified.slot,
            "Invalid attestation: target slot {} must be >= source slot {}",
            vote_target.slot.0,
            store.latest_justified.slot.0
        );

        let head_block = store
            .blocks
            .get(&store.head)
            .ok_or(anyhow!("Head block not found"))?;
        let head_checkpoint = Checkpoint {
            root: store.head,
            slot: head_block.slot,
        };

        let proposer_attestation = Attestation {
            validator_id: proposer_index,
            data: AttestationData {
                slot,
                head: head_checkpoint,
                target: vote_target.clone(),
                source: store.latest_justified.clone(),
            },
        };

        // Collect valid attestations from the KNOWN attestations pool.
        // Note: get_proposal_head() calls accept_new_attestations() which moves attestations
        // from latest_new_attestations to latest_known_attestations. So we must read from
        // latest_known_attestations here, not latest_new_attestations.
        // Filter to only include attestations that:
        // 1. Have source matching the parent state's justified checkpoint
        // 2. Have target slot > source slot (valid attestations)
        // 3. Target block must be known
        // 4. Target is not already justified in parent state
        // 5. Source is justified in parent state

        // Helper: check if a slot is justified using RELATIVE indexing
        // Slots at or before finalized_slot are implicitly justified
        let finalized_slot = parent_state.latest_finalized.slot.0 as i64;
        let is_slot_justified = |slot: Slot| -> bool {
            if (slot.0 as i64) <= finalized_slot {
                return true; // Implicitly justified (at or before finalized)
            }
            let relative_index = (slot.0 as i64 - finalized_slot - 1) as usize;
            parent_state
                .justified_slots
                .get(relative_index)
                .map(|b| *b)
                .unwrap_or(false)
        };

        let valid_attestations: Vec<Attestation> = store
            .latest_known_attestations
            .iter()
            .filter(|(_, data)| {
                // Source must match the store's justified checkpoint
                // (attestations are created with store.latest_justified as source)
                let source_matches = data.source == store.latest_justified;
                // Target must be strictly after source
                let target_after_source = data.target.slot > data.source.slot;
                // Target block must be known
                let target_known = store.blocks.contains_key(&data.target.root);

                // Check if target is NOT already justified (using relative indexing)
                let target_already_justified = is_slot_justified(data.target.slot);

                // Check if source is justified (using relative indexing)
                let source_is_justified = is_slot_justified(data.source.slot);

                source_matches
                    && target_after_source
                    && target_known
                    && source_is_justified
                    && !target_already_justified
            })
            .map(|(validator_idx, data)| Attestation {
                validator_id: *validator_idx,
                data: data.clone(),
            })
            .collect();

        // De-duplicate by target slot: only include ONE aggregated attestation per target slot.
        // This prevents the case where the first attestation justifies a slot and the second
        // gets rejected (causing state root mismatch).
        // Group by target slot, keeping attestations with the most common AttestationData.
        use std::collections::HashMap;

        // First group by target slot
        let mut target_slot_groups: HashMap<u64, Vec<Attestation>> = HashMap::new();
        for att in valid_attestations {
            let target_slot = att.data.target.slot.0;
            target_slot_groups.entry(target_slot).or_default().push(att);
        }

        // For each target slot, group by data root and pick the one with most votes
        let valid_attestations: Vec<Attestation> = target_slot_groups
            .into_iter()
            .flat_map(|(_, slot_atts)| {
                // Group by data root (Bytes32 implements Hash)
                let mut data_groups: HashMap<H256, Vec<Attestation>> = HashMap::new();
                for att in slot_atts {
                    let data_root = att.data.hash_tree_root();
                    data_groups.entry(data_root).or_default().push(att);
                }
                // Find the data with the most attestations
                data_groups
                    .into_iter()
                    .max_by_key(|(_, atts)| atts.len())
                    .map(|(_, atts)| atts)
                    .unwrap_or_default()
            })
            .collect();

        let num_attestations = valid_attestations.len();

        info!(
            slot = slot.0,
            valid_attestations = num_attestations,
            total_known = store.latest_known_attestations.len(),
            "Collected attestations for block"
        );

        // Build block with collected attestations
        // Pass gossip_signatures and aggregated_payloads from the store so that
        // compute_aggregated_signatures can find signatures for the attestations
        let (block, _post_state, _collected_atts, sigs) = {
            parent_state.build_block(
                slot,
                proposer_index,
                parent_root,
                Some(valid_attestations),
                None,                             // available_attestations
                None,                             // known_block_roots
                Some(&store.gossip_signatures),   // gossip_signatures
                Some(&store.aggregated_payloads), // aggregated_payloads
            )?
        };

        let signatures = sigs;

        info!(
            slot = block.slot.0,
            proposer = block.proposer_index,
            parent_root = %format!("0x{:x}", block.parent_root),
            state_root = %format!("0x{:x}", block.state_root),
            attestation_sigs = num_attestations,
            "Block built successfully"
        );

        // Sign the proposer attestation
        let proposer_signature: Signature;

        if let Some(ref key_manager) = self.key_manager {
            let _timer = METRICS.get().map(|metrics| {
                metrics
                    .lean_pq_signature_attestation_signing_time_seconds
                    .start_timer()
            });

            // Sign proposer attestation with XMSS
            let message = proposer_attestation.hash_tree_root();
            let epoch = slot.0 as u32;

            match key_manager.sign(proposer_index, epoch, message) {
                Ok(sig) => {
                    proposer_signature = sig;
                    info!(proposer = proposer_index, "Signed proposer attestation");
                }
                Err(e) => {
                    bail!("Failed to sign proposer attestation: {}", e);
                }
            }
        } else {
            // No key manager - use zero signature
            warn!("Building block with zero signature (no key manager)");
            proposer_signature = Signature::default();
        }

        // Convert signatures to PersistentList for BlockSignatures
        // Extract proof_data from AggregatedSignatureProof for wire format
        let attestation_signatures = {
            let mut list = ssz::PersistentList::default();
            for proof in signatures {
                list.push(proof)
                    .context("Failed to add attestation signature")?;
            }
            list
        };

        let signed_block = SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation,
            },
            signature: BlockSignatures {
                attestation_signatures,
                proposer_signature,
            },
        };

        Ok(signed_block)
    }

    /// Create attestations for all our validators for the given slot
    pub fn create_attestations(&self, store: &Store, slot: Slot) -> Vec<SignedAttestation> {
        let vote_target = get_vote_target(store);

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
                            .lean_pq_signature_attestation_signing_time_seconds
                            .start_timer()
                    });

                    // Sign with XMSS
                    let message = attestation.hash_tree_root();
                    let epoch = slot.0 as u32;

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
