// Lean validator client with XMSS signing support
use std::collections::HashMap;
use std::path::Path;

use containers::block::BlockSignatures;
use containers::ssz;
use containers::{
    attestation::{Attestation, AttestationData, Signature, SignedAttestation},
    block::{hash_tree_root, BlockWithAttestation, SignedBlockWithAttestation},
    checkpoint::Checkpoint,
    types::{Uint64, ValidatorIndex},
    AggregatedAttestation, Slot,
};
use fork_choice::store::{get_proposal_head, get_vote_target, Store};
use tracing::{info, warn};

pub mod keys;

use keys::KeyManager;

pub type ValidatorRegistry = HashMap<String, Vec<u64>>;
// Node
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub node_id: String,
    pub validator_indices: Vec<u64>,
}

impl ValidatorConfig {
    // load validator index
    pub fn load_from_file(
        path: impl AsRef<Path>,
        node_id: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path)?;
        let registry: ValidatorRegistry = serde_yaml::from_reader(file)?;

        let indices = registry
            .get(node_id)
            .ok_or_else(|| format!("Node '{}' not found in validator registry", node_id))?
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

        Ok(Self {
            config,
            num_validators,
            key_manager: Some(key_manager),
        })
    }

    pub fn get_proposer_for_slot(&self, slot: Slot) -> Option<ValidatorIndex> {
        if self.num_validators == 0 {
            return None;
        }
        let proposer = slot.0 % self.num_validators;

        if self.config.is_assigned(proposer) {
            Some(ValidatorIndex(proposer))
        } else {
            None
        }
    }

    /// Build a block proposal for the given slot
    pub fn build_block_proposal(
        &self,
        store: &mut Store,
        slot: Slot,
        proposer_index: ValidatorIndex,
    ) -> Result<SignedBlockWithAttestation, String> {
        info!(
            slot = slot.0,
            proposer = proposer_index.0,
            "Building block proposal"
        );

        let parent_root = get_proposal_head(store, slot);
        let parent_state = store
            .states
            .get(&parent_root)
            .ok_or_else(|| format!("Couldn't find parent state {:?}", parent_root))?;

        let vote_target = get_vote_target(store);

        // Validate that target slot is strictly greater than source slot
        if vote_target.slot <= store.latest_justified.slot {
            return Err(format!(
                "Invalid attestation: target slot {} must be greater than source slot {}",
                vote_target.slot.0, store.latest_justified.slot.0
            ));
        }

        let head_block = store
            .blocks
            .get(&store.head)
            .ok_or("Head block not found")?;
        let head_checkpoint = Checkpoint {
            root: store.head,
            slot: head_block.message.block.slot,
        };

        let proposer_attestation = Attestation {
            validator_id: Uint64(proposer_index.0),
            data: AttestationData {
                slot,
                head: head_checkpoint,
                target: vote_target.clone(),
                source: store.latest_justified.clone(),
            },
        };

        // Collect valid attestations from the NEW attestations pool (gossip attestations
        // that haven't been included in any block yet).
        // Do NOT use latest_known_attestations - those have already been included in blocks!
        // Filter to only include attestations that:
        // 1. Have source matching the parent state's justified checkpoint
        // 2. Have target slot > source slot (valid attestations)
        // 3. Target block must be known
        // Also collect the corresponding signatures
        let valid_signed_attestations: Vec<&SignedAttestation> = store
            .latest_new_attestations
            .values()
            .filter(|att| {
                let data = &att.message;
                // Source must match the parent state's justified checkpoint (not store's!)
                let source_matches = data.source == parent_state.latest_justified;
                // Target must be strictly after source
                let target_after_source = data.target.slot > data.source.slot;
                // Target block must be known
                let target_known = store.blocks.contains_key(&data.target.root);

                source_matches && target_after_source && target_known
            })
            .collect();

        let valid_attestations: Vec<AttestationData> = valid_signed_attestations
            .iter()
            .map(|att| att.message.clone())
            .collect();

        #[cfg(feature = "devnet2")]
        let valid_attestations: Vec<AttestationData> = valid_signed_attestations
            .iter()
            .map(|att| att.message.clone())
            .collect();

        info!(
            slot = slot.0,
            valid_attestations = valid_attestations.len(),
            total_new = store.latest_new_attestations.len(),
            "Collected new attestations for block"
        );

        // Build block with collected attestations (empty body - attestations go to state)
        let (block, _post_state, _collected_atts, sigs) = {
            let valid_attestations: Vec<Attestation> = valid_attestations
                .iter()
                .map(|data| Attestation {
                    validator_id: Uint64(0), // Placeholder, real validator IDs should be used
                    data: data.clone(),
                })
                .collect();
            parent_state.build_block(
                slot,
                proposer_index,
                parent_root,
                Some(valid_attestations),
                None,
                None,
                None,
                None,
            )?
        };

        let signatures = sigs;

        info!(
            slot = block.slot.0,
            proposer = block.proposer_index.0,
            parent_root = %format!("0x{:x}", block.parent_root.0),
            state_root = %format!("0x{:x}", block.state_root.0),
            attestation_sigs = valid_signed_attestations.len(),
            "Block built successfully"
        );

        // Sign the proposer attestation
        let proposer_signature: Signature;

        if let Some(ref key_manager) = self.key_manager {
            // Sign proposer attestation with XMSS
            let message = hash_tree_root(&proposer_attestation);
            let epoch = slot.0 as u32;

            match key_manager.sign(proposer_index.0, epoch, &message.0.into()) {
                Ok(sig) => {
                    proposer_signature = sig;
                    info!(proposer = proposer_index.0, "Signed proposer attestation");
                }
                Err(e) => {
                    return Err(format!("Failed to sign proposer attestation: {}", e));
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
                    .map_err(|e| format!("Failed to add attestation signature: {:?}", e))?;
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

        // Skip attestation creation if target slot is not strictly greater than source slot
        // This prevents creating invalid attestations when the node's view is behind
        if vote_target.slot <= store.latest_justified.slot {
            warn!(
                target_slot = vote_target.slot.0,
                source_slot = store.latest_justified.slot.0,
                "Skipping attestation: target slot must be greater than source slot"
            );
            return vec![];
        }

        let get_head_block_info = match store.blocks.get(&store.head) {
            Some(b) => b,
            None => {
                // Pasileiskit, su DEBUG. Kitaip galima pakeist i tiesiog
                // println!("WARNING: Attestation skipped. (Reason: HEAD BLOCK NOT FOUND)\n");
                warn!("WARNING: Attestation skipped. (Reason: HEAD BLOCK NOT FOUND)");
                return vec![];
            }
        };

        let head_checkpoint = Checkpoint {
            root: store.head,
            slot: get_head_block_info.message.block.slot,
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

                #[cfg(feature = "devnet2")]
                let attestation = AttestationData {
                    slot,
                    head: head_checkpoint.clone(),
                    target: vote_target.clone(),
                    source: store.latest_justified.clone(),
                };

                let signature = if let Some(ref key_manager) = self.key_manager {
                    // Sign with XMSS
                    let message = hash_tree_root(&attestation);
                    let epoch = slot.0 as u32;

                    match key_manager.sign(idx, epoch, &message.0.into()) {
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

// DI GENERUOTI TESTAI
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proposer_selection() {
        let config = ValidatorConfig {
            node_id: "test_0".to_string(),
            validator_indices: vec![2],
        };
        let service = ValidatorService::new(config, 4);

        // Validator 2 should propose at slots 2, 6, 10, ...
        assert!(service.get_proposer_for_slot(Slot(2)).is_some());
        assert!(service.get_proposer_for_slot(Slot(6)).is_some());
        assert!(service.get_proposer_for_slot(Slot(10)).is_some());

        // Validator 2 should NOT propose at slots 0, 1, 3, 4, 5, ...
        assert!(service.get_proposer_for_slot(Slot(0)).is_none());
        assert!(service.get_proposer_for_slot(Slot(1)).is_none());
        assert!(service.get_proposer_for_slot(Slot(3)).is_none());
        assert!(service.get_proposer_for_slot(Slot(4)).is_none());
        assert!(service.get_proposer_for_slot(Slot(5)).is_none());
    }

    #[test]
    fn test_is_assigned() {
        let config = ValidatorConfig {
            node_id: "test_0".to_string(),
            validator_indices: vec![2, 5, 8],
        };

        assert!(config.is_assigned(2));
        assert!(config.is_assigned(5));
        assert!(config.is_assigned(8));
        assert!(!config.is_assigned(0));
        assert!(!config.is_assigned(1));
        assert!(!config.is_assigned(3));
    }
}
