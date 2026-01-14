// Lean validator client with XMSS signing support
use std::collections::HashMap;
use std::path::Path;
use containers::ssz::SszHash;

#[cfg(feature = "devnet2")]
use containers::attestation::{NaiveAggregatedSignature};
use containers::block::BlockSignatures;
use containers::{
    attestation::{Attestation, AttestationData, Signature, SignedAttestation},
    block::{BlockWithAttestation, SignedBlockWithAttestation},
    checkpoint::Checkpoint,
    types::ValidatorIndex, Slot,
};
use fork_choice::store::{get_proposal_head, get_vote_target, Store};
use tracing::{info, warn};

pub mod keys;

use keys::KeyManager;

pub type ValidatorRegistry = HashMap<String, Vec<u64>>;

#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub node_id: String,
    pub validator_indices: Vec<u64>,
}

impl ValidatorConfig {
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
            Some(proposer) // ValidatorIndex dabar yra u64, todėl tiesiog grąžiname reikšmę
        } else {
            None
        }
    }

    pub fn build_block_proposal(
        &self,
        store: &mut Store,
        slot: Slot,
        proposer_index: ValidatorIndex,
    ) -> Result<SignedBlockWithAttestation, String> {
        info!(
            slot = slot.0,
            proposer = proposer_index,
            "Building block proposal"
        );

        let parent_root = get_proposal_head(store, slot);
        let parent_state = store
            .states
            .get(&parent_root)
            .ok_or_else(|| format!("Couldn't find parent state {:?}", parent_root))?;

        let vote_target = get_vote_target(store);

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
            validator_id: proposer_index,
            data: AttestationData {
                slot,
                head: head_checkpoint,
                target: vote_target.clone(),
                source: store.latest_justified.clone(),
            },
        };

        let valid_signed_attestations: Vec<&SignedAttestation> = store
            .latest_new_attestations
            .values()
            .filter(|att| {
                #[cfg(feature = "devnet1")]
                let data = &att.message.data;
                #[cfg(feature = "devnet2")]
                let data = &att.message;
                
                let source_matches = data.source == parent_state.latest_justified;
                let target_after_source = data.target.slot > data.source.slot;
                let target_known = store.blocks.contains_key(&data.target.root);

                source_matches && target_after_source && target_known
            })
            .collect();

        #[cfg(feature = "devnet1")]
        let valid_attestations: Vec<Attestation> = valid_signed_attestations
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

        #[cfg(feature = "devnet1")]
        let (block, _post_state, _collected_atts, sigs) = parent_state.build_block(
            slot,
            proposer_index,
            parent_root,
            Some(valid_attestations),
            None,
            None,
        )?;

        #[cfg(feature = "devnet2")]
        let (block, _post_state, _collected_atts, sigs) = {
            let valid_atts_wrapped: Vec<Attestation> = valid_attestations
                .iter()
                .map(|data| Attestation {
                    validator_id: 0,
                    data: data.clone(),
                })
                .collect();
            parent_state.build_block(
                slot,
                proposer_index,
                parent_root,
                Some(valid_atts_wrapped),
                None,
                None,
            )?
        };

        #[cfg(feature = "devnet1")]
        let mut signatures = sigs;
        #[cfg(feature = "devnet2")]
        let mut signatures = sigs.attestation_signatures;

        for signed_att in &valid_signed_attestations {
            #[cfg(feature = "devnet1")]
            signatures
                .push(signed_att.signature.clone())
                .map_err(|e| format!("Failed to add attestation signature: {:?}", e))?;
            #[cfg(feature = "devnet2")]
            {
                let aggregated_sig: NaiveAggregatedSignature = NaiveAggregatedSignature::default();
                signatures
                    .push(aggregated_sig)
                    .map_err(|e| format!("Failed to add attestation signature: {:?}", e))?;
            }
        }

        info!(
            slot = block.slot.0,
            proposer = block.proposer_index,
            parent_root = %hex::encode(block.parent_root),
            state_root = %hex::encode(block.state_root),
            attestation_sigs = valid_signed_attestations.len(),
            "Block built successfully"
        );

        if let Some(ref key_manager) = self.key_manager {
            let message = proposer_attestation.hash_tree_root();
            let epoch = slot.0 as u32;

            match key_manager.sign(proposer_index, epoch, &message.into()) {
                Ok(sig) => {
                    #[cfg(feature = "devnet1")]
                    signatures
                        .push(sig)
                        .map_err(|e| format!("Failed to add proposer signature: {:?}", e))?;
                    
                    #[cfg(feature = "devnet2")]
                    {
                        let aggregated_sig: NaiveAggregatedSignature = NaiveAggregatedSignature::default();
                        signatures
                            .push(aggregated_sig)
                            .map_err(|e| format!("Failed to add proposer signature: {:?}", e))?;
                    }
                    info!(proposer = proposer_index, "Signed proposer attestation");
                }
                Err(e) => {
                    return Err(format!("Failed to sign proposer attestation: {}", e));
                }
            }
        } else {
            warn!("Building block with zero signature (no key manager)");
        }

        let signed_block = SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation,
            },
            #[cfg(feature = "devnet1")]
            signature: signatures,
            #[cfg(feature = "devnet2")]
            signature: BlockSignatures {
                attestation_signatures: signatures,
                proposer_signature: Signature::default(),
            },
        };

        Ok(signed_block)
    }

    pub fn create_attestations(&self, store: &Store, slot: Slot) -> Vec<SignedAttestation> {
        let vote_target = get_vote_target(store);

        if vote_target.slot <= store.latest_justified.slot {
            warn!(
                target_slot = vote_target.slot.0,
                source_slot = store.latest_justified.slot.0,
                "Skipping attestation: target slot must be greater than source slot"
            );
            return vec![];
        }

        let head_block_info = match store.blocks.get(&store.head) {
            Some(b) => b,
            None => {
                warn!("WARNING: Attestation skipped. (Reason: HEAD BLOCK NOT FOUND)");
                return vec![];
            }
        };

        let head_checkpoint = Checkpoint {
            root: store.head,
            slot: head_block_info.message.block.slot,
        };

        self.config
            .validator_indices
            .iter()
            .filter_map(|&idx| {
                #[cfg(feature = "devnet1")]
                let attestation = Attestation {
                    validator_id: idx,
                    data: AttestationData {
                        slot,
                        head: head_checkpoint.clone(),
                        target: vote_target.clone(),
                        source: store.latest_justified.clone(),
                    },
                };

                #[cfg(feature = "devnet2")]
                let attestation = AttestationData {
                    slot,
                    head: head_checkpoint.clone(),
                    target: vote_target.clone(),
                    source: store.latest_justified.clone(),
                };

                let signature = if let Some(ref key_manager) = self.key_manager {
                    let message = attestation.hash_tree_root();
                    let epoch = slot.0 as u32;

                    match key_manager.sign(idx, epoch, &message.into()) {
                        Ok(sig) => {
                            info!(
                                slot = slot.0,
                                validator = idx,
                                "Created signed attestation"
                            );
                            sig
                        }
                        Err(e) => {
                            warn!(validator = idx, error = %e, "Failed to sign attestation, skipping");
                            return None;
                        }
                    }
                } else {
                    Signature::default()
                };

                #[cfg(feature = "devnet1")]
                {
                    Some(SignedAttestation {
                        message: attestation,
                        signature,
                    })
                }

                #[cfg(feature = "devnet2")]
                {
                    Some(SignedAttestation {
                        validator_id: idx,
                        message: attestation,
                        signature,
                    })
                }
            })
            .collect()
    }
}

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

        assert!(service.get_proposer_for_slot(Slot(2)).is_some());
        assert!(service.get_proposer_for_slot(Slot(6)).is_some());
        assert!(service.get_proposer_for_slot(Slot(10)).is_some());

        assert!(service.get_proposer_for_slot(Slot(0)).is_none());
    }

    #[test]
    fn test_is_assigned() {
        let config = ValidatorConfig {
            node_id: "test_0".to_string(),
            validator_indices: vec![2, 5, 8],
        };

        assert!(config.is_assigned(2));
        assert!(!config.is_assigned(0));
    }
}