use crate::attestation::{AggregatedAttestation, AggregatedAttestations};
use crate::validator::Validator;
use crate::{
    block::{hash_tree_root, Block, BlockBody, BlockHeader, SignedBlockWithAttestation},
    Attestation, Bytes32, Checkpoint, Config, Signature, Slot, Uint64, ValidatorIndex,
};
use crate::{
    HistoricalBlockHashes, JustificationRoots, JustificationsValidators, JustifiedSlots, Validators,
};
use serde::{Deserialize, Serialize};
use ssz::PersistentList as List;
use ssz_derive::Ssz;
use std::collections::BTreeMap;

pub const VALIDATOR_REGISTRY_LIMIT: usize = 1 << 12; // 4096
pub const JUSTIFICATION_ROOTS_LIMIT: usize = 1 << 18; // 262144
pub const JUSTIFICATIONS_VALIDATORS_MAX: usize =
    VALIDATOR_REGISTRY_LIMIT * JUSTIFICATION_ROOTS_LIMIT;

#[derive(Clone, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    // --- configuration (spec-local) ---
    pub config: Config,

    // --- slot / header tracking ---
    pub slot: Slot,
    pub latest_block_header: BlockHeader,

    // --- fork-choice checkpoints ---
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,

    // --- historical data ---
    #[serde(with = "crate::serde_helpers")]
    pub historical_block_hashes: HistoricalBlockHashes,

    // --- flattened justification tracking ---
    #[serde(with = "crate::serde_helpers::bitlist")]
    pub justified_slots: JustifiedSlots,

    // Validators registry
    #[serde(with = "crate::serde_helpers")]
    pub validators: Validators,

    #[serde(with = "crate::serde_helpers")]
    pub justifications_roots: JustificationRoots,
    #[serde(with = "crate::serde_helpers::bitlist")]
    pub justifications_validators: JustificationsValidators,
}

impl State {
    pub fn generate_genesis_with_validators(
        genesis_time: Uint64,
        validators: Vec<Validator>,
    ) -> Self {
        let body_for_root = BlockBody {
            attestations: Default::default(),
        };
        let genesis_header = BlockHeader {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Bytes32(ssz::H256::zero()),
            state_root: Bytes32(ssz::H256::zero()),
            body_root: hash_tree_root(&body_for_root),
        };

        let mut validator_list = List::default();
        for v in validators {
            validator_list.push(v).expect("Failed to add validator");
        }

        Self {
            config: Config {
                genesis_time: genesis_time.0,
            },
            slot: Slot(0),
            latest_block_header: genesis_header,
            latest_justified: Checkpoint {
                root: Bytes32(ssz::H256::zero()),
                slot: Slot(0),
            },
            latest_finalized: Checkpoint {
                root: Bytes32(ssz::H256::zero()),
                slot: Slot(0),
            },
            historical_block_hashes: HistoricalBlockHashes::default(),
            justified_slots: JustifiedSlots::default(),
            validators: validator_list,
            justifications_roots: JustificationRoots::default(),
            justifications_validators: JustificationsValidators::default(),
        }
    }

    pub fn generate_genesis(genesis_time: Uint64, num_validators: Uint64) -> Self {
        let body_for_root = BlockBody {
            attestations: Default::default(),
        };
        let header = BlockHeader {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Bytes32(ssz::H256::zero()),
            state_root: Bytes32(ssz::H256::zero()),
            body_root: hash_tree_root(&body_for_root),
        };

        //TEMP: Create validators list with dummy validators
        let mut validators = List::default();
        for i in 0..num_validators.0 {
            let validator = Validator {
                pubkey: crate::public_key::PublicKey::default(),
                index: Uint64(i),
            };
            validators.push(validator).expect("Failed to add validator");
        }

        Self {
            config: Config {
                genesis_time: genesis_time.0,
            },
            slot: Slot(0),
            latest_block_header: header,
            latest_justified: Checkpoint {
                root: Bytes32(ssz::H256::zero()),
                slot: Slot(0),
            },
            latest_finalized: Checkpoint {
                root: Bytes32(ssz::H256::zero()),
                slot: Slot(0),
            },
            historical_block_hashes: HistoricalBlockHashes::default(),
            justified_slots: JustifiedSlots::default(),
            validators,
            justifications_roots: JustificationRoots::default(),
            justifications_validators: JustificationsValidators::default(),
        }
    }

    /// Simple RR proposer rule (round-robin).
    pub fn is_proposer(&self, index: ValidatorIndex) -> bool {
        let num_validators = self.validators.len_u64();

        if num_validators == 0 {
            return false; // No validators
        }
        (self.slot.0 % num_validators) == (index.0 % num_validators)
    }

    /// Get the number of validators (since PersistentList doesn't have len())
    pub fn validator_count(&self) -> usize {
        let mut count: u64 = 0;
        loop {
            match self.validators.get(count) {
                Ok(_) => count += 1,
                Err(_) => break,
            }
        }
        count as usize
    }

    pub fn get_justifications(&self) -> BTreeMap<Bytes32, Vec<bool>> {
        // Use actual validator count, matching leanSpec
        let num_validators = self.validator_count();
        (&self.justifications_roots)
            .into_iter()
            .enumerate()
            .map(|(i, root)| {
                let start = i * num_validators;
                let end = start + num_validators;
                // Extract bits from BitList for this root's validator votes
                let votes: Vec<bool> = (start..end)
                    .map(|idx| {
                        self.justifications_validators
                            .get(idx)
                            .map(|b| *b)
                            .unwrap_or(false)
                    })
                    .collect();
                (*root, votes)
            })
            .collect()
    }

    pub fn with_justifications(mut self, map: BTreeMap<Bytes32, Vec<bool>>) -> Self {
        // Use actual validator count, matching leanSpec
        let num_validators = self.validator_count();
        let mut roots: Vec<_> = map.keys().cloned().collect();
        roots.sort();

        // Build PersistentList by pushing elements
        let mut new_roots = JustificationRoots::default();
        for r in &roots {
            new_roots.push(*r).expect("within limit");
        }

        // Build BitList: create with length, then set bits
        // Each root has num_validators votes (matching leanSpec)
        let total_bits = roots.len() * num_validators;
        let mut new_validators = JustificationsValidators::new(false, total_bits);

        for (i, r) in roots.iter().enumerate() {
            let v = map.get(r).expect("root present");
            assert_eq!(
                v.len(),
                num_validators,
                "vote vector must match validator count"
            );
            let base = i * num_validators;
            for (j, &bit) in v.iter().enumerate() {
                if bit {
                    new_validators.set(base + j, true);
                }
            }
        }

        self.justifications_roots = new_roots;
        self.justifications_validators = new_validators;
        self
    }

    pub fn with_historical_hashes(mut self, hashes: Vec<Bytes32>) -> Self {
        let mut new_hashes = HistoricalBlockHashes::default();
        for h in hashes {
            new_hashes.push(h).expect("within limit");
        }
        self.historical_block_hashes = new_hashes;
        self
    }

    // updated for fork choice tests
    pub fn state_transition(
        &self,
        signed_block: SignedBlockWithAttestation,
        valid_signatures: bool,
    ) -> Result<Self, String> {
        self.state_transition_with_validation(signed_block, valid_signatures, true)
    }

    // updated for fork choice tests
    pub fn state_transition_with_validation(
        &self,
        signed_block: SignedBlockWithAttestation,
        valid_signatures: bool,
        validate_state_root: bool,
    ) -> Result<Self, String> {
        if !valid_signatures {
            return Err("Block signatures must be valid".to_string());
        }

        let block = &signed_block.message.block;
        let mut state = self.process_slots(block.slot)?;
        state = state.process_block(block)?;

        if validate_state_root {
            let state_for_hash = state.clone();
            let state_root = hash_tree_root(&state_for_hash);
            if block.state_root != state_root {
                return Err("Invalid block state root".to_string());
            }
        }

        Ok(state)
    }

    pub fn process_slots(&self, target_slot: Slot) -> Result<Self, String> {
        if self.slot >= target_slot {
            return Err("Target slot must be in the future".to_string());
        }

        let mut state = self.clone();

        while state.slot < target_slot {
            state = state.process_slot();
            state.slot = Slot(state.slot.0 + 1);
        }

        Ok(state)
    }

    pub fn process_slot(&self) -> Self {
        // Cache the state root in the header if not already set (matches leanSpec)
        // Per spec: leanSpec/src/lean_spec/subspecs/containers/state/state.py lines 173-176
        if self.latest_block_header.state_root == Bytes32(ssz::H256::zero()) {
            let state_for_hash = self.clone();
            let previous_state_root = hash_tree_root(&state_for_hash);

            let mut new_header = self.latest_block_header.clone();
            new_header.state_root = previous_state_root;

            let mut new_state = self.clone();
            new_state.latest_block_header = new_header;
            return new_state;
        }

        self.clone()
    }

    pub fn process_block(&self, block: &Block) -> Result<Self, String> {
        let state = self.process_block_header(block)?;

        if AggregatedAttestation::has_duplicate_data(&block.body.attestations) {
            return Err("Block contains duplicate AttestationData".to_string());
        }

        Ok(state.process_attestations(&block.body.attestations))
    }

    pub fn process_block_header(&self, block: &Block) -> Result<Self, String> {
        if !(block.slot == self.slot) {
            return Err(String::from("Block slot mismatch"));
        }
        if !(block.slot > self.latest_block_header.slot) {
            return Err(String::from("Block is older than latest header"));
        }
        if !self.is_proposer(block.proposer_index) {
            return Err(String::from("Incorrect block proposer"));
        }

        // Create a mutable clone for hash computation
        let latest_header_for_hash = self.latest_block_header.clone();
        let parent_root = hash_tree_root(&latest_header_for_hash);
        if block.parent_root != parent_root {
            tracing::error!(
                expected_parent_root = %format!("0x{:x}", parent_root.0),
                block_parent_root = %format!("0x{:x}", block.parent_root.0),
                header_slot = self.latest_block_header.slot.0,
                header_proposer = self.latest_block_header.proposer_index.0,
                header_parent = %format!("0x{:x}", self.latest_block_header.parent_root.0),
                header_state_root = %format!("0x{:x}", self.latest_block_header.state_root.0),
                header_body_root = %format!("0x{:x}", self.latest_block_header.body_root.0),
                "Block parent root mismatch - debug info"
            );
            return Err(String::from("Block parent root mismatch"));
        }

        // Build new PersistentList for historical hashes
        let mut new_historical_hashes = HistoricalBlockHashes::default();
        for hash in &self.historical_block_hashes {
            new_historical_hashes.push(*hash).expect("within limit");
        }
        new_historical_hashes
            .push(parent_root)
            .expect("within limit");

        // Calculate number of empty slots (skipped slots between parent and this block)
        let num_empty_slots = (block.slot.0 - self.latest_block_header.slot.0 - 1) as usize;

        // Add ZERO_HASH entries for empty slots to historical hashes
        for _ in 0..num_empty_slots {
            new_historical_hashes
                .push(Bytes32(ssz::H256::zero()))
                .expect("within limit");
        }

        // Extend justified_slots to cover slots from finalized_slot+1 to last_materialized_slot
        // per leanSpec: justified_slots is stored RELATIVE to the finalized boundary
        // The first entry corresponds to slot (finalized_slot + 1)
        let last_materialized_slot = block.slot.0.saturating_sub(1);
        let finalized_slot = self.latest_finalized.slot.0;

        let new_justified_slots = if last_materialized_slot > finalized_slot {
            // Calculate relative index: slot X maps to index (X - finalized_slot - 1)
            let relative_index = (last_materialized_slot - finalized_slot - 1) as usize;
            let required_capacity = relative_index + 1;
            let current_len = self.justified_slots.len();

            if required_capacity > current_len {
                // Extend the bitlist
                let mut new_slots = JustifiedSlots::new(false, required_capacity);
                // Copy existing bits
                for i in 0..current_len {
                    if let Some(bit) = self.justified_slots.get(i) {
                        if *bit {
                            new_slots.set(i, true);
                        }
                    }
                }
                // New slots are initialized to false (unjustified)
                new_slots
            } else {
                self.justified_slots.clone()
            }
        } else {
            // last_materialized_slot <= finalized_slot: no extension needed
            self.justified_slots.clone()
        };

        let body_for_hash = block.body.clone();
        let body_root = hash_tree_root(&body_for_hash);

        let new_latest_block_header = BlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            body_root,
            state_root: Bytes32(ssz::H256::zero()),
        };

        let mut new_latest_justified = self.latest_justified.clone();
        let mut new_latest_finalized = self.latest_finalized.clone();

        if self.latest_block_header.slot == Slot(0) {
            new_latest_justified.root = parent_root;
            new_latest_finalized.root = parent_root;
        }

        Ok(Self {
            config: self.config.clone(),
            slot: self.slot,
            latest_block_header: new_latest_block_header,
            latest_justified: new_latest_justified,
            latest_finalized: new_latest_finalized,
            historical_block_hashes: new_historical_hashes,
            justified_slots: new_justified_slots,
            validators: self.validators.clone(),
            justifications_roots: self.justifications_roots.clone(),
            justifications_validators: self.justifications_validators.clone(),
        })
    }

    pub fn process_attestations(&self, attestations: &AggregatedAttestations) -> Self {
        let mut justifications = self.get_justifications();
        let mut latest_justified = self.latest_justified.clone();
        let mut latest_finalized = self.latest_finalized.clone();
        let initial_finalized_slot = self.latest_finalized.slot;
        let justified_slots = self.justified_slots.clone();

        tracing::info!(
            current_justified_slot = latest_justified.slot.0,
            current_finalized_slot = latest_finalized.slot.0,
            "Processing attestations in block"
        );

        let mut justified_slots_working = Vec::new();
        for i in 0..justified_slots.len() {
            justified_slots_working.push(justified_slots.get(i).map(|b| *b).unwrap_or(false));
        }

        for aggregated_attestation in attestations {
            let validator_ids = aggregated_attestation
                .aggregation_bits
                .to_validator_indices();
            self.process_single_attestation(
                &aggregated_attestation.data,
                &validator_ids,
                &mut justifications,
                &mut latest_justified,
                &mut latest_finalized,
                &mut justified_slots_working,
                initial_finalized_slot,
            );
        }

        self.finalize_attestation_processing(
            justifications,
            latest_justified,
            latest_finalized,
            justified_slots_working,
        )
    }

    /// Process a single attestation's votes.
    /// 
    /// NOTE: justified_slots uses RELATIVE indexing. Slot X maps to index (X - finalized_slot - 1).
    /// Slots at or before finalized_slot are implicitly justified (not stored in the bitlist).
    fn process_single_attestation(
        &self,
        vote: &crate::attestation::AttestationData,
        validator_ids: &[u64],
        justifications: &mut BTreeMap<Bytes32, Vec<bool>>,
        latest_justified: &mut Checkpoint,
        latest_finalized: &mut Checkpoint,
        justified_slots_working: &mut Vec<bool>,
        initial_finalized_slot: Slot,
    ) {
        let target_slot = vote.target.slot;
        let source_slot = vote.source.slot;
        let target_root = vote.target.root;
        let source_root = vote.source.root;

        let finalized_slot_int = initial_finalized_slot.0 as i64;

        // Helper to check if a slot is justified using RELATIVE indexing
        // Per leanSpec: slots at or before finalized_slot are implicitly justified
        let is_slot_justified = |slot: Slot, justified_slots: &[bool]| -> bool {
            if slot.0 as i64 <= finalized_slot_int {
                // Slots at or before finalized boundary are implicitly justified
                return true;
            }
            // Calculate relative index: slot X maps to index (X - finalized_slot - 1)
            let relative_index = (slot.0 as i64 - finalized_slot_int - 1) as usize;
            justified_slots.get(relative_index).copied().unwrap_or(false)
        };

        let source_is_justified = is_slot_justified(source_slot, justified_slots_working);
        let target_already_justified = is_slot_justified(target_slot, justified_slots_working);

        let source_slot_int = source_slot.0 as usize;
        let target_slot_int = target_slot.0 as usize;

        // Check root matches using absolute slot for historical_block_hashes lookup
        let source_root_matches = self
            .historical_block_hashes
            .get(source_slot_int as u64)
            .map(|r| *r == source_root)
            .unwrap_or(false);
        let target_root_matches = self
            .historical_block_hashes
            .get(target_slot_int as u64)
            .map(|r| *r == target_root)
            .unwrap_or(false);

        // Ignore votes that reference zero-hash slots (per leanSpec)
        if source_root.0.is_zero() || target_root.0.is_zero() {
            return;
        }

        let is_valid_vote = source_is_justified
            && !target_already_justified
            && source_root_matches
            && target_root_matches
            && target_slot > source_slot
            && target_slot.is_justifiable_after(initial_finalized_slot);

        // Debug logging for vote validation
        tracing::debug!(
            source_slot = source_slot.0,
            target_slot = target_slot.0,
            source_root = %format!("0x{:x}", source_root.0),
            target_root = %format!("0x{:x}", target_root.0),
            validator_count = validator_ids.len(),
            source_is_justified,
            target_already_justified,
            source_root_matches,
            target_root_matches,
            is_valid_vote,
            "Processing attestation vote"
        );

        if !is_valid_vote {
            tracing::warn!(
                source_slot = source_slot.0,
                target_slot = target_slot.0,
                source_is_justified,
                target_already_justified,
                source_root_matches,
                target_root_matches,
                "Vote rejected"
            );
            return;
        }

        if !justifications.contains_key(&target_root) {
            justifications.insert(target_root, vec![false; self.validator_count()]);
        }

        for &validator_id in validator_ids {
            let vid = validator_id as usize;
            if let Some(votes) = justifications.get_mut(&target_root) {
                if vid < votes.len() && !votes[vid] {
                    votes[vid] = true;
                }
            }
        }

        if let Some(votes) = justifications.get(&target_root) {
            let num_validators = self.validators.len_u64() as usize;
            let count = votes.iter().filter(|&&v| v).count();
            let threshold = (2 * num_validators).div_ceil(3);

            tracing::info!(
                target_slot = target_slot.0,
                target_root = %format!("0x{:x}", target_root.0),
                vote_count = count,
                num_validators,
                threshold,
                needs = format!("3*{} >= 2*{} = {} >= {}", count, num_validators, 3*count, 2*num_validators),
                will_justify = 3 * count >= 2 * num_validators,
                "Vote count for target"
            );

            if 3 * count >= 2 * num_validators {
                tracing::info!(
                    target_slot = target_slot.0,
                    target_root = %format!("0x{:x}", target_root.0),
                    "Justification threshold reached"
                );
                *latest_justified = vote.target.clone();

                // Use RELATIVE indexing for justified_slots_working
                // Calculate relative index for target slot
                let target_relative_index = (target_slot.0 as i64 - finalized_slot_int - 1) as usize;
                
                // Extend the working vec if needed
                if target_relative_index >= justified_slots_working.len() {
                    justified_slots_working.resize(target_relative_index + 1, false);
                }
                justified_slots_working[target_relative_index] = true;

                justifications.remove(&target_root);

                let is_finalizable = (source_slot_int + 1..target_slot_int)
                    .all(|s| !Slot(s as u64).is_justifiable_after(initial_finalized_slot));

                if is_finalizable {
                    tracing::info!(source_slot = source_slot.0, "FINALIZATION!");
                    *latest_finalized = vote.source.clone();
                }
            }
        }
    }

    fn finalize_attestation_processing(
        &self,
        justifications: BTreeMap<Bytes32, Vec<bool>>,
        latest_justified: Checkpoint,
        latest_finalized: Checkpoint,
        justified_slots_working: Vec<bool>,
    ) -> Self {
        let mut new_state = self.clone().with_justifications(justifications);
        new_state.latest_justified = latest_justified;
        new_state.latest_finalized = latest_finalized;

        let mut new_justified_slots = JustifiedSlots::with_length(justified_slots_working.len());
        for (i, &val) in justified_slots_working.iter().enumerate() {
            new_justified_slots.set(i, val);
        }
        new_state.justified_slots = new_justified_slots;
        new_state
    }

    /// Build a valid block on top of this state.
    ///
    /// Computes the post-state and creates a block with the correct state root.
    /// If `available_attestations` and `known_block_roots` are provided,
    /// performs fixed-point attestation collection: iteratively adds valid
    /// attestations until no more can be included. This is necessary because
    /// processing attestations may update the justified checkpoint, which may
    /// make additional attestations valid.
    ///
    /// # Arguments
    ///
    /// * `slot` - Target slot for the block
    /// * `proposer_index` - Validator index of the proposer
    /// * `parent_root` - Root of the parent block (must match state after slot processing)
    /// * `initial_attestations` - Initial attestations to include
    /// * `available_attestations` - Optional pool of attestations to collect from
    /// * `known_block_roots` - Optional set of known block roots for attestation validation
    /// * `gossip_signatures` - Optional map of individual signatures from gossip
    /// * `aggregated_payloads` - Optional map of aggregated signature proofs
    ///
    /// # Returns
    ///
    /// Tuple of (Block, post-State, collected aggregated attestations, aggregated proofs)
    pub fn build_block(
        &self,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        initial_attestations: Option<Vec<Attestation>>,
        available_attestations: Option<Vec<Attestation>>,
        known_block_roots: Option<&std::collections::HashSet<Bytes32>>,
        gossip_signatures: Option<&std::collections::HashMap<crate::SignatureKey, Signature>>,
        aggregated_payloads: Option<
            &std::collections::HashMap<crate::SignatureKey, Vec<crate::AggregatedSignatureProof>>,
        >,
    ) -> Result<
        (
            Block,
            Self,
            Vec<crate::AggregatedAttestation>,
            Vec<crate::AggregatedSignatureProof>,
        ),
        String,
    > {
        use crate::attestation::{AggregatedAttestation, SignatureKey};

        // Initialize attestation set
        let mut attestations = initial_attestations.unwrap_or_default();

        // Advance state to target slot
        let pre_state = self.process_slots(slot)?;

        // Fixed-point attestation collection loop
        // Iteratively add valid attestations until no new ones can be added
        loop {
            // Create candidate block with current attestation set
            let aggregated = AggregatedAttestation::aggregate_by_data(&attestations);
            let mut attestations_list = AggregatedAttestations::default();
            for att in &aggregated {
                attestations_list
                    .push(att.clone())
                    .map_err(|e| format!("Failed to push attestation: {:?}", e))?;
            }

            let candidate_block = Block {
                slot,
                proposer_index,
                parent_root,
                state_root: Bytes32(ssz::H256::zero()),
                body: BlockBody {
                    attestations: attestations_list,
                },
            };

            // Apply state transition to get the post-block state
            let post_state = pre_state.process_block(&candidate_block)?;

            // If no available attestations pool, skip fixed-point iteration
            let available = match &available_attestations {
                Some(avail) => avail,
                None => {
                    // No fixed-point: compute signatures and return
                    let (aggregated_attestations, aggregated_proofs) = self
                        .compute_aggregated_signatures(
                            &attestations,
                            gossip_signatures,
                            aggregated_payloads,
                        )?;

                    let mut final_attestations_list = AggregatedAttestations::default();
                    for att in &aggregated_attestations {
                        final_attestations_list
                            .push(att.clone())
                            .map_err(|e| format!("Failed to push attestation: {:?}", e))?;
                    }

                    // IMPORTANT: Recompute post_state using the FINAL attestations.
                    // The original post_state was computed from candidate_block with ALL attestations,
                    // but final_attestations_list may have fewer attestations (only those with signatures).
                    // We must use the same attestations for state computation and the block body.
                    let final_candidate_block = Block {
                        slot,
                        proposer_index,
                        parent_root,
                        state_root: Bytes32(ssz::H256::zero()),
                        body: BlockBody {
                            attestations: final_attestations_list.clone(),
                        },
                    };
                    let final_post_state = pre_state.process_block(&final_candidate_block)?;

                    let final_block = Block {
                        slot,
                        proposer_index,
                        parent_root,
                        state_root: hash_tree_root(&final_post_state),
                        body: BlockBody {
                            attestations: final_attestations_list,
                        },
                    };

                    return Ok((
                        final_block,
                        final_post_state,
                        aggregated_attestations,
                        aggregated_proofs,
                    ));
                }
            };

            // Find new valid attestations from available pool
            let mut new_attestations: Vec<Attestation> = Vec::new();
            let current_data_roots: std::collections::HashSet<_> = attestations
                .iter()
                .map(|a| a.data.data_root_bytes())
                .collect();

            for attestation in available {
                // Skip if already included
                if current_data_roots.contains(&attestation.data.data_root_bytes()) {
                    continue;
                }

                // Validate attestation against post-state
                // Source must match post-state's justified checkpoint
                if attestation.data.source != post_state.latest_justified {
                    continue;
                }

                // Target must be after source
                if attestation.data.target.slot <= attestation.data.source.slot {
                    continue;
                }

                // Target block must be known (if known_block_roots provided)
                if let Some(known_roots) = known_block_roots {
                    if !known_roots.contains(&attestation.data.target.root) {
                        continue;
                    }
                }

                // Check if we have a signature for this attestation
                let data_root = attestation.data.data_root_bytes();
                let sig_key = SignatureKey::new(attestation.validator_id.0, data_root);
                let has_gossip_sig =
                    gossip_signatures.map_or(false, |gs| gs.contains_key(&sig_key));
                let has_block_proof =
                    aggregated_payloads.map_or(false, |ap| ap.contains_key(&sig_key));

                if has_gossip_sig || has_block_proof {
                    new_attestations.push(attestation.clone());
                }
            }

            // Fixed point reached: no new attestations found
            if new_attestations.is_empty() {
                // Compute aggregated signatures
                let (aggregated_attestations, aggregated_proofs) = self
                    .compute_aggregated_signatures(
                        &attestations,
                        gossip_signatures,
                        aggregated_payloads,
                    )?;

                let mut final_attestations_list = AggregatedAttestations::default();
                for att in &aggregated_attestations {
                    final_attestations_list
                        .push(att.clone())
                        .map_err(|e| format!("Failed to push attestation: {:?}", e))?;
                }

                // IMPORTANT: Recompute post_state using the FINAL attestations.
                // The original post_state was computed from candidate_block with ALL attestations,
                // but final_attestations_list may have fewer attestations (only those with signatures).
                // We must use the same attestations for state computation and the block body.
                let final_candidate_block = Block {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root: Bytes32(ssz::H256::zero()),
                    body: BlockBody {
                        attestations: final_attestations_list.clone(),
                    },
                };
                let final_post_state = pre_state.process_block(&final_candidate_block)?;

                let final_block = Block {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root: hash_tree_root(&final_post_state),
                    body: BlockBody {
                        attestations: final_attestations_list,
                    },
                };

                return Ok((
                    final_block,
                    final_post_state,
                    aggregated_attestations,
                    aggregated_proofs,
                ));
            }

            // Add new attestations and continue iteration
            attestations.extend(new_attestations);
        }
    }

    pub fn compute_aggregated_signatures(
        &self,
        attestations: &[Attestation],
        gossip_signatures: Option<&std::collections::HashMap<crate::SignatureKey, Signature>>,
        aggregated_payloads: Option<
            &std::collections::HashMap<crate::SignatureKey, Vec<crate::AggregatedSignatureProof>>,
        >,
    ) -> Result<
        (
            Vec<crate::AggregatedAttestation>,
            Vec<crate::AggregatedSignatureProof>,
        ),
        String,
    > {
        use crate::attestation::{AggregatedAttestation, AggregationBits, SignatureKey};
        use std::collections::HashSet;

        let mut results: Vec<(AggregatedAttestation, crate::AggregatedSignatureProof)> = Vec::new();

        // Group individual attestations by data
        for aggregated in AggregatedAttestation::aggregate_by_data(attestations) {
            let data = &aggregated.data;
            let data_root = data.data_root_bytes();
            let validator_ids = aggregated.aggregation_bits.to_validator_indices();

            // Phase 1: Gossip Collection
            // Try to collect individual signatures from gossip network
            let mut gossip_ids: Vec<u64> = Vec::new();
            let mut _gossip_sigs_collected: Vec<Signature> = Vec::new();
            let mut remaining: HashSet<u64> = HashSet::new();

            if let Some(gossip_sigs) = gossip_signatures {
                for vid in &validator_ids {
                    let key = SignatureKey::new(*vid, data_root);
                    if let Some(sig) = gossip_sigs.get(&key) {
                        gossip_ids.push(*vid);
                        _gossip_sigs_collected.push(sig.clone());
                    } else {
                        remaining.insert(*vid);
                    }
                }
            } else {
                // No gossip data: all validators need fallback
                remaining = validator_ids.iter().copied().collect();
            }

            // If we collected any gossip signatures, create an aggregated proof
            // NOTE: This matches Python leanSpec behavior (test_mode=True).
            // Python also uses test_mode=True with TODO: "Remove test_mode once leanVM
            // supports correct signature encoding."
            // Once lean-multisig is fully integrated, this will call:
            //   MultisigAggregatedSignature::aggregate(public_keys, signatures, message, epoch)
            if !gossip_ids.is_empty() {
                let participants = AggregationBits::from_validator_indices(&gossip_ids);

                // Create proof placeholder (matches Python test_mode behavior)
                // TODO: Call actual aggregation when lean-multisig supports proper encoding
                let proof_data = crate::MultisigAggregatedSignature::new(Vec::new())
                    .expect("Empty proof should always be valid");
                let proof = crate::AggregatedSignatureProof::new(participants.clone(), proof_data);

                results.push((
                    AggregatedAttestation {
                        aggregation_bits: participants,
                        data: data.clone(),
                    },
                    proof,
                ));
            }

            // Phase 2: Fallback to block proofs using greedy set-cover
            // Goal: Cover remaining validators with minimum number of proofs
            while !remaining.is_empty() {
                let payloads = match aggregated_payloads {
                    Some(p) => p,
                    None => break,
                };

                // Pick any remaining validator to find candidate proofs
                let target_id = *remaining.iter().next().unwrap();
                let key = SignatureKey::new(target_id, data_root);

                let candidates = match payloads.get(&key) {
                    Some(proofs) if !proofs.is_empty() => proofs,
                    _ => break, // No proofs found for this validator
                };

                // Greedy selection: find proof covering most remaining validators
                // For each candidate proof, compute intersection with remaining validators
                let (best_proof, covered_set) = candidates
                    .iter()
                    .map(|proof| {
                        let proof_validators: HashSet<u64> =
                            proof.get_participant_indices().into_iter().collect();
                        let intersection: HashSet<u64> =
                            remaining.intersection(&proof_validators).copied().collect();
                        (proof, intersection)
                    })
                    .max_by_key(|(_, intersection)| intersection.len())
                    .expect("candidates is non-empty");

                // Guard: If best proof has zero overlap, stop
                if covered_set.is_empty() {
                    break;
                }

                // Record proof with its actual participants (from the proof itself)
                let covered_validators: Vec<u64> = best_proof.get_participant_indices();
                let participants = AggregationBits::from_validator_indices(&covered_validators);

                results.push((
                    AggregatedAttestation {
                        aggregation_bits: participants,
                        data: data.clone(),
                    },
                    best_proof.clone(),
                ));

                // Remove covered validators from remaining
                for vid in &covered_set {
                    remaining.remove(vid);
                }
            }
        }

        // Handle empty case
        if results.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        // Unzip results into parallel lists
        let (aggregated_attestations, aggregated_proofs): (Vec<_>, Vec<_>) =
            results.into_iter().unzip();

        Ok((aggregated_attestations, aggregated_proofs))
    }
}
