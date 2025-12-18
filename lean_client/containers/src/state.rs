use crate::validator::Validator;
use crate::{
    block::{hash_tree_root, Block, BlockBody, BlockHeader, SignedBlockWithAttestation},
    Attestation, Attestations, Bytes32, Checkpoint, Config, Signature, Slot, Uint64,
    ValidatorIndex,
};
use crate::{
    HistoricalBlockHashes, JustificationRoots, JustificationsValidators, JustifiedSlots, Validators,
};
use serde::{Deserialize, Serialize};
use ssz::{PersistentList as List, PersistentList};
use ssz_derive::Ssz;
use std::collections::BTreeMap;
use typenum::U4096;

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
                pubkey: crate::validator::BlsPublicKey::default(),
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
        let num_validators: u64 = self.validators.len_u64();
        (self.slot.0 % num_validators) == (index.0 % num_validators)
    }

    pub fn get_justifications(&self) -> BTreeMap<Bytes32, Vec<bool>> {
        // Use actual validator count, matching leanSpec
        let num_validators = self.validators.len_usize();
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
        let num_validators = self.validators.len_usize();
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
        let state_after_ops = state.process_attestations(&block.body.attestations);

        // State root validation is handled by state_transition_with_validation when needed

        Ok(state_after_ops)
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

        // Calculate total number of slots to track
        let num_empty_slots = (block.slot.0 - self.latest_block_header.slot.0 - 1) as usize;
        let new_len = self.justified_slots.len() + 1 + num_empty_slots;

        // Build new BitList with extended length
        let mut new_justified_slots = JustifiedSlots::new(false, new_len);
        for i in 0..self.justified_slots.len() {
            if let Some(bit) = self.justified_slots.get(i) {
                if *bit {
                    new_justified_slots.set(i, true);
                }
            }
        }
        // Set the bit for the latest block header
        new_justified_slots.set(
            self.justified_slots.len(),
            self.latest_block_header.slot == Slot(0),
        );
        // Empty slots remain false (already initialized)

        // Add empty slots to historical hashes
        for _ in 0..num_empty_slots {
            new_historical_hashes
                .push(Bytes32(ssz::H256::zero()))
                .expect("within limit");
        }

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

    pub fn process_attestations(&self, attestations: &Attestations) -> Self {
        let mut justifications = self.get_justifications();
        let mut latest_justified = self.latest_justified.clone();
        let mut latest_finalized = self.latest_finalized.clone();
        // Store initial finalized slot for justifiability checks (per leanSpec)
        let initial_finalized_slot = self.latest_finalized.slot;
        let justified_slots = self.justified_slots.clone();

        // PersistentList doesn't expose iter; convert to Vec for simple iteration for now
        // Build a temporary Vec by probing sequentially until index error
        let mut votes_vec: Vec<Attestation> = Vec::new();
        let mut i: u64 = 0;
        loop {
            match attestations.get(i) {
                Ok(v) => votes_vec.push(v.clone()),
                Err(_) => break,
            }
            i += 1;
        }

        // Create mutable working BitList for justified_slots tracking
        let mut justified_slots_working = Vec::new();
        for i in 0..justified_slots.len() {
            justified_slots_working.push(justified_slots.get(i).map(|b| *b).unwrap_or(false));
        }

        for attestation in votes_vec.iter() {
            let vote = attestation.data.clone();
            let target_slot = vote.target.slot;
            let source_slot = vote.source.slot;
            let target_root = vote.target.root;
            let source_root = vote.source.root;

            let target_slot_int = target_slot.0 as usize;
            let source_slot_int = source_slot.0 as usize;

            let source_is_justified = justified_slots_working
                .get(source_slot_int)
                .copied()
                .unwrap_or(false);
            let target_already_justified = justified_slots_working
                .get(target_slot_int)
                .copied()
                .unwrap_or(false);

            let source_root_matches_history = self
                .historical_block_hashes
                .get(source_slot_int as u64)
                .map(|root| *root == source_root)
                .unwrap_or(false);

            let target_root_matches_history = self
                .historical_block_hashes
                .get(target_slot_int as u64)
                .map(|root| *root == target_root)
                .unwrap_or(false);

            let target_is_after_source = target_slot > source_slot;
            // Use initial_finalized_slot per leanSpec (not the mutating local copy)
            let target_is_justifiable = target_slot.is_justifiable_after(initial_finalized_slot);

            // leanSpec logic: skip if BOTH source and target roots don't match history
            // i.e., continue if EITHER matches
            let roots_valid = source_root_matches_history || target_root_matches_history;

            let is_valid_vote = source_is_justified
                && !target_already_justified
                && roots_valid
                && target_is_after_source
                && target_is_justifiable;

            if !is_valid_vote {
                continue;
            }

            if !justifications.contains_key(&target_root) {
                // Use actual validator count, not VALIDATOR_REGISTRY_LIMIT
                // This matches leanSpec: justifications[target.root] = [Boolean(False)] * self.validators.count
                let num_validators = self.validators.len_usize();
                justifications.insert(target_root, vec![false; num_validators]);
            }

            let validator_id = attestation.validator_id.0 as usize;
            if let Some(votes) = justifications.get_mut(&target_root) {
                if validator_id < votes.len() && !votes[validator_id] {
                    votes[validator_id] = true;

                    let num_validators: u64 = self.validators.len_u64();

                    let count = votes.iter().filter(|&&v| v).count();
                    if 3 * count >= 2 * num_validators as usize {
                        latest_justified = vote.target;

                        // Extend justified_slots_working if needed
                        while justified_slots_working.len() <= target_slot_int {
                            justified_slots_working.push(false);
                        }
                        justified_slots_working[target_slot_int] = true;

                        justifications.remove(&target_root);

                        let mut is_finalizable = true;
                        for s in (source_slot_int + 1)..target_slot_int {
                            // Use initial_finalized_slot per leanSpec
                            if Slot(s as u64).is_justifiable_after(initial_finalized_slot) {
                                is_finalizable = false;
                                break;
                            }
                        }

                        if is_finalizable {
                            latest_finalized = vote.source;
                        }
                    }
                }
            }
        }

        let mut new_state = self.clone().with_justifications(justifications);

        new_state.latest_justified = latest_justified;
        new_state.latest_finalized = latest_finalized;

        // Convert justified_slots_working Vec back to BitList
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
    /// If `available_signed_attestations` and `known_block_roots` are provided,
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
    /// * `available_signed_attestations` - Optional pool of attestations to collect from
    /// * `known_block_roots` - Optional set of known block roots for attestation validation
    ///
    /// # Returns
    ///
    /// Tuple of (Block, post-State, collected attestations, signatures)
    #[cfg(feature = "devnet1")]
    pub fn build_block(
        &self,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        initial_attestations: Option<Vec<Attestation>>,
        available_signed_attestations: Option<&[SignedBlockWithAttestation]>,
        known_block_roots: Option<&std::collections::HashSet<Bytes32>>,
    ) -> Result<
        (
            Block,
            Self,
            Vec<Attestation>,
            PersistentList<Signature, U4096>,
        ),
        String,
    > {
        // Initialize empty attestation set for iterative collection
        let mut attestations = initial_attestations.unwrap_or_default();
        let mut signatures = PersistentList::default();

        // Advance state to target slot
        // Note: parent_root comes from fork choice and is already validated.
        // We cannot validate it against the header hash here because process_slots()
        // caches the state root in the header, changing its hash.
        let pre_state = self.process_slots(slot)?;

        // Iteratively collect valid attestations using fixed-point algorithm
        //
        // Continue until no new attestations can be added to the block.
        // This ensures we include the maximal valid attestation set.
        loop {
            // Create candidate block with current attestation set
            let mut attestations_list = Attestations::default();
            for att in &attestations {
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

            // No attestation source provided: done after computing post_state
            if available_signed_attestations.is_none() || known_block_roots.is_none() {
                // Store the post state root in the block
                let final_block = Block {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root: hash_tree_root(&post_state),
                    body: candidate_block.body,
                };
                return Ok((final_block, post_state, attestations, signatures));
            }

            // Find new valid attestations matching post-state justification
            let mut new_attestations = Vec::new();
            let mut new_signatures = Vec::new();

            let available = available_signed_attestations.unwrap();
            let known_roots = known_block_roots.unwrap();

            for signed_attestation in available {
                let att = &signed_attestation.message.proposer_attestation;
                let data = &att.data;

                // Skip if target block is unknown
                if !known_roots.contains(&data.head.root) {
                    continue;
                }

                // Skip if attestation source does not match post-state's latest justified
                if data.source != post_state.latest_justified {
                    continue;
                }

                // Add attestation if not already included
                if !attestations.contains(att) {
                    new_attestations.push(att.clone());
                    // Add corresponding signatures from the signed block
                    // Note: In the actual implementation, you'd need to properly track
                    // which signatures correspond to which attestations
                    let mut idx = 0u64;
                    loop {
                        match signed_attestation.signature.get(idx) {
                            Ok(sig) => {
                                new_signatures.push(sig.clone());
                                idx += 1;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }

            // Fixed point reached: no new attestations found
            if new_attestations.is_empty() {
                // Store the post state root in the block
                let final_block = Block {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root: hash_tree_root(&post_state),
                    body: candidate_block.body,
                };
                return Ok((final_block, post_state, attestations, signatures));
            }

            // Add new attestations and continue iteration
            attestations.extend(new_attestations);
            for sig in new_signatures {
                signatures
                    .push(sig)
                    .map_err(|e| format!("Failed to push signature: {:?}", e))?;
            }
        }
    }

    #[cfg(feature = "devnet2")]
    pub fn build_block(
        &self,
        _slot: Slot,
        _proposer_index: ValidatorIndex,
        _parent_root: Bytes32,
        _initial_attestations: Option<Vec<Attestation>>,
        _available_signed_attestations: Option<&[SignedBlockWithAttestation]>,
        _known_block_roots: Option<&std::collections::HashSet<Bytes32>>,
    ) -> Result<(Block, Self, Vec<Attestation>, BlockSignatures), String> {
        Err("build_block is not implemented for devnet2".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proposer_round_robin() {
        let st = State::generate_genesis(Uint64(0), Uint64(4));
        assert!(State {
            config: st.config.clone(),
            ..st.clone()
        }
        .is_proposer(ValidatorIndex(0)));
    }

    #[test]
    fn slot_justifiability_rules() {
        use crate::slot::Slot;
        assert!(Slot(1).is_justifiable_after(Slot(0)));
        assert!(Slot(9).is_justifiable_after(Slot(0))); // perfect square
        assert!(Slot(6).is_justifiable_after(Slot(0))); // pronic (2*3)
    }

    #[test]
    fn test_hash_tree_root() {
        let body = BlockBody {
            attestations: List::default(),
        };
        let block = Block {
            slot: Slot(1),
            proposer_index: ValidatorIndex(0),
            parent_root: Bytes32(ssz::H256::zero()),
            state_root: Bytes32(ssz::H256::zero()),
            body,
        };

        let root = hash_tree_root(&block);
        assert_ne!(root, Bytes32(ssz::H256::zero()));
    }

    #[test]
    fn test_process_slots() {
        let genesis_state = State::generate_genesis(Uint64(0), Uint64(10));
        let target_slot = Slot(5);

        let new_state = genesis_state.process_slots(target_slot).unwrap();

        assert_eq!(new_state.slot, target_slot);
        let genesis_state_for_hash = genesis_state.clone(); //this is sooooo bad
        assert_eq!(
            new_state.latest_block_header.state_root,
            hash_tree_root(&genesis_state_for_hash)
        );
    }

    #[test]
    #[cfg(feature = "devnet1")]
    fn test_build_block() {
        // Create genesis state with validators
        let genesis_state = State::generate_genesis(Uint64(0), Uint64(4));

        // Compute expected parent root after slot processing
        let pre_state = genesis_state.process_slots(Slot(1)).unwrap();
        let expected_parent_root = hash_tree_root(&pre_state.latest_block_header);

        // Test 1: Build a simple block without attestations
        let result = genesis_state.build_block(
            Slot(1),
            ValidatorIndex(1),
            expected_parent_root,
            None,
            None,
            None,
        );

        assert!(result.is_ok(), "Building simple block should succeed");
        let (block, post_state, attestations, signatures) = result.unwrap();

        // Verify block properties
        assert_eq!(block.slot, Slot(1));
        assert_eq!(block.proposer_index, ValidatorIndex(1));
        assert_eq!(block.parent_root, expected_parent_root);
        assert_ne!(
            block.state_root,
            Bytes32(ssz::H256::zero()),
            "State root should be computed"
        );

        // Verify attestations and signatures are empty
        assert_eq!(attestations.len(), 0);
        // Check signatures by trying to get first element
        assert!(signatures.get(0).is_err(), "Signatures should be empty");

        // Verify post-state has advanced
        assert_eq!(post_state.slot, Slot(1));
        // Note: The post-state's latest_block_header.state_root is zero because it will be
        // filled in during the next slot processing
        assert_eq!(
            block.parent_root, expected_parent_root,
            "Parent root should match"
        );

        // Test 2: Build block with initial attestations
        let attestation = Attestation {
            validator_id: Uint64(0),
            data: crate::AttestationData {
                slot: Slot(1),
                head: Checkpoint {
                    root: expected_parent_root,
                    slot: Slot(0),
                },
                target: Checkpoint {
                    root: expected_parent_root,
                    slot: Slot(1),
                },
                source: Checkpoint {
                    root: expected_parent_root,
                    slot: Slot(0),
                },
            },
        };

        let result = genesis_state.build_block(
            Slot(1),
            ValidatorIndex(1),
            expected_parent_root,
            Some(vec![attestation.clone()]),
            None,
            None,
        );

        assert!(
            result.is_ok(),
            "Building block with attestations should succeed"
        );
        let (block, _post_state, attestations, _signatures) = result.unwrap();

        // Verify attestation was included
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].validator_id, Uint64(0));
        // Check that attestation list has one element
        assert!(
            block.body.attestations.get(0).is_ok(),
            "Block should contain attestation"
        );
        assert!(
            block.body.attestations.get(1).is_err(),
            "Block should have only one attestation"
        );
    }

    #[test]
    fn test_build_block_advances_state() {
        // Create genesis state
        let genesis_state = State::generate_genesis(Uint64(0), Uint64(10));

        // Compute parent root after advancing to target slot
        let pre_state = genesis_state.process_slots(Slot(5)).unwrap();
        let parent_root = hash_tree_root(&pre_state.latest_block_header);

        // Build block at slot 5
        // Proposer for slot 5 with 10 validators is (5 % 10) = 5
        let result =
            genesis_state.build_block(Slot(5), ValidatorIndex(5), parent_root, None, None, None);

        assert!(result.is_ok());
        let (block, post_state, _, _) = result.unwrap();

        // Verify state advanced through slots
        assert_eq!(post_state.slot, Slot(5));
        assert_eq!(block.slot, Slot(5));

        // Verify block can be applied to genesis state
        let transition_result = genesis_state.state_transition_with_validation(
            SignedBlockWithAttestation {
                message: crate::BlockWithAttestation {
                    block: block.clone(),
                    proposer_attestation: Attestation::default(),
                },
                signature: PersistentList::default(),
            },
            true, // signatures are considered valid (not validating, just marking as valid)
            true,
        );

        assert!(
            transition_result.is_ok(),
            "Built block should be valid for state transition"
        );
    }

    #[test]
    fn test_build_block_state_root_matches() {
        // Create genesis state
        let genesis_state = State::generate_genesis(Uint64(0), Uint64(3));

        // Compute parent root after advancing to target slot
        let pre_state = genesis_state.process_slots(Slot(1)).unwrap();
        let parent_root = hash_tree_root(&pre_state.latest_block_header);

        // Build a block
        // Proposer for slot 1 with 3 validators is (1 % 3) = 1
        let result =
            genesis_state.build_block(Slot(1), ValidatorIndex(1), parent_root, None, None, None);

        assert!(result.is_ok());
        let (block, post_state, _, _) = result.unwrap();

        // Verify the state root in block matches the computed post-state
        let computed_state_root = hash_tree_root(&post_state);
        assert_eq!(
            block.state_root, computed_state_root,
            "Block state root should match computed post-state root"
        );

        // Verify it's not zero
        assert_ne!(
            block.state_root,
            Bytes32(ssz::H256::zero()),
            "State root should not be zero"
        );
    }
}
