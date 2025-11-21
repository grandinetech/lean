use crate::validator::Validator;
use crate::{
    block::{hash_tree_root, Block, BlockBody, BlockHeader, SignedBlock},
    Attestation, Attestations, Bytes32, Checkpoint, Config, Slot, Uint64, ValidatorIndex,
};
use crate::{HistoricalBlockHashes, JustificationRoots, JustificationsValidators, JustifiedSlots};
use serde::{Deserialize, Serialize};
use ssz::PersistentList as List;
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
    pub validators: List<Validator, U4096>,

    #[serde(with = "crate::serde_helpers")]
    pub justifications_roots: JustificationRoots,
    #[serde(with = "crate::serde_helpers::bitlist")]
    pub justifications_validators: JustificationsValidators,
}

impl State {
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
        for _ in 0..num_validators.0 {
            let validator = Validator {
                pubkey: crate::validator::BlsPublicKey::default(),
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
        // Count validators by iterating (since PersistentList doesn't have len())
        let mut num_validators: u64 = 0;
        let mut i: u64 = 0;
        loop {
            match self.validators.get(i) {
                Ok(_) => {
                    num_validators += 1;
                    i += 1;
                }
                Err(_) => break,
            }
        }

        if num_validators == 0 {
            return false; // No validators
        }
        (self.slot.0 % num_validators) == (index.0 % num_validators)
    }

    pub fn get_justifications(&self) -> BTreeMap<Bytes32, Vec<bool>> {
        // Chunk validator votes per root using the fixed registry limit
        let limit = VALIDATOR_REGISTRY_LIMIT;
        (&self.justifications_roots)
            .into_iter()
            .enumerate()
            .map(|(i, root)| {
                let start = i * limit;
                let end = start + limit;
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

    pub fn with_justifications(mut self, mut map: BTreeMap<Bytes32, Vec<bool>>) -> Self {
        // Expect each root to have exactly `VALIDATOR_REGISTRY_LIMIT` votes
        let limit = VALIDATOR_REGISTRY_LIMIT;
        let mut roots: Vec<_> = map.keys().cloned().collect();
        roots.sort();

        // Build PersistentList by pushing elements
        let mut new_roots = JustificationRoots::default();
        for r in &roots {
            new_roots.push(*r).expect("within limit");
        }

        // Build BitList: create with length, then set bits
        let total_bits = roots.len() * limit;
        let mut new_validators = JustificationsValidators::new(false, total_bits);

        for (i, r) in roots.iter().enumerate() {
            let v = map.remove(r).expect("root present");
            assert_eq!(v.len(), limit, "vote vector must match validator limit");
            let base = i * limit;
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
    pub fn state_transition(&self, signed_block: SignedBlock, valid_signatures: bool) -> Self {
        self.state_transition_with_validation(signed_block, valid_signatures, true)
    }

    // updated for fork choice tests
    pub fn state_transition_with_validation(
        &self,
        signed_block: SignedBlock,
        valid_signatures: bool,
        validate_state_root: bool,
    ) -> Self {
        assert!(valid_signatures, "Block signatures must be valid");

        let block = signed_block.message;
        let mut state = self.process_slots(block.slot);
        state = state.process_block(&block);

        if validate_state_root {
            let state_for_hash = state.clone();
            let state_root = hash_tree_root(&state_for_hash);
            assert!(block.state_root == state_root, "Invalid block state root");
        }

        state
    }

    pub fn process_slots(&self, target_slot: Slot) -> Self {
        assert!(self.slot < target_slot, "Target slot must be in the future");

        let mut state = self.clone();

        while state.slot < target_slot {
            state = state.process_slot();
            state.slot = Slot(state.slot.0 + 1);
        }

        state
    }

    pub fn process_slot(&self) -> Self {
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

    pub fn process_block(&self, block: &Block) -> Self {
        let state = self.process_block_header(block);
        let state_after_ops = state.process_attestations(&block.body.attestations);

        // State root validation is handled by state_transition_with_validation when needed

        state_after_ops
    }

    pub fn process_block_header(&self, block: &Block) -> Self {
        if !(block.slot == self.slot) {
            std::panic::panic_any(String::from("Block slot mismatch"));
        }
        if !(block.slot > self.latest_block_header.slot) {
            std::panic::panic_any(String::from("Block is older than latest header"));
        }
        if !self.is_proposer(block.proposer_index) {
            std::panic::panic_any(String::from("Incorrect block proposer"));
        }

        // Create a mutable clone for hash computation
        let latest_header_for_hash  = self.latest_block_header.clone();
        let parent_root = hash_tree_root(&latest_header_for_hash);
        if block.parent_root != parent_root {
            std::panic::panic_any(String::from("Block parent root mismatch"));
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

        Self {
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
        }
    }

    pub fn process_attestations(&self, attestations: &Attestations) -> Self {
        let mut justifications = self.get_justifications();
        let mut latest_justified = self.latest_justified.clone();
        let mut latest_finalized = self.latest_finalized.clone();
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

            let latest_header_for_hash = self.latest_block_header.clone();
            let target_matches_latest_header = target_slot == self.latest_block_header.slot
                && target_root == hash_tree_root(&latest_header_for_hash);

            let target_root_is_valid = target_root_matches_history || target_matches_latest_header;
            let target_is_after_source = target_slot > source_slot;
            let target_is_justifiable = target_slot.is_justifiable_after(latest_finalized.slot);

            let is_valid_vote = source_is_justified
                && !target_already_justified
                && source_root_matches_history
                && target_root_is_valid
                && target_is_after_source
                && target_is_justifiable;

            if !is_valid_vote {
                continue;
            }

            if !justifications.contains_key(&target_root) {
                let limit = VALIDATOR_REGISTRY_LIMIT;
                justifications.insert(target_root, vec![false; limit]);
            }

            let validator_id = attestation.validator_id.0 as usize;
            if let Some(votes) = justifications.get_mut(&target_root) {
                if validator_id < votes.len() && !votes[validator_id] {
                    votes[validator_id] = true;

                    // Count validators
                    let mut num_validators: u64 = 0;
                    let mut i: u64 = 0;
                    loop {
                        match self.validators.get(i) {
                            Ok(_) => {
                                num_validators += 1;
                                i += 1;
                            }
                            Err(_) => break,
                        }
                    }

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
                            if Slot(s as u64).is_justifiable_after(latest_finalized.slot) {
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

        let new_state = genesis_state.process_slots(target_slot);

        assert_eq!(new_state.slot, target_slot);
        let genesis_state_for_hash = genesis_state.clone(); //this is sooooo bad
        assert_eq!(
            new_state.latest_block_header.state_root,
            hash_tree_root(&genesis_state_for_hash)
        );
    }
}
