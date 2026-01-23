use anyhow::{Context, Result, ensure};
use metrics::METRICS;
use serde::{Deserialize, Serialize};
use ssz::{BitList, H256, PersistentList, Ssz, SszHash};
use std::collections::{BTreeMap, HashMap, HashSet};
use try_from_iterator::TryFromIterator;
use typenum::{Prod, U262144};
use xmss::{PublicKey, Signature};

use crate::{
    AggregatedSignatureProof, Attestation, AttestationData, Checkpoint, Config, SignatureKey, Slot,
    attestation::{AggregatedAttestation, AggregatedAttestations, AggregationBits},
    block::{Block, BlockBody, BlockHeader, SignedBlockWithAttestation},
    validator::{Validator, ValidatorRegistryLimit, Validators},
};

type HistoricalRootsLimit = U262144; // 2^18

type JustificationValidatorsLimit = Prod<ValidatorRegistryLimit, HistoricalRootsLimit>;

pub type HistoricalBlockHashes = PersistentList<H256, U262144>;
pub type JustifiedSlots = BitList<HistoricalRootsLimit>;
pub type JustificationValidators = BitList<JustificationValidatorsLimit>;
pub type JustificationRoots = PersistentList<H256, HistoricalRootsLimit>;

#[derive(Clone, Debug, Ssz, Serialize, Deserialize)]
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
    pub justifications_validators: JustificationValidators,
}

impl State {
    pub fn generate_genesis_with_validators(genesis_time: u64, validators: Vec<Validator>) -> Self {
        let body_for_root = BlockBody {
            attestations: Default::default(),
        };
        let genesis_header = BlockHeader {
            slot: Slot(0),
            proposer_index: 0,
            parent_root: H256::zero(),
            state_root: H256::zero(),
            body_root: body_for_root.hash_tree_root(),
        };

        let mut validator_list = PersistentList::default();
        for v in validators {
            validator_list.push(v).expect("Failed to add validator");
        }

        Self {
            config: Config { genesis_time },
            slot: Slot(0),
            latest_block_header: genesis_header,
            latest_justified: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            latest_finalized: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            historical_block_hashes: HistoricalBlockHashes::default(),
            justified_slots: JustifiedSlots::default(),
            validators: validator_list,
            justifications_roots: JustificationRoots::default(),
            justifications_validators: JustificationValidators::default(),
        }
    }

    pub fn generate_genesis(genesis_time: u64, num_validators: u64) -> Self {
        let body_for_root = BlockBody {
            attestations: Default::default(),
        };
        let header = BlockHeader {
            slot: Slot(0),
            proposer_index: 0,
            parent_root: H256::zero(),
            state_root: H256::zero(),
            body_root: body_for_root.hash_tree_root(),
        };

        //TEMP: Create validators list with dummy validators
        let mut validators = PersistentList::default();
        for i in 0..num_validators {
            let validator = Validator {
                pubkey: PublicKey::default(),
                index: i,
            };
            validators.push(validator).expect("Failed to add validator");
        }

        Self {
            config: Config { genesis_time },
            slot: Slot(0),
            latest_block_header: header,
            latest_justified: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            latest_finalized: Checkpoint {
                root: H256::zero(),
                slot: Slot(0),
            },
            historical_block_hashes: HistoricalBlockHashes::default(),
            justified_slots: JustifiedSlots::default(),
            validators,
            justifications_roots: JustificationRoots::default(),
            justifications_validators: JustificationValidators::default(),
        }
    }

    /// Simple RR proposer rule (round-robin).
    pub fn is_proposer(&self, index: u64) -> bool {
        let num_validators = self.validators.len_u64();

        if num_validators == 0 {
            return false; // No validators
        }
        (self.slot.0 % num_validators) == (index % num_validators)
    }

    pub fn get_justifications(&self) -> BTreeMap<H256, Vec<bool>> {
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

    pub fn with_justifications(mut self, map: BTreeMap<H256, Vec<bool>>) -> Self {
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
        let mut new_validators = JustificationValidators::new(false, total_bits);

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

    pub fn with_historical_hashes(mut self, hashes: Vec<H256>) -> Self {
        let mut new_hashes = HistoricalBlockHashes::default();
        for h in hashes {
            new_hashes.push(h).expect("within limit");
        }
        self.historical_block_hashes = new_hashes;
        self
    }

    pub fn state_transition(
        &self,
        signed_block: SignedBlockWithAttestation,
        valid_signatures: bool,
    ) -> Result<Self> {
        self.state_transition_with_validation(signed_block, valid_signatures, true)
    }

    pub fn state_transition_with_validation(
        &self,
        signed_block: SignedBlockWithAttestation,
        valid_signatures: bool,
        validate_state_root: bool,
    ) -> Result<Self> {
        ensure!(valid_signatures, "invalid block signatures");

        let _timer = METRICS
            .get()
            .map(|metrics| metrics.lean_state_transition_time_seconds.start_timer());
        let block = &signed_block.message.block;
        let mut state = self.process_slots(block.slot)?;
        state = state.process_block(block)?;

        if validate_state_root {
            let state_for_hash = state.clone();
            let state_root = state_for_hash.hash_tree_root();

            ensure!(block.state_root == state_root, "invalid block state root");
        }

        Ok(state)
    }

    pub fn process_slots(&self, target_slot: Slot) -> Result<Self> {
        ensure!(self.slot < target_slot, "target slot must be in the future");

        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_state_transition_slots_processing_time_seconds
                .start_timer()
        });

        let mut state = self.clone();

        while state.slot < target_slot {
            state = state.process_slot();
            state.slot = Slot(state.slot.0 + 1);

            METRICS
                .get()
                .map(|metrics| metrics.lean_state_transition_slots_processed_total.inc());
        }

        Ok(state)
    }

    pub fn process_slot(&self) -> Self {
        // Cache the state root in the header if not already set (matches leanSpec)
        // Per spec: leanSpec/src/lean_spec/subspecs/containers/state/state.py lines 173-176
        if self.latest_block_header.state_root.is_zero() {
            let state_for_hash = self.clone();
            let previous_state_root = state_for_hash.hash_tree_root();

            let mut new_header = self.latest_block_header.clone();
            new_header.state_root = previous_state_root;

            let mut new_state = self.clone();
            new_state.latest_block_header = new_header;
            return new_state;
        }

        self.clone()
    }

    pub fn process_block(&self, block: &Block) -> Result<Self> {
        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_state_transition_block_processing_time_seconds
                .start_timer()
        });

        let state = self.process_block_header(block)?;

        ensure!(
            !AggregatedAttestation::has_duplicate_data(&block.body.attestations),
            "block contains duplicate attestation data"
        );

        Ok(state.process_attestations(&block.body.attestations))
    }

    pub fn process_block_header(&self, block: &Block) -> Result<Self> {
        ensure!(block.slot == self.slot, "block slot mismatch");
        ensure!(
            block.slot > self.latest_block_header.slot,
            "block is older than latest header"
        );
        ensure!(
            self.is_proposer(block.proposer_index),
            "incorrect block proposer"
        );

        // Create a mutable clone for hash computation
        let latest_header_for_hash = self.latest_block_header.clone();
        let parent_root = latest_header_for_hash.hash_tree_root();

        ensure!(
            block.parent_root == parent_root,
            "block parent root mismatch"
        );

        // Build new PersistentList for historical hashes
        let mut new_historical_hashes = HistoricalBlockHashes::default();
        for hash in &self.historical_block_hashes {
            new_historical_hashes.push(*hash)?;
        }
        new_historical_hashes.push(parent_root)?;

        // Calculate number of empty slots (skipped slots between parent and this block)
        let num_empty_slots = (block.slot.0 - self.latest_block_header.slot.0 - 1) as usize;

        // Add ZERO_HASH entries for empty slots to historical hashes
        for _ in 0..num_empty_slots {
            new_historical_hashes.push(H256::zero())?;
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
        let body_root = body_for_hash.hash_tree_root();

        let new_latest_block_header = BlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            body_root,
            state_root: H256::zero(),
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
        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_state_transition_attestations_processing_time_seconds
                .start_timer()
        });

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
            METRICS.get().map(|metrics| {
                metrics
                    .lean_state_transition_attestations_processed_total
                    .inc()
            });
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
        vote: &AttestationData,
        validator_ids: &[u64],
        justifications: &mut BTreeMap<H256, Vec<bool>>,
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
            justified_slots
                .get(relative_index)
                .copied()
                .unwrap_or(false)
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
        if source_root.is_zero() || target_root.is_zero() {
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
            source_root = %format!("0x{:x}", source_root),
            target_root = %format!("0x{:x}", target_root),
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
            justifications.insert(target_root, vec![false; self.validators.len_usize()]);
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
            let threshold = (2usize * num_validators).div_ceil(3);

            tracing::info!(
                target_slot = target_slot.0,
                target_root = %format!("0x{:x}", target_root),
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
                    target_root = %format!("0x{:x}", target_root),
                    "Justification threshold reached"
                );
                *latest_justified = vote.target.clone();

                // Use RELATIVE indexing for justified_slots_working
                // Calculate relative index for target slot
                let target_relative_index =
                    (target_slot.0 as i64 - finalized_slot_int - 1) as usize;

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
        justifications: BTreeMap<H256, Vec<bool>>,
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
        proposer_index: u64,
        parent_root: H256,
        initial_attestations: Option<Vec<Attestation>>,
        available_attestations: Option<Vec<Attestation>>,
        known_block_roots: Option<&HashSet<H256>>,
        gossip_signatures: Option<&HashMap<SignatureKey, Signature>>,
        aggregated_payloads: Option<&HashMap<SignatureKey, Vec<AggregatedSignatureProof>>>,
    ) -> Result<(
        Block,
        Self,
        Vec<AggregatedAttestation>,
        Vec<AggregatedSignatureProof>,
    )> {
        // Initialize attestation set
        let mut attestations = initial_attestations.unwrap_or_default();

        // Fixed-point attestation collection loop
        // Iteratively add valid attestations until no new ones can be added
        loop {
            // Create candidate block with current attestation set
            let aggregated = AggregatedAttestation::aggregate_by_data(&attestations);

            let candidate_block = Block {
                slot,
                proposer_index,
                parent_root,
                state_root: H256::zero(),
                body: BlockBody {
                    attestations: AggregatedAttestations::try_from_iter(aggregated.into_iter())?,
                },
            };

            // Apply state transition to get the post-block state
            let post_state = self.process_slots(slot)?.process_block(&candidate_block)?;

            let Some(ref available_attestations) = available_attestations else {
                // No attestation source provided: done after computing post_state
                break;
            };

            let Some(known_block_roots) = known_block_roots else {
                // No attestation source provided: done after computing post_state
                break;
            };

            //  Find new valid attestations matching post-state justification
            let mut new_attestations = Vec::new();

            for attestation in available_attestations {
                let data = &attestation.data;
                let validator_id = attestation.validator_id;
                let data_root = data.hash_tree_root();
                let sig_key = SignatureKey::new(validator_id, data_root);

                // Skip if target block is unknown
                if !known_block_roots.contains(&data.head.root) {
                    continue;
                }

                // Skip if attestation source does not match post-state's latest justified
                if data.source != post_state.latest_justified {
                    continue;
                }

                // Avoid adding duplicates of attestations already in the candidate set
                if attestations.contains(attestation) {
                    continue;
                }

                // We can only include an attestation if we have some way to later provide
                // an aggregated proof for its group:
                // - either a per validator XMSS signature from gossip, or
                // - at least one aggregated proof learned from a block that references
                //   this validator+data.
                let has_gossip_sig =
                    gossip_signatures.is_some_and(|sigs| sigs.contains_key(&sig_key));
                let has_block_proof =
                    aggregated_payloads.is_some_and(|payloads| payloads.contains_key(&sig_key));

                if has_gossip_sig || has_block_proof {
                    new_attestations.push(attestation.clone());
                }
            }

            // Fixed point reached: no new attestations found
            if new_attestations.is_empty() {
                break;
            }

            // Add new attestations and continue iteration
            attestations.extend(new_attestations);
        }

        let (aggregated_attestations, aggregated_signatures) = self.compute_aggregated_signatures(
            &attestations,
            gossip_signatures,
            aggregated_payloads,
        )?;

        METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_attestations_in_aggregated_signatures_total
                .inc_by(
                    aggregated_attestations
                        .iter()
                        .map(|v| v.aggregation_bits.to_validator_indices().len())
                        .sum::<usize>() as u64,
                );
        });

        let mut final_block = Block {
            slot,
            proposer_index,
            parent_root,
            state_root: H256::zero(),
            body: BlockBody {
                attestations: AggregatedAttestations::try_from_iter(
                    aggregated_attestations.clone(),
                )?,
            },
        };

        let post_state = self.process_slots(slot)?.process_block(&final_block)?;

        final_block.state_root = post_state.hash_tree_root();

        Ok((
            final_block,
            post_state,
            aggregated_attestations,
            aggregated_signatures,
        ))
    }

    pub fn compute_aggregated_signatures(
        &self,
        attestations: &[Attestation],
        gossip_signatures: Option<&HashMap<SignatureKey, Signature>>,
        aggregated_payloads: Option<&HashMap<SignatureKey, Vec<AggregatedSignatureProof>>>,
    ) -> Result<(Vec<AggregatedAttestation>, Vec<AggregatedSignatureProof>)> {
        let mut results: Vec<(AggregatedAttestation, AggregatedSignatureProof)> = Vec::new();

        // Group individual attestations by data
        for aggregated in AggregatedAttestation::aggregate_by_data(attestations) {
            let data = &aggregated.data;
            let data_root = data.hash_tree_root();
            let validator_ids = aggregated.aggregation_bits.to_validator_indices();

            // Phase 1: Gossip Collection
            // Try to collect individual signatures from gossip network
            let mut gossip_sigs = Vec::new();
            let mut gossip_keys = Vec::new();
            let mut gossip_ids = Vec::new();

            let mut remaining = HashSet::new();

            if let Some(gossip_signatures) = gossip_signatures {
                for vid in validator_ids {
                    let key = SignatureKey::new(vid, data_root);
                    if let Some(sig) = gossip_signatures.get(&key) {
                        gossip_sigs.push(sig.clone());
                        gossip_keys.push(
                            self.validators
                                .get(vid)
                                .map(|v| v.pubkey.clone())
                                .context(format!("invalid validator id {vid}"))?,
                        );
                        gossip_ids.push(vid);
                    } else {
                        remaining.insert(vid);
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

                let proof = AggregatedSignatureProof::aggregate(
                    participants.clone(),
                    gossip_keys,
                    gossip_sigs,
                    data_root,
                    data.slot.0 as u32,
                )?;

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
            loop {
                let Some(payloads) = aggregated_payloads else {
                    break;
                };

                // Pick any remaining validator to find candidate proofs
                let Some(target_id) = remaining.iter().next().copied() else {
                    break;
                };

                let key = SignatureKey::new(target_id, data_root);

                let Some(candidates) = payloads.get(&key) else {
                    // No proofs found for this validator
                    break;
                };

                if candidates.is_empty() {
                    // Same as before, no proofs found for this validator
                    break;
                }

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
                    .context("greedy algoritm failure: candidates were empty")?;

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
