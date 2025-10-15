use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use containers::{Bytes32, Block, State, Checkpoint, ValidatorIndex, Slot};
use containers::config::Config as ContainerConfig;
use containers::block::hash_tree_root;
use crate::helpers::*;

/// Wrapper for ValidatorIndex to add Hash implementation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorId(pub ValidatorIndex);

impl Hash for ValidatorId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.0.hash(state);
    }
}

impl From<ValidatorIndex> for ValidatorId {
    fn from(vi: ValidatorIndex) -> Self {
        ValidatorId(vi)
    }
}

impl From<ValidatorId> for ValidatorIndex {
    fn from(vid: ValidatorId) -> Self {
        vid.0
    }
}

/// Fork choice specific configuration
#[derive(Clone, Debug)]
pub struct ForkChoiceConfig {
    pub genesis_time: u64,
    pub num_validators: u64,
    pub seconds_per_slot: u64,
    pub intervals_per_slot: u64,
}

impl From<&ContainerConfig> for ForkChoiceConfig {
    fn from(config: &ContainerConfig) -> Self {
        ForkChoiceConfig {
            genesis_time: config.genesis_time,
            num_validators: config.num_validators,
            seconds_per_slot: chain::config::SECONDS_PER_SLOT,
            intervals_per_slot: chain::config::INTERVALS_PER_SLOT,
        }
    }
}

/// The fork choice store maintains all the state needed for the fork choice algorithm
#[derive(Debug, Clone)]
pub struct Store {
    /// Current time in intervals since genesis
    pub time: u64,
    /// Protocol configuration
    pub config: ForkChoiceConfig,
    /// Current head of the canonical chain
    pub head: Bytes32,
    /// Safe target for validators to vote on
    pub safe_target: Bytes32,
    /// Latest justified checkpoint
    pub latest_justified: Checkpoint,
    /// Latest finalized checkpoint
    pub latest_finalized: Checkpoint,
    /// All known blocks indexed by their hash
    pub blocks: HashMap<Bytes32, Block>,
    /// All known states indexed by block hash
    pub states: HashMap<Bytes32, State>,
    /// Latest known votes from validators
    pub latest_known_votes: HashMap<ValidatorId, Checkpoint>,
    /// New votes that haven't been processed yet
    pub latest_new_votes: HashMap<ValidatorId, Checkpoint>,
}

impl Store {
    /// Create a new fork choice store anchored at the given block and state
    pub fn new(anchor_state: State, anchor_block: Block, config: ContainerConfig) -> Self {
        let block_root = hash_tree_root(&anchor_block);
        let fork_choice_config = ForkChoiceConfig::from(&config);
        let time = anchor_block.slot.0 * fork_choice_config.intervals_per_slot;

        Store {
            time,
            config: fork_choice_config,
            head: block_root,
            safe_target: block_root,
            latest_justified: anchor_state.latest_justified.clone(),
            latest_finalized: anchor_state.latest_finalized.clone(),
            blocks: [(block_root, anchor_block)].into(),
            states: [(block_root, anchor_state)].into(),
            latest_known_votes: HashMap::new(),
            latest_new_votes: HashMap::new(),
        }
    }

    /// Get the proposal head for a given slot
    pub fn get_proposal_head(&mut self, slot: Slot) -> Bytes32 {
        let slot_time = self.config.genesis_time + (slot.0 * self.config.seconds_per_slot);
        crate::handlers::on_tick(self, slot_time, true);
        accept_new_votes(self);
        self.head
    }
}