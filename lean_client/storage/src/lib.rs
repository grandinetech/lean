use std::path::Path;

use anyhow::Result;
use bytesize::ByteSize;
use database::{Database, DatabaseMode};

use containers::{Block, State, Checkpoint, Slot};
use ssz::H256;

pub struct Storage {
    blocks: Blocks,
    states: States,
    checkpoints: Checkpoints,
    slot_index: SlotIndex,
    state_root_index: StateRootIndex,
}

impl Storage {
    pub fn new() -> Result<Self> {
        Ok(Self {
            blocks: Blocks::new()?,
            states: States::new()?,
            checkpoints: Checkpoints::new()?,
            slot_index: SlotIndex::new()?,
            state_root_index: StateRootIndex::new()?,
        })
    }

    pub fn get_block(self, root: H256) -> Result<Option<Block>> {
        let blocks_db = self.blocks;

        Ok(None)
    }

    pub fn put_block(self, block: Block, root: H256) {
        let blocks_db = self.blocks;
    }

    pub fn get_state(self, root: H256) -> Result<Option<State>> {
        let states_db = self.states;

        Ok(None)
    }

    pub fn put_state(self, state: State, root: H256) {
        let states_db = self.states;
    }

    pub fn get_justified_checkpoint(self) -> Result<Option<Checkpoint>> {
        let checkpoints_db = self.checkpoints;

        Ok(None)
    }

    pub fn put_justified_checkpoint(self, checkpoint: Checkpoint) {
        let checkpoints_db = self.checkpoints;
    }

    pub fn get_finalized_checkpoint(self) -> Result<Option<Checkpoint>> {
        let checkpoints_db = self.checkpoints;

        Ok(None)
    }

    pub fn put_finalized_checkpoint(self, checkpoint: Checkpoint) {
        let checkpoints_db = self.checkpoints;
    }

    pub fn get_head_root(self) -> Result<Option<H256>> {
        let checkpoints_db = self.checkpoints;

        Ok(None)
    }

    pub fn put_head_root(self, root: H256) {
        let checkpoints_db = self.checkpoints;
    }

    pub fn get_block_root_by_slot(self, slot: Slot) -> Result<Option<H256>> {
        let slot_index_db = self.slot_index;

        Ok(None)
    }

    pub fn put_block_root_by_slot(self, slot: Slot, root: H256) {
        let slot_index_db = self.slot_index;
    }

    pub fn get_block_root_by_state_root(self, state_root: H256) -> Result<Option<H256>> {
        let state_root_index_db = self.state_root_index;

        Ok(None)
    }

    pub fn put_block_root_by_state_root(self, state_root: H256, block_root: H256) {
        let state_root_index_db = self.state_root_index;
    }

    pub fn get_genesis_time(self) -> Result<Option<u64>> {
        let checkpoints_db = self.checkpoints;

        Ok(None)
    }

    pub fn put_genesis_time(self, genesis_time: u64) {
        let checkpoints_db = self.checkpoints;
    }
}

struct Blocks(Database);
struct States(Database);
struct Checkpoints(Database);
struct SlotIndex(Database);
struct StateRootIndex(Database);

impl Blocks {
    fn new() -> Result<Self> {
        let db = Database::persistent(
            "blocks",
            Path::new("./database/blocks"),
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

impl States {
    fn new() -> Result<Self> {
        let db = Database::persistent(
            "states",
            Path::new("./database/states"),
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

impl Checkpoints {
    fn new() -> Result<Self> {
        let db = Database::persistent(
            "checkpoints",
            Path::new("./database/checkpoints"),
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

impl SlotIndex {
    fn new() -> Result<Self> {
        let db = Database::persistent(
            "slot_index",
            Path::new("./database/slot_index"),
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

impl StateRootIndex {
    fn new() -> Result<Self> {
        let db = Database::persistent(
            "state_root_index",
            Path::new("./database/state_root_index"),
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}
