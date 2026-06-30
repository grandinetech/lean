use std::path::Path;

use anyhow::Result;
use bytesize::ByteSize;
use database::{Database, DatabaseMode};

use containers::{Block, Checkpoint, Slot, State};
use ssz::{H256, SszReadDefault as _, SszWrite as _};

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

    pub fn get_block(&self, root: H256) -> Result<Option<Block>> {
        match self.blocks.0.get(root)? {
            Some(block_bytes) => Ok(Some(Block::from_ssz_default(&block_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_block(&self, block: Block, root: H256) -> Result<()> {
        let block_bytes = block.to_ssz()?;
        self.blocks.0.put(root, block_bytes)?;
        Ok(())
    }

    pub fn get_state(&self, root: H256) -> Result<Option<State>> {
        match self.states.0.get(root)? {
            Some(state_bytes) => Ok(Some(State::from_ssz_default(&state_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_state(&self, state: State, root: H256) -> Result<()> {
        let state_bytes = state.to_ssz()?;
        self.states.0.put(root, state_bytes)?;
        Ok(())
    }

    pub fn get_justified_checkpoint(&self) -> Result<Option<Checkpoint>> {
        match self.checkpoints.0.get("justified")? {
            Some(checkpoint_bytes) => Ok(Some(Checkpoint::from_ssz_default(&checkpoint_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_justified_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        let checkpoint_bytes = checkpoint.to_ssz()?;
        self.checkpoints.0.put("justified", checkpoint_bytes)?;
        Ok(())
    }

    pub fn get_finalized_checkpoint(&self) -> Result<Option<Checkpoint>> {
        match self.checkpoints.0.get("finalized")? {
            Some(checkpoint_bytes) => Ok(Some(Checkpoint::from_ssz_default(&checkpoint_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_finalized_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        let checkpoint_bytes = checkpoint.to_ssz()?;
        self.checkpoints.0.put("finalized", checkpoint_bytes)?;
        Ok(())
    }

    pub fn get_head_root(&self) -> Result<Option<H256>> {
        match self.checkpoints.0.get("head")? {
            Some(head_root_bytes) => Ok(Some(H256::from_slice(&head_root_bytes))),
            None => Ok(None),
        }
    }

    pub fn put_head_root(&self, root: H256) -> Result<()> {
        self.checkpoints.0.put("head", root)?;
        Ok(())
    }

    pub fn get_block_root_by_slot(&self, slot: Slot) -> Result<Option<H256>> {
        let slot_bytes = slot.0.to_be_bytes();
        match self.slot_index.0.get(slot_bytes)? {
            Some(block_root_bytes) => Ok(Some(H256::from_slice(&block_root_bytes))),
            None => Ok(None),
        }
    }

    pub fn put_block_root_by_slot(&self, slot: Slot, root: H256) -> Result<()> {
        let slot_bytes = slot.0.to_be_bytes();
        self.slot_index.0.put(slot_bytes, root)?;
        Ok(())
    }

    pub fn get_block_root_by_state_root(&self, state_root: H256) -> Result<Option<H256>> {
        match self.state_root_index.0.get(state_root)? {
            Some(block_root_bytes) => Ok(Some(H256::from_slice(&block_root_bytes))),
            None => Ok(None),
        }
    }

    pub fn put_block_root_by_state_root(&self, state_root: H256, block_root: H256) -> Result<()> {
        self.state_root_index.0.put(state_root, block_root)?;
        Ok(())
    }

    pub fn get_genesis_time(&self) -> Result<Option<u64>> {
        match self.checkpoints.0.get("genesis_time")? {
            Some(genesis_time_bytes) => Ok(Some(u64::from_ssz_default(&genesis_time_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_genesis_time(&self, genesis_time: u64) -> Result<()> {
        let genesis_time_bytes = genesis_time.to_ssz()?;
        self.checkpoints.0.put("genesis_time", genesis_time_bytes)?;
        Ok(())
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
