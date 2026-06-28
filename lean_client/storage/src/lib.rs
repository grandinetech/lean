use std::path::Path;

use anyhow::Result;
use bytesize::ByteSize;
use database::{Database, DatabaseMode};

pub struct Storage {
    pub blocks: Blocks,
    pub states: States,
    pub checkpoints: Checkpoints,
    pub slot_index: SlotIndex,
    pub state_root_index: StateRootIndex,
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
}

pub struct Blocks(Database);
pub struct States(Database);
pub struct Checkpoints(Database);
pub struct SlotIndex(Database);
pub struct StateRootIndex(Database);

impl Blocks {
    pub fn new() -> Result<Self> {
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
    pub fn new() -> Result<Self> {
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
    pub fn new() -> Result<Self> {
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
    pub fn new() -> Result<Self> {
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
    pub fn new() -> Result<Self> {
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
