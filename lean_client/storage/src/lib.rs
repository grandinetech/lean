mod database;

// Dev-dependency reserved for parametrized tests we haven't written yet.
#[cfg(test)]
use ::test_case as _;

use std::path::Path;

use crate::database::{Compression, Database, DatabaseMode};
use anyhow::Result;
use bytesize::ByteSize;

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
    pub fn new(base: impl AsRef<Path>) -> Result<Self> {
        let base = base.as_ref();
        Ok(Self {
            blocks: Blocks::new(base)?,
            states: States::new(base)?,
            checkpoints: Checkpoints::new(base)?,
            slot_index: SlotIndex::new(base)?,
            state_root_index: StateRootIndex::new(base)?,
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
    fn new(base: &Path) -> Result<Self> {
        let db = Database::persistent(
            "blocks",
            base.join("blocks"),
            Compression::Lz4,
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

impl States {
    fn new(base: &Path) -> Result<Self> {
        let db = Database::persistent(
            "states",
            base.join("states"),
            Compression::Zstd,
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

impl Checkpoints {
    fn new(base: &Path) -> Result<Self> {
        let db = Database::persistent(
            "checkpoints",
            base.join("checkpoints"),
            Compression::None,
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

impl SlotIndex {
    fn new(base: &Path) -> Result<Self> {
        let db = Database::persistent(
            "slot_index",
            base.join("slot_index"),
            Compression::None,
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

impl StateRootIndex {
    fn new(base: &Path) -> Result<Self> {
        let db = Database::persistent(
            "state_root_index",
            base.join("state_root_index"),
            Compression::None,
            ByteSize::gib(2),
            DatabaseMode::ReadWrite,
            None,
        )?;
        Ok(Self(db))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use containers::BlockBody;
    use ssz::SszWrite;
    use tempfile::TempDir;

    // Each test gets its own persistent `Storage` rooted in a fresh temp dir, so
    // tests are isolated, parallel-safe, and cleaned up on drop. This uses the
    // real `Storage::new`, so it exercises the real libmdbx path and the real
    // per-DB codecs — the only difference from production is the base directory.
    //
    // The returned `TempDir` MUST be kept alive for as long as the `Storage` is
    // used: dropping it deletes the on-disk database files.
    fn storage() -> (TempDir, Storage) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let storage = Storage::new(dir.path()).expect("failed to open storage");
        (dir, storage)
    }

    fn h256(byte: u8) -> H256 {
        H256::from_slice(&[byte; 32])
    }

    fn sample_block(seed: u8) -> Block {
        Block {
            slot: Slot(u64::from(seed)),
            proposer_index: u64::from(seed),
            parent_root: h256(seed),
            state_root: h256(seed.wrapping_add(1)),
            body: BlockBody::default(),
        }
    }

    // `Block` and `State` do not implement `PartialEq`, so compare their SSZ
    // encodings — the exact bytes the database stores and returns.
    fn assert_ssz_eq<T: SszWrite>(left: &T, right: &T) {
        assert_eq!(
            left.to_ssz().expect("left should serialize"),
            right.to_ssz().expect("right should serialize"),
        );
    }

    // --- blocks -----------------------------------------------------------

    #[test]
    fn get_block_returns_none_when_absent() {
        let (_dir, storage) = storage();
        assert!(storage.get_block(h256(9)).unwrap().is_none());
    }

    #[test]
    fn put_then_get_block_roundtrips() {
        let (_dir, storage) = storage();
        let root = h256(1);
        let block = sample_block(1);

        storage.put_block(block.clone(), root).unwrap();

        let read = storage
            .get_block(root)
            .unwrap()
            .expect("block should exist");
        assert_ssz_eq(&block, &read);
    }

    #[test]
    fn put_and_get_multiple_blocks() {
        let (_dir, storage) = storage();
        let blocks: Vec<(H256, Block)> = (0..8).map(|i| (h256(i), sample_block(i))).collect();

        for (root, block) in &blocks {
            storage.put_block(block.clone(), *root).unwrap();
        }

        for (root, block) in &blocks {
            let read = storage
                .get_block(*root)
                .unwrap()
                .expect("block should exist");
            assert_ssz_eq(block, &read);
        }
    }

    #[test]
    fn put_block_overwrites_existing_root() {
        let (_dir, storage) = storage();
        let root = h256(3);

        storage.put_block(sample_block(3), root).unwrap();
        let updated = sample_block(7);
        storage.put_block(updated.clone(), root).unwrap();

        let read = storage
            .get_block(root)
            .unwrap()
            .expect("block should exist");
        assert_ssz_eq(&updated, &read);
    }

    // --- states -----------------------------------------------------------

    #[test]
    fn get_state_returns_none_when_absent() {
        let (_dir, storage) = storage();
        assert!(storage.get_state(h256(9)).unwrap().is_none());
    }

    #[test]
    fn put_then_get_state_roundtrips() {
        let (_dir, storage) = storage();
        let root = h256(2);
        let state = State::generate_genesis(1_234, 3);

        storage.put_state(state.clone(), root).unwrap();

        let read = storage
            .get_state(root)
            .unwrap()
            .expect("state should exist");
        assert_ssz_eq(&state, &read);
    }

    #[test]
    fn put_and_get_multiple_states() {
        let (_dir, storage) = storage();
        let states: Vec<(H256, State)> = (0..4)
            .map(|i| (h256(i), State::generate_genesis(u64::from(i), u64::from(i))))
            .collect();

        for (root, state) in &states {
            storage.put_state(state.clone(), *root).unwrap();
        }

        for (root, state) in &states {
            let read = storage
                .get_state(*root)
                .unwrap()
                .expect("state should exist");
            assert_ssz_eq(state, &read);
        }
    }

    // --- checkpoints (justified / finalized / head / genesis_time) ---------

    #[test]
    fn justified_checkpoint_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_justified_checkpoint().unwrap().is_none());

        let checkpoint = Checkpoint {
            root: h256(4),
            slot: Slot(10),
        };
        storage
            .put_justified_checkpoint(checkpoint.clone())
            .unwrap();

        assert_eq!(
            storage.get_justified_checkpoint().unwrap().unwrap(),
            checkpoint
        );
    }

    #[test]
    fn finalized_checkpoint_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_finalized_checkpoint().unwrap().is_none());

        let checkpoint = Checkpoint {
            root: h256(5),
            slot: Slot(20),
        };
        storage
            .put_finalized_checkpoint(checkpoint.clone())
            .unwrap();

        assert_eq!(
            storage.get_finalized_checkpoint().unwrap().unwrap(),
            checkpoint
        );
    }

    #[test]
    fn head_root_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_head_root().unwrap().is_none());

        let root = h256(6);
        storage.put_head_root(root).unwrap();

        assert_eq!(storage.get_head_root().unwrap().unwrap(), root);
    }

    #[test]
    fn genesis_time_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_genesis_time().unwrap().is_none());

        storage.put_genesis_time(1_700_000_000).unwrap();

        assert_eq!(storage.get_genesis_time().unwrap().unwrap(), 1_700_000_000);
    }

    // All four values above share the single `checkpoints` database under
    // distinct string keys; verify they never clobber one another.
    #[test]
    fn checkpoints_database_keys_do_not_collide() {
        let (_dir, storage) = storage();
        let justified = Checkpoint {
            root: h256(1),
            slot: Slot(1),
        };
        let finalized = Checkpoint {
            root: h256(2),
            slot: Slot(2),
        };
        let head = h256(3);
        let genesis_time = 42;

        storage.put_justified_checkpoint(justified.clone()).unwrap();
        storage.put_finalized_checkpoint(finalized.clone()).unwrap();
        storage.put_head_root(head).unwrap();
        storage.put_genesis_time(genesis_time).unwrap();

        assert_eq!(
            storage.get_justified_checkpoint().unwrap().unwrap(),
            justified
        );
        assert_eq!(
            storage.get_finalized_checkpoint().unwrap().unwrap(),
            finalized
        );
        assert_eq!(storage.get_head_root().unwrap().unwrap(), head);
        assert_eq!(storage.get_genesis_time().unwrap().unwrap(), genesis_time);
    }

    // --- slot_index -------------------------------------------------------

    #[test]
    fn block_root_by_slot_returns_none_when_absent() {
        let (_dir, storage) = storage();
        assert!(storage.get_block_root_by_slot(Slot(0)).unwrap().is_none());
    }

    #[test]
    fn block_root_by_slot_roundtrips() {
        let (_dir, storage) = storage();
        let root = h256(6);
        storage.put_block_root_by_slot(Slot(42), root).unwrap();

        assert_eq!(
            storage.get_block_root_by_slot(Slot(42)).unwrap().unwrap(),
            root
        );
    }

    #[test]
    fn block_root_by_slot_handles_multiple() {
        let (_dir, storage) = storage();
        for i in 0..10 {
            storage
                .put_block_root_by_slot(Slot(u64::from(i)), h256(i))
                .unwrap();
        }

        for i in 0..10 {
            assert_eq!(
                storage
                    .get_block_root_by_slot(Slot(u64::from(i)))
                    .unwrap()
                    .unwrap(),
                h256(i),
            );
        }
    }

    // --- state_root_index -------------------------------------------------

    #[test]
    fn block_root_by_state_root_returns_none_when_absent() {
        let (_dir, storage) = storage();
        assert!(
            storage
                .get_block_root_by_state_root(h256(7))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn block_root_by_state_root_roundtrips() {
        let (_dir, storage) = storage();
        let state_root = h256(7);
        let block_root = h256(8);
        storage
            .put_block_root_by_state_root(state_root, block_root)
            .unwrap();

        assert_eq!(
            storage
                .get_block_root_by_state_root(state_root)
                .unwrap()
                .unwrap(),
            block_root,
        );
    }

    #[test]
    fn block_root_by_state_root_handles_multiple() {
        let (_dir, storage) = storage();
        let pairs: Vec<(H256, H256)> = (0..10)
            .map(|i| (h256(i), h256(i.wrapping_add(100))))
            .collect();

        for (state_root, block_root) in &pairs {
            storage
                .put_block_root_by_state_root(*state_root, *block_root)
                .unwrap();
        }

        for (state_root, block_root) in &pairs {
            assert_eq!(
                storage
                    .get_block_root_by_state_root(*state_root)
                    .unwrap()
                    .unwrap(),
                *block_root,
            );
        }
    }
}
