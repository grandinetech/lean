use std::{
    borrow::Cow,
    path::Path,
    sync::Arc,
};

use anyhow::Result;
use bytesize::ByteSize;

use containers::{Block, Checkpoint, Slot, State};
use ssz::{H256, SszReadDefault as _, SszWrite as _};

use libmdbx::{
    DatabaseFlags, Environment, Geometry, RW, Transaction, WriteFlags,
};

pub struct Storage {
    environment: Arc<Environment>,
    blocks: Database,
    states: Database,
    checkpoints: Database,
    slot_index: Database,
    state_root_index: Database,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compression {
    None,
    #[default]
    Lz4,
    Zstd,
}

impl Compression {
    fn compress(self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::None => Ok(data.to_vec()),
            Self::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
            Self::Zstd => Ok(zstd::encode_all(data, 3)?),
        }
    }

    fn decompress(self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::None => Ok(data.to_vec()),
            Self::Lz4 => Ok(lz4_flex::decompress_size_prepended(data)?),
            Self::Zstd => Ok(zstd::decode_all(data)?),
        }
    }
}

#[derive(Clone, Copy)]
pub enum DatabaseMode {
    ReadOnly,
    ReadWrite,
}

impl DatabaseMode {
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }

    #[must_use]
    pub const fn mode_permissions(self) -> u16 {
        match self {
            Self::ReadOnly => 0,
            Self::ReadWrite => 0o600,
        }
    }

    #[must_use]
    #[cfg(target_os = "linux")]
    pub fn permissions(self) -> u32 {
        self.mode_permissions().into()
    }

    #[must_use]
    #[cfg(not(target_os = "linux"))]
    pub const fn permissions(self) -> u16 {
        self.mode_permissions()
    }
}

pub struct Database {
    environment: Arc<Environment>,
    name: String,
    compression: Compression,
}

impl Database {
    pub fn new(env: Arc<Environment>, name: &str, compression: Compression) -> Result<Database> {
        Ok(Self {
            environment: env,
            name: name.to_owned(),
            compression,
        })
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let txn = self.environment.begin_ro_txn()?;
        let db = txn.open_db(Some(&self.name))?;

        txn.get::<Cow<_>>(db.dbi(), key.as_ref())?
            .map(|compressed| self.compression.decompress(&compressed))
            .transpose()
    }

    pub fn put(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<()> {
        let txn = self.environment.begin_rw_txn()?;
        self.put_in(&txn, key, value)?;
        txn.commit()?;
        Ok(())
    }

    fn put_in(
        &self,
        txn: &Transaction<RW>,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<()> {
        let db = txn.open_db(Some(&self.name))?;
        let compressed = self.compression.compress(value.as_ref())?;
        txn.put(db.dbi(), key.as_ref(), compressed, WriteFlags::default())?;
        Ok(())
    }
}

impl Storage {
    pub fn new(base: impl AsRef<Path>) -> Result<Self> {
        let base = base.as_ref();
        fs_err::create_dir_all(base)?;

        let environment = Arc::new(
            Environment::builder()
                .set_max_dbs(5)
                .set_geometry(Geometry {
                    size: Some(..usize::try_from(ByteSize::gib(2).as_u64())?),
                    growth_step: Some(isize::try_from(ByteSize::mib(256).as_u64())?),
                    shrink_threshold: None,
                    page_size: None,
                })
                .open_with_permissions(base, DatabaseMode::ReadWrite.permissions())?,
        );

        let txn = environment.begin_rw_txn()?;
        for name in [
            "blocks",
            "states",
            "checkpoints",
            "slot_index",
            "state_root_index",
        ] {
            txn.create_db(Some(name), DatabaseFlags::default())?;
        }
        txn.commit()?;

        Ok(Self {
            blocks: Database::new(environment.clone(), "blocks", Compression::Lz4)?,
            states: Database::new(environment.clone(), "states", Compression::Zstd)?,
            checkpoints: Database::new(environment.clone(), "checkpoints", Compression::None)?,
            slot_index: Database::new(environment.clone(), "slot_index", Compression::None)?,
            state_root_index: Database::new(
                environment.clone(),
                "state_root_index",
                Compression::None,
            )?,
            environment,
        })
    }

    pub fn get_block(&self, root: H256) -> Result<Option<Block>> {
        match self.blocks.get(root)? {
            Some(block_bytes) => Ok(Some(Block::from_ssz_default(&block_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_block(&self, block: Block, root: H256) -> Result<()> {
        let block_bytes = block.to_ssz()?;
        self.blocks.put(root, block_bytes)?;
        Ok(())
    }

    pub fn get_state(&self, root: H256) -> Result<Option<State>> {
        match self.states.get(root)? {
            Some(state_bytes) => Ok(Some(State::from_ssz_default(&state_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_state(&self, state: State, root: H256) -> Result<()> {
        let state_bytes = state.to_ssz()?;
        self.states.put(root, state_bytes)?;
        Ok(())
    }

    pub fn get_justified_checkpoint(&self) -> Result<Option<Checkpoint>> {
        match self.checkpoints.get("justified")? {
            Some(checkpoint_bytes) => Ok(Some(Checkpoint::from_ssz_default(&checkpoint_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_justified_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        let checkpoint_bytes = checkpoint.to_ssz()?;
        self.checkpoints.put("justified", checkpoint_bytes)?;
        Ok(())
    }

    pub fn get_finalized_checkpoint(&self) -> Result<Option<Checkpoint>> {
        match self.checkpoints.get("finalized")? {
            Some(checkpoint_bytes) => Ok(Some(Checkpoint::from_ssz_default(&checkpoint_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_finalized_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        let checkpoint_bytes = checkpoint.to_ssz()?;
        self.checkpoints.put("finalized", checkpoint_bytes)?;
        Ok(())
    }

    pub fn get_head_root(&self) -> Result<Option<H256>> {
        match self.checkpoints.get("head")? {
            Some(head_root_bytes) => Ok(Some(H256::from_slice(&head_root_bytes))),
            None => Ok(None),
        }
    }

    pub fn put_head_root(&self, root: H256) -> Result<()> {
        self.checkpoints.put("head", root)?;
        Ok(())
    }

    pub fn get_block_root_by_slot(&self, slot: Slot) -> Result<Option<H256>> {
        let slot_bytes = slot.0.to_be_bytes();
        match self.slot_index.get(slot_bytes)? {
            Some(block_root_bytes) => Ok(Some(H256::from_slice(&block_root_bytes))),
            None => Ok(None),
        }
    }

    pub fn put_block_root_by_slot(&self, slot: Slot, root: H256) -> Result<()> {
        let slot_bytes = slot.0.to_be_bytes();
        self.slot_index.put(slot_bytes, root)?;
        Ok(())
    }

    pub fn get_block_root_by_state_root(&self, state_root: H256) -> Result<Option<H256>> {
        match self.state_root_index.get(state_root)? {
            Some(block_root_bytes) => Ok(Some(H256::from_slice(&block_root_bytes))),
            None => Ok(None),
        }
    }

    pub fn put_block_root_by_state_root(&self, state_root: H256, block_root: H256) -> Result<()> {
        self.state_root_index.put(state_root, block_root)?;
        Ok(())
    }

    pub fn get_genesis_time(&self) -> Result<Option<u64>> {
        match self.checkpoints.get("genesis_time")? {
            Some(genesis_time_bytes) => Ok(Some(u64::from_ssz_default(&genesis_time_bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_genesis_time(&self, genesis_time: u64) -> Result<()> {
        let genesis_time_bytes = genesis_time.to_ssz()?;
        self.checkpoints.put("genesis_time", genesis_time_bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use containers::BlockBody;
    use ssz::SszWrite;
    use tempfile::TempDir;

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

    fn assert_ssz_eq<T: SszWrite>(left: &T, right: &T) {
        assert_eq!(
            left.to_ssz().expect("left should serialize"),
            right.to_ssz().expect("right should serialize"),
        );
    }

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
