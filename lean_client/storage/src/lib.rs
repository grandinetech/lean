use std::{borrow::Cow, collections::HashSet, path::Path, sync::{Arc, Mutex}};

use anyhow::Result;
use bytesize::ByteSize;

use containers::{Block, Checkpoint, Slot, State};
use ssz::{H256, SszReadDefault as _, SszWrite as _};

use libmdbx::{DatabaseFlags, Environment, Geometry, RW, Transaction, TransactionKind, WriteFlags};

const BLOCKS_TABLE_NAME: &str = "blocks";
const STATES_TABLE_NAME: &str = "states";
const CHECKPOINTS_TABLE_NAME: &str = "checkpoints";
const SLOT_INDEX_TABLE_NAME: &str = "slot_index";
const BLOCKS_BY_SLOT_TABLE_NAME: &str = "blocks_by_slot";
const METADATA_TABLE_NAME: &str = "metadata";

const JUSTIFIED: u8 = 0;
const FINALIZED: u8 = 1;
const HEAD: u8 = 2;
const SAFE_TARGET: u8 = 3;

const SCHEMA_VERSION: u8 = 0;
const NETWORK_ID: u8 = 1;
const JUSTIFIED_EVER_UPDATED: u8 = 2;
const FINALIZED_EVER_UPDATED: u8 = 3;

#[derive(Debug)]
pub struct Storage {
    environment: Arc<Environment>,
    transaction: Mutex<Option<Transaction<RW>>>,
    blocks: Database,
    states: Database,
    checkpoints: Database,
    slot_index: Database,
    blocks_by_slot: Database,
    metadata: Database,
}

impl Storage {
    pub fn new(base: impl AsRef<Path>) -> Result<Self> {
        let base = base.as_ref();
        fs_err::create_dir_all(base)?;

        let environment = Arc::new(
            Environment::builder()
                .set_max_dbs(6)
                .set_geometry(Geometry {
                    size: Some(..usize::try_from(ByteSize::gib(2).as_u64())?),
                    growth_step: Some(isize::try_from(ByteSize::mib(256).as_u64())?),
                    shrink_threshold: None,
                    page_size: None,
                })
                .open_with_permissions(base, 0o600)?,
        );

        let txn = environment.begin_rw_txn()?;
        for name in [
            BLOCKS_TABLE_NAME,
            STATES_TABLE_NAME,
            CHECKPOINTS_TABLE_NAME,
            SLOT_INDEX_TABLE_NAME,
            BLOCKS_BY_SLOT_TABLE_NAME,
            METADATA_TABLE_NAME,
        ] {
            txn.create_db(Some(name), DatabaseFlags::default())?;
        }
        txn.commit()?;

        Ok(Self {
            blocks: Database::new(BLOCKS_TABLE_NAME, Compression::Lz4),
            states: Database::new(STATES_TABLE_NAME, Compression::Zstd),
            checkpoints: Database::new(CHECKPOINTS_TABLE_NAME, Compression::None),
            slot_index: Database::new(SLOT_INDEX_TABLE_NAME, Compression::None),
            blocks_by_slot: Database::new(BLOCKS_BY_SLOT_TABLE_NAME, Compression::None),
            metadata: Database::new(METADATA_TABLE_NAME, Compression::None),
            environment,
            transaction: Mutex::new(None),
        })
    }

    pub fn batch_write(&self, f: impl FnOnce() -> Result<()>) -> Result<()> {
        let txn = self.environment.begin_rw_txn()?;
        *self.transaction.lock().expect("transaction mutex poisoned") = Some(txn);

        let result = f();

        let txn = self
            .transaction
            .lock()
            .expect("transaction mutex poisoned")
            .take()
            .expect("batch_write installed the ambient transaction");

        match result {
            Ok(()) => {
                txn.commit()?;
                Ok(())
            }
            Err(error) => {
                drop(txn);
                Err(error)
            }
        }
    }

    fn write<R>(&self, f: impl FnOnce(&Transaction<RW>) -> Result<R>) -> Result<R> {
        let guard = self.transaction.lock().expect("transaction mutex poisoned");
        if let Some(txn) = guard.as_ref() {
            return f(txn);
        }
        drop(guard);
        let txn = self.environment.begin_rw_txn()?;
        let result = f(&txn)?;
        txn.commit()?;
        Ok(result)
    }

    fn read_bytes(&self, db: &Database, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let guard = self.transaction.lock().expect("transaction mutex poisoned");
        if let Some(txn) = guard.as_ref() {
            return db.get(txn, key);
        }
        drop(guard);
        let txn = self.environment.begin_ro_txn()?;
        let bytes = db.get(&txn, key)?;
        txn.commit()?;
        Ok(bytes)
    }

    pub fn get_block(&self, block_root: H256) -> Result<Option<Block>> {
        match self.read_bytes(&self.blocks, block_root)? {
            Some(bytes) => Ok(Some(Block::from_ssz_default(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_block(&self, block: Block, block_root: H256) -> Result<()> {
        let block_bytes = block.to_ssz()?;
        let index_key = slot_root_key(block.slot, block_root);
        self.write(|txn| {
            self.blocks.put(txn, block_root, block_bytes)?;
            self.blocks_by_slot.put(txn, index_key, b"")?;
            Ok(())
        })
    }

    pub fn has_block(&self, block_root: H256) -> Result<bool> {
        Ok(self.read_bytes(&self.blocks, block_root)?.is_some())
    }

    pub fn get_state(&self, block_root: H256) -> Result<Option<State>> {
        match self.read_bytes(&self.states, block_root)? {
            Some(bytes) => Ok(Some(State::from_ssz_default(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_state(&self, state: State, block_root: H256) -> Result<()> {
        let state_bytes = state.to_ssz()?;
        self.write(|txn| self.states.put(txn, block_root, state_bytes))
    }

    pub fn get_justified_checkpoint(&self) -> Result<Option<Checkpoint>> {
        match self.read_bytes(&self.checkpoints, [JUSTIFIED])? {
            Some(bytes) => Ok(Some(Checkpoint::from_ssz_default(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_justified_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        let checkpoint_bytes = checkpoint.to_ssz()?;
        self.write(|txn| self.checkpoints.put(txn, [JUSTIFIED], checkpoint_bytes))
    }

    pub fn get_finalized_checkpoint(&self) -> Result<Option<Checkpoint>> {
        match self.read_bytes(&self.checkpoints, [FINALIZED])? {
            Some(bytes) => Ok(Some(Checkpoint::from_ssz_default(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_finalized_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        let checkpoint_bytes = checkpoint.to_ssz()?;
        self.write(|txn| self.checkpoints.put(txn, [FINALIZED], checkpoint_bytes))
    }

    pub fn get_head_root(&self) -> Result<Option<H256>> {
        match self.read_bytes(&self.checkpoints, [HEAD])? {
            Some(bytes) => Ok(Some(H256::from_slice(&bytes))),
            None => Ok(None),
        }
    }

    pub fn put_head_root(&self, root: H256) -> Result<()> {
        self.write(|txn| self.checkpoints.put(txn, [HEAD], root))
    }

    pub fn get_safe_target(&self) -> Result<Option<H256>> {
        match self.read_bytes(&self.checkpoints, [SAFE_TARGET])? {
            Some(bytes) => Ok(Some(H256::from_slice(&bytes))),
            None => Ok(None),
        }
    }

    pub fn put_safe_target(&self, root: H256) -> Result<()> {
        self.write(|txn| self.checkpoints.put(txn, [SAFE_TARGET], root))
    }

    pub fn get_schema_version(&self) -> Result<Option<u32>> {
        match self.read_bytes(&self.metadata, [SCHEMA_VERSION])? {
            Some(bytes) => Ok(Some(u32::from_be_bytes(bytes.as_slice().try_into()?))),
            None => Ok(None),
        }
    }

    pub fn put_schema_version(&self, version: u32) -> Result<()> {
        self.write(|txn| self.metadata.put(txn, [SCHEMA_VERSION], version.to_be_bytes()))
    }

    pub fn get_network_id(&self) -> Result<Option<H256>> {
        match self.read_bytes(&self.metadata, [NETWORK_ID])? {
            Some(bytes) => Ok(Some(H256::from_slice(&bytes))),
            None => Ok(None),
        }
    }

    pub fn put_network_id(&self, network_id: H256) -> Result<()> {
        self.write(|txn| self.metadata.put(txn, [NETWORK_ID], network_id))
    }

    pub fn get_justified_ever_updated(&self) -> Result<Option<bool>> {
        match self.read_bytes(&self.metadata, [JUSTIFIED_EVER_UPDATED])? {
            Some(bytes) => Ok(Some(bytes.first().copied().unwrap_or(0) != 0)),
            None => Ok(None),
        }
    }

    pub fn put_justified_ever_updated(&self, value: bool) -> Result<()> {
        self.write(|txn| {
            self.metadata
                .put(txn, [JUSTIFIED_EVER_UPDATED], [u8::from(value)])
        })
    }

    pub fn get_finalized_ever_updated(&self) -> Result<Option<bool>> {
        match self.read_bytes(&self.metadata, [FINALIZED_EVER_UPDATED])? {
            Some(bytes) => Ok(Some(bytes.first().copied().unwrap_or(0) != 0)),
            None => Ok(None),
        }
    }

    pub fn put_finalized_ever_updated(&self, value: bool) -> Result<()> {
        self.write(|txn| {
            self.metadata
                .put(txn, [FINALIZED_EVER_UPDATED], [u8::from(value)])
        })
    }

    pub fn get_block_root_by_slot(&self, slot: Slot) -> Result<Option<H256>> {
        match self.read_bytes(&self.slot_index, slot.0.to_be_bytes())? {
            Some(bytes) => Ok(Some(H256::from_slice(&bytes))),
            None => Ok(None),
        }
    }

    pub fn put_block_root_by_slot(&self, slot: Slot, root: H256) -> Result<()> {
        let slot_bytes = slot.0.to_be_bytes();
        self.write(|txn| self.slot_index.put(txn, slot_bytes, root))
    }

    pub fn prune_before_slot(&self, slot: Slot, keep_roots: &HashSet<H256>) -> Result<usize> {
        let bound = slot.0;
        self.write(|txn| {
            let mut roots: Vec<H256> = Vec::new();
            let mut block_index_keys: Vec<Vec<u8>> = Vec::new();
            self.blocks_by_slot.for_each(txn, |key, _value| {
                if slot_of(key) >= bound {
                    return Ok(false);
                }
                let root = H256::from_slice(&key[8..]);
                if !keep_roots.contains(&root) {
                    roots.push(root);
                    block_index_keys.push(key.to_vec());
                }
                Ok(true)
            })?;

            let mut slot_index_keys: Vec<Vec<u8>> = Vec::new();
            self.slot_index.for_each(txn, |key, value| {
                if slot_of(key) >= bound {
                    return Ok(false);
                }
                let canonical_root = H256::from_slice(value);
                if !keep_roots.contains(&canonical_root) {
                    slot_index_keys.push(key.to_vec());
                }
                Ok(true)
            })?;

            let mut removed = 0;
            removed += self.blocks.delete_batch(txn, &roots)?;
            removed += self.states.delete_batch(txn, &roots)?;
            removed += self.blocks_by_slot.delete_batch(txn, &block_index_keys)?;
            removed += self.slot_index.delete_batch(txn, &slot_index_keys)?;

            Ok(removed)
        })
    }

    pub fn load_since(&self, slot: Slot) -> Result<Vec<(H256, Block, State)>> {
        let bound = slot.0;
        let txn = self.environment.begin_ro_txn()?;

        let mut roots: Vec<H256> = Vec::new();
        self.blocks_by_slot.for_each(&txn, |key, _value| {
            if slot_of(key) >= bound {
                roots.push(H256::from_slice(&key[8..]));
            }
            Ok(true)
        })?;

        let mut entries = Vec::with_capacity(roots.len());
        for root in roots {
            let block = match self.blocks.get(&txn, root)? {
                Some(bytes) => Block::from_ssz_default(&bytes)?,
                None => continue,
            };
            let state = match self.states.get(&txn, root)? {
                Some(bytes) => State::from_ssz_default(&bytes)?,
                None => continue,
            };
            entries.push((root, block, state));
        }

        txn.commit()?;
        Ok(entries)
    }

    pub fn commit_finalization(
        &self,
        head: H256,
        finalized: Checkpoint,
        safe_target: H256,
        prune_before: Slot,
        keep_roots: &HashSet<H256>,
    ) -> Result<usize> {
        let mut removed = 0;
        self.batch_write(|| {
            self.put_head_root(head)?;
            self.put_finalized_checkpoint(finalized)?;
            self.put_safe_target(safe_target)?;
            removed = self.prune_before_slot(prune_before, keep_roots)?;
            Ok(())
        })?;
        Ok(removed)
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new("./database").expect("failed to open default storage at ./database")
    }
}

fn slot_root_key(slot: Slot, root: H256) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&slot.0.to_be_bytes());
    key[8..].copy_from_slice(root.as_ref());
    key
}

fn slot_of(key: &[u8]) -> u64 {
    let mut slot = [0u8; 8];
    slot.copy_from_slice(&key[..8]);
    u64::from_be_bytes(slot)
}

#[derive(Debug)]
struct Database {
    name: String,
    compression: Compression,
}

impl Database {
    fn new(name: &str, compression: Compression) -> Self {
        Self {
            name: name.to_owned(),
            compression,
        }
    }

    fn get<K: TransactionKind>(
        &self,
        txn: &Transaction<K>,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        let db = txn.open_db(Some(&self.name))?;

        txn.get::<Cow<_>>(db.dbi(), key.as_ref())?
            .map(|compressed| self.compression.decompress(&compressed))
            .transpose()
    }

    fn put(
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

    fn for_each<K: TransactionKind>(
        &self,
        txn: &Transaction<K>,
        mut f: impl FnMut(&[u8], &[u8]) -> Result<bool>,
    ) -> Result<()> {
        let db = txn.open_db(Some(&self.name))?;
        let mut cursor = txn.cursor(&db)?;

        while let Some((key, value)) = cursor.next::<Cow<[u8]>, Cow<[u8]>>()? {
            let value = self.compression.decompress(&value)?;
            if !f(key.as_ref(), &value)? {
                break;
            }
        }

        Ok(())
    }

    fn delete_batch(
        &self,
        txn: &Transaction<RW>,
        keys: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<usize> {
        let db = txn.open_db(Some(&self.name))?;
        let mut cursor = txn.cursor(&db)?;

        let mut deleted = 0;
        for key in keys {
            if cursor.set::<()>(key.as_ref())?.is_some() {
                cursor.del(WriteFlags::default())?;
                deleted += 1;
            }
        }

        Ok(deleted)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Compression {
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
    fn safe_target_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_safe_target().unwrap().is_none());

        let root = h256(7);
        storage.put_safe_target(root).unwrap();

        assert_eq!(storage.get_safe_target().unwrap().unwrap(), root);
    }

    #[test]
    fn schema_version_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_schema_version().unwrap().is_none());

        storage.put_schema_version(3).unwrap();

        assert_eq!(storage.get_schema_version().unwrap().unwrap(), 3);
    }

    #[test]
    fn network_id_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_network_id().unwrap().is_none());

        let id = h256(9);
        storage.put_network_id(id).unwrap();

        assert_eq!(storage.get_network_id().unwrap().unwrap(), id);
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
    fn justified_ever_updated_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_justified_ever_updated().unwrap().is_none());

        storage.put_justified_ever_updated(true).unwrap();
        assert!(storage.get_justified_ever_updated().unwrap().unwrap());

        storage.put_justified_ever_updated(false).unwrap();
        assert!(!storage.get_justified_ever_updated().unwrap().unwrap());
    }

    #[test]
    fn finalized_ever_updated_roundtrips() {
        let (_dir, storage) = storage();
        assert!(storage.get_finalized_ever_updated().unwrap().is_none());

        storage.put_finalized_ever_updated(true).unwrap();
        assert!(storage.get_finalized_ever_updated().unwrap().unwrap());

        storage.put_finalized_ever_updated(false).unwrap();
        assert!(!storage.get_finalized_ever_updated().unwrap().unwrap());
    }

    #[test]
    fn checkpoints_and_metadata_keys_do_not_collide() {
        let (_dir, storage) = storage();
        let justified = Checkpoint {
            root: h256(1),
            slot: Slot(1),
        };
        let finalized = Checkpoint {
            root: h256(2),
            slot: Slot(2),
        };

        storage.put_justified_checkpoint(justified.clone()).unwrap();
        storage.put_finalized_checkpoint(finalized.clone()).unwrap();
        storage.put_head_root(h256(3)).unwrap();
        storage.put_safe_target(h256(4)).unwrap();
        storage.put_schema_version(7).unwrap();
        storage.put_network_id(h256(5)).unwrap();
        storage.put_justified_ever_updated(true).unwrap();
        storage.put_finalized_ever_updated(false).unwrap();

        assert_eq!(
            storage.get_justified_checkpoint().unwrap().unwrap(),
            justified
        );
        assert_eq!(
            storage.get_finalized_checkpoint().unwrap().unwrap(),
            finalized
        );
        assert_eq!(storage.get_head_root().unwrap().unwrap(), h256(3));
        assert_eq!(storage.get_safe_target().unwrap().unwrap(), h256(4));
        assert_eq!(storage.get_schema_version().unwrap().unwrap(), 7);
        assert_eq!(storage.get_network_id().unwrap().unwrap(), h256(5));
        assert!(storage.get_justified_ever_updated().unwrap().unwrap());
        assert!(!storage.get_finalized_ever_updated().unwrap().unwrap());
    }

    #[test]
    fn has_block_reflects_presence() {
        let (_dir, storage) = storage();
        assert!(!storage.has_block(h256(1)).unwrap());

        storage.put_block(sample_block(1), h256(1)).unwrap();

        assert!(storage.has_block(h256(1)).unwrap());
        assert!(!storage.has_block(h256(2)).unwrap());
    }

    #[test]
    fn load_since_returns_blocks_and_states_from_slot() {
        let (_dir, storage) = storage();
        for i in 0..6u8 {
            storage.put_block(sample_block(i), h256(i)).unwrap();
            storage
                .put_state(state_at_slot(u64::from(i)), h256(i))
                .unwrap();
        }

        let mut loaded = storage.load_since(Slot(3)).unwrap();
        loaded.sort_by_key(|(_, block, _)| block.slot.0);

        let slots: Vec<u64> = loaded.iter().map(|(_, block, _)| block.slot.0).collect();
        assert_eq!(slots, vec![3, 4, 5]);

        for (root, block, state) in loaded {
            assert_eq!(root, h256(u8::try_from(block.slot.0).unwrap()));
            assert_eq!(state.slot, block.slot);
        }
    }

    #[test]
    fn commit_finalization_persists_and_prunes() {
        let (_dir, storage) = storage();
        for i in 0..6u8 {
            storage.put_block(sample_block(i), h256(i)).unwrap();
            storage
                .put_state(state_at_slot(u64::from(i)), h256(i))
                .unwrap();
        }

        let finalized = Checkpoint {
            root: h256(4),
            slot: Slot(4),
        };
        let mut keep = HashSet::new();
        keep.insert(h256(4));

        let removed = storage
            .commit_finalization(h256(4), finalized.clone(), h256(5), Slot(4), &keep)
            .unwrap();

        assert!(removed > 0);
        assert_eq!(storage.get_head_root().unwrap().unwrap(), h256(4));
        assert_eq!(
            storage.get_finalized_checkpoint().unwrap().unwrap(),
            finalized
        );
        assert_eq!(storage.get_safe_target().unwrap().unwrap(), h256(5));
        assert!(storage.get_block(h256(0)).unwrap().is_none());
        assert!(storage.get_state(h256(0)).unwrap().is_none());
        assert!(storage.get_block(h256(4)).unwrap().is_some());
        assert!(storage.get_block(h256(5)).unwrap().is_some());
    }

    #[test]
    fn checkpoints_database_keys_do_not_collide() {
        let (_dir, storage) = storage();
        let finalized = Checkpoint {
            root: h256(2),
            slot: Slot(2),
        };
        let head = h256(3);

        storage.put_finalized_checkpoint(finalized.clone()).unwrap();
        storage.put_head_root(head).unwrap();

        assert_eq!(
            storage.get_finalized_checkpoint().unwrap().unwrap(),
            finalized
        );
        assert_eq!(storage.get_head_root().unwrap().unwrap(), head);
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

    fn state_at_slot(slot: u64) -> State {
        let mut state = State::generate_genesis(1_234, 3);
        state.slot = Slot(slot);
        state
    }

    #[test]
    fn prune_removes_blocks_below_slot_and_keeps_the_rest() {
        let (_dir, storage) = storage();
        for i in 0..10u8 {
            storage.put_block(sample_block(i), h256(i)).unwrap();
        }

        let removed = storage.prune_before_slot(Slot(5), &HashSet::new()).unwrap();
        assert_eq!(removed, 10);

        for i in 0..5u8 {
            assert!(storage.get_block(h256(i)).unwrap().is_none());
        }
        for i in 5..10u8 {
            assert!(storage.get_block(h256(i)).unwrap().is_some());
        }
    }

    #[test]
    fn prune_keeps_frozen_block_root() {
        let (_dir, storage) = storage();
        for i in 0..5u8 {
            storage.put_block(sample_block(i), h256(i)).unwrap();
        }

        let mut keep = HashSet::new();
        keep.insert(h256(2));

        storage.prune_before_slot(Slot(5), &keep).unwrap();

        assert!(storage.get_block(h256(2)).unwrap().is_some());
        for i in [0u8, 1, 3, 4] {
            assert!(storage.get_block(h256(i)).unwrap().is_none());
        }
    }

    #[test]
    fn prune_removes_forked_blocks_at_same_slot() {
        let (_dir, storage) = storage();
        let mut fork = sample_block(2);
        fork.proposer_index = 99;
        storage.put_block(sample_block(2), h256(20)).unwrap();
        storage.put_block(fork, h256(21)).unwrap();

        let removed = storage.prune_before_slot(Slot(5), &HashSet::new()).unwrap();

        assert_eq!(removed, 4);
        assert!(storage.get_block(h256(20)).unwrap().is_none());
        assert!(storage.get_block(h256(21)).unwrap().is_none());
    }

    #[test]
    fn prune_cleans_slot_index_unless_frozen() {
        let (_dir, storage) = storage();
        storage.put_block(sample_block(2), h256(2)).unwrap();
        storage.put_block_root_by_slot(Slot(2), h256(2)).unwrap();
        storage.put_block(sample_block(3), h256(3)).unwrap();
        storage.put_block_root_by_slot(Slot(3), h256(3)).unwrap();

        let mut keep = HashSet::new();
        keep.insert(h256(3));

        storage.prune_before_slot(Slot(5), &keep).unwrap();

        assert!(storage.get_block_root_by_slot(Slot(2)).unwrap().is_none());
        assert_eq!(
            storage.get_block_root_by_slot(Slot(3)).unwrap().unwrap(),
            h256(3),
        );
    }

    #[test]
    fn prune_removes_states_below_slot_and_keeps_frozen() {
        let (_dir, storage) = storage();
        storage.put_block(sample_block(1), h256(1)).unwrap();
        storage.put_state(state_at_slot(1), h256(1)).unwrap();
        storage.put_block(sample_block(2), h256(2)).unwrap();
        storage.put_state(state_at_slot(2), h256(2)).unwrap();

        let mut keep = HashSet::new();
        keep.insert(h256(2));

        storage.prune_before_slot(Slot(5), &keep).unwrap();

        assert!(storage.get_block(h256(1)).unwrap().is_none());
        assert!(storage.get_state(h256(1)).unwrap().is_none());
        assert!(storage.get_block(h256(2)).unwrap().is_some());
        assert!(storage.get_state(h256(2)).unwrap().is_some());
    }

    #[test]
    fn prune_protection_is_per_entity() {
        let (_dir, storage) = storage();
        storage.put_block(sample_block(1), h256(1)).unwrap();
        storage.put_state(state_at_slot(1), h256(1)).unwrap();

        let mut keep = HashSet::new();
        keep.insert(h256(1));

        storage.prune_before_slot(Slot(5), &keep).unwrap();

        assert!(storage.get_block(h256(1)).unwrap().is_some());
        assert!(storage.get_state(h256(1)).unwrap().is_some());
    }

    #[test]
    fn prune_below_lowest_slot_is_a_noop() {
        let (_dir, storage) = storage();
        for i in 0..5u8 {
            storage.put_block(sample_block(i), h256(i)).unwrap();
        }

        let removed = storage.prune_before_slot(Slot(0), &HashSet::new()).unwrap();
        assert_eq!(removed, 0);
        for i in 0..5u8 {
            assert!(storage.get_block(h256(i)).unwrap().is_some());
        }
    }

    #[test]
    fn batch_write_commits_all_on_success() {
        let (_dir, storage) = storage();

        storage
            .batch_write(|| {
                storage.put_block(sample_block(1), h256(1))?;
                storage.put_state(state_at_slot(1), h256(2))?;
                storage.put_head_root(h256(3))?;
                Ok(())
            })
            .unwrap();

        assert!(storage.get_block(h256(1)).unwrap().is_some());
        assert!(storage.get_state(h256(2)).unwrap().is_some());
        assert_eq!(storage.get_head_root().unwrap().unwrap(), h256(3));
    }

    #[test]
    fn batch_write_rolls_back_every_write_on_error() {
        let (_dir, storage) = storage();

        let result = storage.batch_write(|| {
            storage.put_block(sample_block(1), h256(1))?;
            storage.put_state(state_at_slot(1), h256(2))?;
            Err(anyhow::anyhow!("intentional failure"))
        });

        assert!(result.is_err());
        assert!(storage.get_block(h256(1)).unwrap().is_none());
        assert!(storage.get_state(h256(2)).unwrap().is_none());
    }

    #[test]
    fn storage_is_usable_after_batch_write() {
        let (_dir, storage) = storage();

        storage
            .batch_write(|| storage.put_block(sample_block(1), h256(1)))
            .unwrap();

        storage.put_block(sample_block(2), h256(2)).unwrap();

        assert!(storage.get_block(h256(1)).unwrap().is_some());
        assert!(storage.get_block(h256(2)).unwrap().is_some());
    }

    #[test]
    fn storage_is_usable_after_failed_batch_write() {
        let (_dir, storage) = storage();

        assert!(
            storage
                .batch_write(|| Err(anyhow::anyhow!("boom")))
                .is_err()
        );

        storage.put_block(sample_block(5), h256(5)).unwrap();
        assert!(storage.get_block(h256(5)).unwrap().is_some());
    }

    #[test]
    fn batch_write_reads_see_pending_writes() {
        let (_dir, storage) = storage();

        storage
            .batch_write(|| {
                storage.put_block(sample_block(7), h256(7)).unwrap();
                assert!(storage.get_block(h256(7)).unwrap().is_some());
                Ok(())
            })
            .unwrap();
    }
}
