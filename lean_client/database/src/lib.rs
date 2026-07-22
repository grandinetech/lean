use std::{
    borrow::Cow,
    collections::HashMap,
    marker::PhantomData,
    ops::{Bound, RangeBounds},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, Weak},
};

use anyhow::{Ok, Result};

use containers::Slot;
use ssz::{H256, SszReadDefault, SszWrite};

use libmdbx::{
    DatabaseFlags, Environment, EnvironmentFlags, EnvironmentKind, Geometry, Mode, SyncMode,
    WriteFlags,
};

const GIB: usize = 1 << 30;
const MIB: usize = 1 << 20;

pub const BLOCKS_TABLE_NAME: &str = "blocks";
pub const GENESIS_STATE_TABLE_NAME: &str = "genesis_state";

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

pub struct EnvironmentBuilder {
    path: PathBuf,
    max_size: usize,
}

impl EnvironmentBuilder {
    pub fn new(path: impl Into<PathBuf>, gib: usize) -> Self {
        Self {
            path: path.into(),
            max_size: gib * GIB,
        }
    }

    pub fn build(&self) -> Result<Arc<Environment>> {
        static ENVIRONMENTS: OnceLock<Mutex<HashMap<PathBuf, Weak<Environment>>>> = OnceLock::new();

        std::fs::create_dir_all(&self.path)?;
        let canonical = self.path.canonicalize()?;

        let mut environments = ENVIRONMENTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(env) = environments.get(&canonical).and_then(Weak::upgrade) {
            return Ok(env);
        }

        let env = Environment::builder()
            .set_max_dbs(2)
            .set_kind(EnvironmentKind::WriteMap)
            .set_flags(EnvironmentFlags {
                mode: Mode::ReadWrite {
                    sync_mode: SyncMode::SafeNoSync,
                },
                no_meminit: true,
                coalesce: true,
                liforeclaim: true,
                ..Default::default()
            })
            .set_geometry(Geometry {
                size: Some(0..self.max_size),
                growth_step: Some((256 * MIB) as isize),
                shrink_threshold: None,
                page_size: None,
            })
            .open(&canonical)?;

        let env = Arc::new(env);
        environments.insert(canonical, Arc::downgrade(&env));
        Ok(env)
    }
}

#[derive(Debug, Clone)]
pub struct Database<K, V> {
    env: Arc<Environment>,
    name: &'static str,
    compression: Compression,
    _marker: PhantomData<fn(K) -> V>,
}

impl<K: Key, V: Value> Database<K, V> {
    pub fn new(
        env: Arc<Environment>,
        name: &'static str,
        compression: Compression,
    ) -> Result<Self> {
        let txn = env.begin_rw_txn()?;
        txn.create_db(Some(name), DatabaseFlags::default())?;
        txn.commit()?;
        Ok(Self {
            env,
            name,
            compression,
            _marker: PhantomData,
        })
    }

    pub fn get(&self, key: &K) -> Result<Option<V>> {
        let txn = self.env.begin_ro_txn()?;
        let db = txn.open_db(Some(self.name))?;

        let key_bytes = key.encode();
        let Some(compressed) = txn.get::<Cow<[u8]>>(db.dbi(), &key_bytes)? else {
            return Ok(None);
        };

        let bytes = self.compression.decompress(&compressed)?;
        Ok(Some(V::decode(&bytes)?))
    }

    pub fn put(&self, key: &K, value: &V) -> Result<()> {
        let txn = self.env.begin_rw_txn()?;
        let db = txn.open_db(Some(self.name))?;

        let compressed = self.compression.compress(&value.encode()?)?;
        txn.put(db.dbi(), key.encode(), compressed, WriteFlags::default())?;

        txn.commit()?;
        Ok(())
    }

    pub fn range<P: KeyPrefix>(&self, bounds: impl RangeBounds<P>) -> Result<Vec<V>> {
        let txn = self.env.begin_ro_txn()?;
        let db = txn.open_db(Some(self.name))?;
        let mut cursor = txn.cursor(&db)?;

        let start = bounds.start_bound().map(|p| p.encode());
        let end = bounds.end_bound().map(|p| p.encode());

        let mut entry = match &start {
            Bound::Included(s) | Bound::Excluded(s) => {
                cursor.set_range::<Cow<[u8]>, Cow<[u8]>>(s)?
            }
            Bound::Unbounded => cursor.first::<Cow<[u8]>, Cow<[u8]>>()?,
        };

        let mut out = Vec::new();
        while let Some((key, value)) = entry {
            if let Bound::Excluded(s) = &start {
                if key.len() >= s.len() && &key[..s.len()] == s.as_slice() {
                    entry = cursor.next::<Cow<[u8]>, Cow<[u8]>>()?;
                    continue;
                }
            }
            let stop = match &end {
                Bound::Included(e) => key.len() >= e.len() && &key[..e.len()] > e.as_slice(),
                Bound::Excluded(e) => key.len() >= e.len() && &key[..e.len()] >= e.as_slice(),
                Bound::Unbounded => false,
            };
            if stop {
                break;
            }

            out.push(V::decode(&self.compression.decompress(&value)?)?);
            entry = cursor.next::<Cow<[u8]>, Cow<[u8]>>()?;
        }
        Ok(out)
    }

    pub fn delete_range<P: KeyPrefix>(&self, bounds: impl RangeBounds<P>) -> Result<usize> {
        let txn = self.env.begin_rw_txn()?;
        let db = txn.open_db(Some(self.name))?;

        let start = bounds.start_bound().map(|p| p.encode());
        let end = bounds.end_bound().map(|p| p.encode());

        let mut keys: Vec<Vec<u8>> = Vec::new();
        {
            let mut cursor = txn.cursor(&db)?;
            let mut entry = match &start {
                Bound::Included(s) | Bound::Excluded(s) => cursor.set_range::<Cow<[u8]>, ()>(s)?,
                Bound::Unbounded => cursor.first::<Cow<[u8]>, ()>()?,
            };
            while let Some((key, ())) = entry {
                if let Bound::Excluded(s) = &start {
                    if key.len() >= s.len() && &key[..s.len()] == s.as_slice() {
                        entry = cursor.next::<Cow<[u8]>, ()>()?;
                        continue;
                    }
                }
                let stop = match &end {
                    Bound::Included(e) => key.len() >= e.len() && &key[..e.len()] > e.as_slice(),
                    Bound::Excluded(e) => key.len() >= e.len() && &key[..e.len()] >= e.as_slice(),
                    Bound::Unbounded => false,
                };
                if stop {
                    break;
                }

                keys.push(key.into_owned());
                entry = cursor.next::<Cow<[u8]>, ()>()?;
            }
        }

        let mut cursor = txn.cursor(&db)?;
        let mut deleted = 0;
        for key in &keys {
            if cursor.set::<()>(key)?.is_some() {
                cursor.del(WriteFlags::default())?;
                deleted += 1;
            }
        }

        txn.commit()?;
        Ok(deleted)
    }
}

pub trait Key {
    fn encode(&self) -> Vec<u8>;
}

pub trait KeyPrefix {
    fn encode(&self) -> Vec<u8>;
}

pub trait Value: Sized {
    fn encode(&self) -> Result<Vec<u8>>;
    fn decode(bytes: &[u8]) -> Result<Self>;
}

impl<T: SszWrite + SszReadDefault> Value for T {
    fn encode(&self) -> Result<Vec<u8>> {
        Ok(self.to_ssz()?)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Self::from_ssz_default(bytes)?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockKey {
    pub slot: Slot,
    pub root: H256,
}

impl Key for BlockKey {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(40);
        b.extend_from_slice(&self.slot.0.to_be_bytes());
        b.extend_from_slice(self.root.as_ref());
        b
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BySlot(pub Slot);

impl KeyPrefix for BySlot {
    fn encode(&self) -> Vec<u8> {
        self.0.0.to_be_bytes().to_vec()
    }
}

const STATE_KEY_PREFIX: &[u8] = b"state";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateKey(pub Slot);

impl Key for StateKey {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(STATE_KEY_PREFIX.len() + 8);
        b.extend_from_slice(STATE_KEY_PREFIX);
        b.extend_from_slice(&self.0.0.to_be_bytes());
        b
    }
}

impl KeyPrefix for StateKey {
    fn encode(&self) -> Vec<u8> {
        Key::encode(self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StateKeyPrefix;

impl KeyPrefix for StateKeyPrefix {
    fn encode(&self) -> Vec<u8> {
        STATE_KEY_PREFIX.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use containers::{Block, BlockBody, State, Validator};

    use super::*;

    fn test_db_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lean_database_test_{}_{}",
            std::process::id(),
            name
        ));
        std::fs::remove_dir_all(&path).ok();
        path
    }

    fn test_env(name: &str) -> Arc<Environment> {
        EnvironmentBuilder::new(test_db_path(name), 1)
            .build()
            .expect("failed to open test environment")
    }

    fn blocks_db(env: Arc<Environment>) -> Database<BlockKey, Block> {
        Database::new(env, BLOCKS_TABLE_NAME, Compression::Lz4)
            .expect("failed to open blocks table")
    }

    fn states_db(env: Arc<Environment>) -> Database<StateKey, State> {
        Database::new(env, GENESIS_STATE_TABLE_NAME, Compression::Zstd)
            .expect("failed to open states table")
    }

    fn h256(byte: u8) -> H256 {
        H256::from_slice(&[byte; 32])
    }

    fn sample_block(slot: u64, root_byte: u8) -> Block {
        Block {
            slot: Slot(slot),
            proposer_index: 0,
            parent_root: H256::default(),
            state_root: h256(root_byte),
            body: BlockBody::default(),
        }
    }

    fn sample_state(genesis_time: u64) -> State {
        State::generate_genesis_with_validators(genesis_time, vec![Validator::default(); 2])
    }

    fn block_key(slot: u64, root_byte: u8) -> BlockKey {
        BlockKey {
            slot: Slot(slot),
            root: h256(root_byte),
        }
    }

    fn assert_ssz_eq<T: SszWrite>(left: &T, right: &T) {
        assert_eq!(
            left.to_ssz().expect("left should serialize"),
            right.to_ssz().expect("right should serialize"),
        );
    }

    #[test]
    fn compression_roundtrips() {
        let data = vec![42u8; 1024];
        for compression in [Compression::None, Compression::Lz4, Compression::Zstd] {
            let compressed = compression.compress(&data).expect("compress should succeed");
            let decompressed = compression
                .decompress(&compressed)
                .expect("decompress should succeed");
            assert_eq!(decompressed, data);
        }
    }

    #[test]
    fn get_missing_key_returns_none() {
        let db = blocks_db(test_env("get_missing"));
        assert!(
            db.get(&block_key(1, 1))
                .expect("get should succeed")
                .is_none()
        );
    }

    #[test]
    fn put_then_get_roundtrips() {
        let db = blocks_db(test_env("put_get"));
        let block = sample_block(3, 7);
        db.put(&block_key(3, 7), &block).expect("put should succeed");
        let read = db
            .get(&block_key(3, 7))
            .expect("get should succeed")
            .expect("value should exist");
        assert_ssz_eq(&read, &block);
    }

    #[test]
    fn put_overwrites_existing_value() {
        let db = blocks_db(test_env("overwrite"));
        let key = block_key(1, 1);
        db.put(&key, &sample_block(1, 1)).expect("put should succeed");
        let updated = sample_block(1, 9);
        db.put(&key, &updated).expect("second put should succeed");
        let read = db
            .get(&key)
            .expect("get should succeed")
            .expect("value should exist");
        assert_ssz_eq(&read, &updated);
    }

    #[test]
    fn range_returns_blocks_in_slot_order() {
        let db = blocks_db(test_env("range_order"));
        for slot in [300u64, 0, 256, 255, 2] {
            db.put(&block_key(slot, slot as u8), &sample_block(slot, slot as u8))
                .expect("put should succeed");
        }
        let slots: Vec<u64> = db
            .range::<BySlot>(..)
            .expect("range should succeed")
            .iter()
            .map(|b| b.slot.0)
            .collect();
        assert_eq!(slots, vec![0, 2, 255, 256, 300]);
    }

    #[test]
    fn range_respects_bounds() {
        let db = blocks_db(test_env("range_bounds"));
        for slot in 0..6u64 {
            db.put(&block_key(slot, slot as u8), &sample_block(slot, slot as u8))
                .expect("put should succeed");
        }

        let slots = |blocks: Vec<Block>| blocks.iter().map(|b| b.slot.0).collect::<Vec<_>>();

        let from = db
            .range(BySlot(Slot(2))..)
            .expect("range from should succeed");
        assert_eq!(slots(from), vec![2, 3, 4, 5]);

        let below = db
            .range(..BySlot(Slot(3)))
            .expect("range below should succeed");
        assert_eq!(slots(below), vec![0, 1, 2]);

        let inclusive = db
            .range(..=BySlot(Slot(3)))
            .expect("inclusive range should succeed");
        assert_eq!(slots(inclusive), vec![0, 1, 2, 3]);
    }

    #[test]
    fn range_returns_all_forks_at_a_slot() {
        let db = blocks_db(test_env("range_forks"));
        db.put(&block_key(4, 1), &sample_block(4, 1)).expect("put should succeed");
        db.put(&block_key(4, 2), &sample_block(4, 2)).expect("put should succeed");
        db.put(&block_key(5, 3), &sample_block(5, 3)).expect("put should succeed");

        let at_slot_4 = db
            .range(BySlot(Slot(4))..=BySlot(Slot(4)))
            .expect("range should succeed");
        assert_eq!(at_slot_4.len(), 2);
        assert!(at_slot_4.iter().all(|b| b.slot.0 == 4));
    }

    #[test]
    fn delete_range_removes_and_counts() {
        let db = blocks_db(test_env("delete_range"));
        for slot in 0..6u64 {
            db.put(&block_key(slot, slot as u8), &sample_block(slot, slot as u8))
                .expect("put should succeed");
        }

        let deleted = db
            .delete_range(..BySlot(Slot(3)))
            .expect("delete_range should succeed");
        assert_eq!(deleted, 3);

        assert!(
            db.get(&block_key(0, 0))
                .expect("get should succeed")
                .is_none()
        );
        let remaining = db.range::<BySlot>(..).expect("range should succeed");
        assert_eq!(remaining.len(), 3);
    }

    #[test]
    fn state_key_prefix_returns_newest_state() {
        let db = states_db(test_env("state_newest"));
        db.put(&StateKey(Slot(0)), &sample_state(1000))
            .expect("put should succeed");
        db.put(&StateKey(Slot(64)), &sample_state(2000))
            .expect("put should succeed");

        let newest = db
            .range(StateKeyPrefix..)
            .expect("range should succeed")
            .pop()
            .expect("state should exist");
        assert_eq!(newest.config.genesis_time, 2000);
    }

    #[test]
    fn delete_range_prunes_old_states() {
        let db = states_db(test_env("state_prune"));
        db.put(&StateKey(Slot(0)), &sample_state(1000))
            .expect("put should succeed");
        db.put(&StateKey(Slot(64)), &sample_state(2000))
            .expect("put should succeed");

        let deleted = db
            .delete_range(..StateKey(Slot(64)))
            .expect("delete_range should succeed");
        assert_eq!(deleted, 1);

        assert!(
            db.get(&StateKey(Slot(0)))
                .expect("get should succeed")
                .is_none()
        );
        assert!(
            db.get(&StateKey(Slot(64)))
                .expect("get should succeed")
                .is_some()
        );
    }

    #[test]
    fn environment_builder_reuses_live_environment() {
        let path = test_db_path("registry_reuse");
        let first = EnvironmentBuilder::new(path.clone(), 1)
            .build()
            .expect("first build should succeed");
        let second = EnvironmentBuilder::new(path, 1)
            .build()
            .expect("second build should succeed");
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn values_persist_across_environment_reopen() {
        let path = test_db_path("reopen");
        let block = sample_block(7, 7);
        {
            let db = blocks_db(
                EnvironmentBuilder::new(path.clone(), 1)
                    .build()
                    .expect("first build should succeed"),
            );
            db.put(&block_key(7, 7), &block).expect("put should succeed");
        }
        let db = blocks_db(
            EnvironmentBuilder::new(path, 1)
                .build()
                .expect("reopen should succeed"),
        );
        let read = db
            .get(&block_key(7, 7))
            .expect("get should succeed")
            .expect("value should survive reopen");
        assert_ssz_eq(&read, &block);
    }
}
