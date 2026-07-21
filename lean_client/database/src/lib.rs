use std::{
    borrow::Cow,
    marker::PhantomData,
    ops::{Bound, RangeBounds},
    path::PathBuf,
    sync::Arc,
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

const BLOCKS_TABLE_NAME: &str = "blocks";
const GENESIS_STATE_TABLE_NAME: &str = "genesis_state";

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

pub struct EnvironmentBuilder {
    path: PathBuf,
    max_size: usize,
}

impl EnvironmentBuilder {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_size: 128 * GIB,
        }
    }

    pub fn max_size(mut self, bytes: usize) -> Self {
        self.max_size = bytes;
        self
    }

    pub fn build(&self) -> Result<Arc<Environment>> {
        std::fs::create_dir_all(&self.path)?;

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
            .open(&self.path)?;

        Ok(Arc::new(env))
    }
}

struct Database<K, V> {
    env: Arc<Environment>,
    name: &'static str,
    compression: Compression,
    _marker: PhantomData<fn(K) -> V>,
}

impl<K: Key, V: Value> Database<K, V> {
    pub fn new(env: Arc<Environment>, name: &'static str, compression: Compression) -> Result<Self> {
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

#[derive(Clone, Copy, Debug)]
pub struct GenesisKey;

impl Key for GenesisKey {
    fn encode(&self) -> Vec<u8> {
        vec![0]
    }
}