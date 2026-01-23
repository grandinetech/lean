use alloy_primitives::{hex::{self, ToHexExt}};
use anyhow::{anyhow};
use leansig::{serialization::Serializable, signature::SignatureScheme};
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{SszSize, SszRead, SszWrite, SszHash, Size, WriteError, ReadError, H256};

const PUBLIC_KEY_SIZE: usize = 52;
pub type LeanSigPublicKey =
    <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::PublicKey;

// This is a wrapper class for storing public keys, implementation based on Ream client
#[derive(Debug, PartialEq, Clone, Eq, Hash, Copy)]
pub struct PublicKey {
    pub inner: [u8; PUBLIC_KEY_SIZE],
}

impl From<&[u8]> for PublicKey {
    fn from(value: &[u8]) -> Self {
        // Handle potential length panics or ensure slice is correct size
        let mut inner = [0u8; PUBLIC_KEY_SIZE];
        let len = value.len().min(PUBLIC_KEY_SIZE);
        inner[..len].copy_from_slice(&value[..len]);
        Self { inner }
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            inner: [0u8; PUBLIC_KEY_SIZE],
        }
    }
}

impl SszSize for PublicKey {
    const SIZE: Size = Size::Fixed {
        size: PUBLIC_KEY_SIZE,
    };
}

// 2. Define how to write (Serialize)
impl SszWrite for PublicKey {
    fn write_fixed(&self, _bytes: &mut [u8]) {
        panic!("SszWrite::write_fixed must be implemented for fixed-size types");
    }

    fn write_variable(&self, _bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        panic!("SszWrite::write_variable must be implemented for variable-size types");
    }

    fn to_ssz(&self) -> Result<Vec<u8>, WriteError> {
        match Self::SIZE {
            Size::Fixed { size } => {
                let mut bytes = vec![0; size];
                self.write_fixed(bytes.as_mut_slice());
                Ok(bytes)
            }
            Size::Variable { minimum_size } => {
                let mut bytes = Vec::with_capacity(minimum_size);
                self.write_variable(&mut bytes)?;
                Ok(bytes)
            }
        }
    }
}

impl<C> SszRead<C> for PublicKey {
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        // For a fixed-size struct, we must ensure we have exactly
        // the number of bytes required by our SszSize implementation.
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(ReadError::FixedSizeMismatch {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut inner = [0u8; PUBLIC_KEY_SIZE];
        inner.copy_from_slice(bytes);

        Ok(Self { inner })
    }
    fn from_ssz(context: &C, bytes: impl AsRef<[u8]>) -> Result<Self, ReadError> {
        let bytes_ref = bytes.as_ref();

        // SSZ fixed-size validation
        if bytes_ref.len() != PUBLIC_KEY_SIZE {
            return Err(ReadError::FixedSizeMismatch {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes_ref.len(),
            });
        }

        Self::from_ssz_unchecked(context, bytes_ref)
    }
}

impl SszHash for PublicKey {
    type PackingFactor = typenum::U1;

    fn hash_tree_root(&self) -> H256 {
        // Simple implementation: hash the inner bytes directly
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.inner);
        let result = hasher.finalize();
        H256::from_slice(&result)
    }
}

impl PublicKey {
    pub fn new(inner: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self { inner }
    }

    pub fn from_lean_sig(public_key: LeanSigPublicKey) -> Result<Self, anyhow::Error> {
        let bytes = public_key.to_bytes();
        // Ensure we fit into 52 bytes
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(anyhow!(
                "LeanSigPublicKey length mismatch: expected 52, got {}",
                bytes.len()
            ));
        }
        let mut inner = [0u8; PUBLIC_KEY_SIZE];
        inner.copy_from_slice(&bytes);
        Ok(Self { inner })
    }

    pub fn as_lean_sig(&self) -> anyhow::Result<LeanSigPublicKey> {
        LeanSigPublicKey::from_bytes(&self.inner)
            .map_err(|err| anyhow!("Failed to decode LeanSigPublicKey from SSZ: {err:?}"))
    }

    pub fn from_hex<S: AsRef<str>>(s: S) -> anyhow::Result<Self> {
        let s = s.as_ref();

        // Allow optional 0x prefix
        let s = s.strip_prefix("0x").unwrap_or(s);

        let bytes = hex::decode(s).map_err(|e| anyhow!("Invalid hex public key: {e}"))?;

        if bytes.len() != 52 {
            return Err(anyhow!(
                "PublicKey hex length mismatch: expected 52 bytes, got {}",
                bytes.len()
            ));
        }

        // Validate structure via LeanSig
        let lean_pk = LeanSigPublicKey::from_bytes(&bytes)
            .map_err(|e| anyhow!("Invalid XMSS public key encoding: {e:?}"))?;

        Self::from_lean_sig(lean_pk)
    }

    pub fn debug_roundtrip(&self) -> anyhow::Result<()> {
        let pk = self.as_lean_sig()?;
        let re = pk.to_bytes();

        anyhow::ensure!(
            re.as_slice() == self.inner.as_slice(),
            "PublicKey roundtrip mismatch: decoded->encoded bytes differ"
        );

        Ok(())
    }

    pub fn fingerprint_hex(&self) -> String {
        use alloy_primitives::hex::ToHexExt;
        let take = self.inner.len().min(12);
        format!("0x{}", ToHexExt::encode_hex(&self.inner[..take].iter()))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!(
            "0x{}",
            self.as_lean_sig()
                .map_err(serde::ser::Error::custom)?
                .to_bytes()
                .encode_hex()
        ))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let result: String = Deserialize::deserialize(deserializer)?;
        let result = hex::decode(&result).map_err(serde::de::Error::custom)?;

        Self::from_lean_sig(
            LeanSigPublicKey::from_bytes(&result)
                .map_err(|err| anyhow!("Convert to error, with error trait implemented {err:?}"))
                .map_err(serde::de::Error::custom)?,
        )
        .map_err(serde::de::Error::custom)
    }
}
