use alloy_primitives::{
    FixedBytes,
    hex::{self, ToHexExt},
};
use anyhow::anyhow;
use leansig::{serialization::Serializable, signature::SignatureScheme};
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use serde::{Deserialize, Deserializer, Serialize};

pub type LeanSigPublicKey = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::PublicKey;

// This is a wrapper class for storing public keys, implementation based on Ream client
#[derive(Debug, PartialEq, Clone, Default, Eq, Hash, Copy)]
pub struct PublicKey {
    pub inner: FixedBytes<52>,
}

impl From<&[u8]> for PublicKey {
    fn from(value: &[u8]) -> Self {
        Self {
            inner: FixedBytes::from_slice(value),
        }
    }
}

impl PublicKey {
    pub fn new(inner: FixedBytes<52>) -> Self {
        Self { inner }
    }

    pub fn from_lean_sig(public_key: LeanSigPublicKey) -> Result<Self, anyhow::Error> {
        Ok(Self {
            inner: FixedBytes::try_from(public_key.to_bytes().as_slice())?,
        })
    }

    pub fn as_lean_sig(&self) -> anyhow::Result<LeanSigPublicKey> {
        LeanSigPublicKey::from_bytes(self.inner.as_slice())
            .map_err(|err| anyhow!("Failed to decode LeanSigPublicKey from SSZ: {err:?}"))
    }

    /// Debug helper: decode using leansig, then re-encode and ensure bytes match.
    pub fn debug_roundtrip(&self) -> anyhow::Result<()> {
        let pk = self.as_lean_sig()?;
        let re = pk.to_bytes();

        anyhow::ensure!(
            re.as_slice() == self.inner.as_slice(),
            "PublicKey roundtrip mismatch: decoded->encoded bytes differ"
        );

        Ok(())
    }

    /// Debug helper: short stable fingerprint for logs.
    pub fn fingerprint_hex(&self) -> String {
        use alloy_primitives::hex::ToHexExt;
        let bytes = self.inner.as_slice();
        let take = bytes.len().min(12);
        format!("0x{}", ToHexExt::encode_hex(&bytes[..take].iter()))
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
