use alloy_primitives::hex::ToHexExt;
use anyhow::anyhow;
use leansig::{MESSAGE_LENGTH, serialization::Serializable, signature::SignatureScheme};
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use serde::{Deserialize, Deserializer, Serialize};
use crate::public_key::{PublicKey};

const SIGNATURE_SIZE: usize = 3112;

type LeanSigSignature = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::Signature;

/// Wrapper around a fixed-size serialized hash-based signature.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Signature {
    pub inner: [u8; SIGNATURE_SIZE],
}

impl From<&[u8]> for Signature {
    fn from(value: &[u8]) -> Self {
        // Handle potential length panics or ensure slice is correct size
        let mut inner = [0u8; SIGNATURE_SIZE];
        let len = value.len().min(SIGNATURE_SIZE);
        inner[..len].copy_from_slice(&value[..len]);
        Self { inner }
    }
}

impl Signature {
    pub fn new(inner: [u8; SIGNATURE_SIZE]) -> Self {
        Self { inner }
    }

    pub fn from_lean_sig(signature: LeanSigSignature) -> Result<Self, anyhow::Error> {
        let bytes = signature.to_bytes();
        // Ensure we fit into 3112 bytes
        if bytes.len() != 3112 {
            return Err(anyhow!(
                "LeanSigSignature length mismatch: expected 3112, got {}",
                bytes.len()
            ));
        }
        let mut inner = [0u8; SIGNATURE_SIZE];
        inner.copy_from_slice(&bytes);
        Ok(Self { inner })
    }

    pub fn as_lean_sig(&self) -> anyhow::Result<LeanSigSignature> {
        println!("Converting Signature to LeanSigSignature...");
        LeanSigSignature::from_bytes(&self.inner)
            .map_err(|err| anyhow!("Failed to decode LeanSigSignature from SSZ: {err:?}"))
    }

    pub fn verify(
        &self,
        public_key: &PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> anyhow::Result<bool> {
        Ok(
            <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::verify(
                &public_key.as_lean_sig()?,
                epoch,
                message,
                &self.as_lean_sig()?,
            ),
        )
    }

    /// Debug helper: decode using leansig, then re-encode and ensure bytes match.
    pub fn debug_roundtrip(&self) -> anyhow::Result<()> {
        let sig = self.as_lean_sig()?;
        let re = sig.to_bytes();

        anyhow::ensure!(
            re.as_slice() == self.inner.as_slice(),
            "Signature roundtrip mismatch: decoded->encoded bytes differ"
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

impl Serialize for Signature {
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

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let result: String = Deserialize::deserialize(deserializer)?;
        let result = alloy_primitives::hex::decode(&result).map_err(serde::de::Error::custom)?;

        Self::from_lean_sig(
            LeanSigSignature::from_bytes(&result)
                .map_err(|err| anyhow!("Convert to error, with error trait implemented {err:?}"))
                .map_err(serde::de::Error::custom)?,
        )
        .map_err(serde::de::Error::custom)
    }
}
