use alloy_primitives::FixedBytes;
use anyhow::anyhow;
use leansig::{MESSAGE_LENGTH, serialization::Serializable, signature::SignatureScheme};
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use serde::{Deserialize, Serialize};
use crate::public_key::PublicKey;

const SIGNATURE_SIZE: usize = 3112;

type LeanSigSignature = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::Signature;

/// Wrapper around a fixed-size serialized hash-based signature.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Copy)]
pub struct SignatureWrapper {
    pub inner: FixedBytes<SIGNATURE_SIZE>,
}

impl From<&[u8]> for SignatureWrapper {
    fn from(value: &[u8]) -> Self {
        Self {
            inner: FixedBytes::from_slice(value),
        }
    }
}

impl SignatureWrapper {
    pub fn new(inner: FixedBytes<SIGNATURE_SIZE>) -> Self {
        Self { inner }
    }

    pub fn blank() -> Self {
        Self::new(Default::default())
    }

    pub fn from_lean_sig(signature: LeanSigSignature) -> Result<Self, anyhow::Error> {
        Ok(Self {
            inner: FixedBytes::try_from(signature.to_bytes().as_slice())?,
        })
    }

    pub fn as_lean_sig(&self) -> anyhow::Result<LeanSigSignature> {
        LeanSigSignature::from_bytes(self.inner.as_slice())
            .map_err(|err| anyhow!("Failed to decode LeanSigSignature from SSZ: {err:?}"))
    }

    pub fn verify(
        &self,
        public_key: &PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> anyhow::Result<bool> {
        Ok(<SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::verify(
            &public_key.as_lean_sig()?,
            epoch,
            message,
            &self.as_lean_sig()?,
        ))
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