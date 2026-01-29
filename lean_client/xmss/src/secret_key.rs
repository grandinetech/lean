use anyhow::{Context, Error, Result, anyhow};
use derive_more::Debug;
use leansig::{serialization::Serializable, signature::{
    SignatureScheme, generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8
}};
use rand::Rng;
use ssz::H256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{PublicKey, Signature};

type LeanSigSecretKey = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::SecretKey;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
#[debug("[REDACTED]")]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn sign(&self, message: H256, epoch: u32) -> Result<Signature> {
        let signature = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::sign(
            &self.as_lean(),
            epoch,
            message.as_fixed_bytes(),
        )
        .context("failed to sign message")?;

        Ok(Signature::from_lean(signature))
    }

    pub fn generate_key_pair<R: Rng>(
        rng: &mut R,
        activation_epoch: u32,
        num_active_epochs: u32,
    ) -> (PublicKey, SecretKey) {
        let (public_key, secret_key) =
            <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::key_gen::<R>(
                rng,
                activation_epoch as usize,
                num_active_epochs as usize,
            );

        (
            PublicKey::from_lean(public_key),
            SecretKey::from_lean(secret_key),
        )
    }

    fn from_lean(key: LeanSigSecretKey) -> Self {
        Self(key.to_bytes())
    }

    fn as_lean(&self) -> LeanSigSecretKey {
        LeanSigSecretKey::from_bytes(&self.0).expect("SecretKey was instantiated incorrectly")
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        LeanSigSecretKey::from_bytes(value)
            .map_err(|_| anyhow!("value is not valid secret key"))?;

        Ok(Self(value.to_vec()))
    }
}
