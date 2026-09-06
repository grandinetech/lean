use std::sync::Mutex;

use anyhow::{Error, Result, anyhow};
use derive_more::Debug;
use leansig::serialization::Serializable;
use leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_32::{
    SIGAbortingTargetSumLifetime32Dim46Base8 as XmssScheme,
    SecretKeyAbortingTargetSumLifetime32Dim46Base8 as XmssSecretKey,
};
use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use rand::CryptoRng;
use ssz::H256;

use crate::{PublicKey, Signature};

// TODO(zeroize): upstream `XmssSecretKey` does not derive `Zeroize`, so we cannot
// derive `ZeroizeOnDrop` on the wrapper. Acceptable for devnet bring-up; before
// mainnet, either upstream a `Zeroize` derive on `GeneralizedXMSSSecretKey` or
// implement `Drop` here manually (zeroize the inner buffers via accessor).
#[derive(Debug)]
#[debug("[REDACTED]")]
pub struct SecretKey(Mutex<XmssSecretKey>);

impl SecretKey {
    pub fn sign(&self, message: H256, epoch: u32) -> Result<Signature> {
        let mut sk = self
            .0
            .lock()
            .map_err(|_| anyhow!("failed to acquire secret key lock"))?;
        let target = epoch as u64;

        if !sk.get_activation_interval().contains(&target) {
            return Err(anyhow!("epoch {epoch} outside key activation window"));
        }

        while !sk.get_prepared_interval().contains(&target) {
            let before = sk.get_prepared_interval();
            sk.advance_preparation();
            if sk.get_prepared_interval() == before {
                return Err(anyhow!(
                    "advance_preparation made no progress for epoch {epoch}"
                ));
            }
        }

        let sig = XmssScheme::sign(&sk, epoch, message.as_fixed_bytes())
            .map_err(|_| anyhow!("failed to sign message"))?;
        Ok(Signature::from_lean(sig))
    }

    pub fn generate_key_pair<R: CryptoRng>(
        rng: &mut R,
        activation_epoch: u32,
        num_active_epochs: u32,
    ) -> (PublicKey, SecretKey) {
        let (pk, sk) =
            XmssScheme::key_gen(rng, activation_epoch as usize, num_active_epochs as usize);
        (PublicKey::from_lean(pk), SecretKey(Mutex::new(sk)))
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sk = XmssSecretKey::from_bytes(value)
            .map_err(|_| anyhow!("value is not valid secret key"))?;
        Ok(Self(Mutex::new(sk)))
    }
}
