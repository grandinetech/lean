use anyhow::{Error, Result, anyhow};
use derive_more::Debug;
use lean_multisig::{XmssSecretKey, xmss_key_gen, xmss_sign};
use rand::CryptoRng;
use ssz::H256;

use crate::{PublicKey, Signature};

// TODO(zeroize): upstream `XmssSecretKey` does not derive `Zeroize`, so we cannot
// derive `ZeroizeOnDrop` on the wrapper. Acceptable for devnet bring-up; before
// mainnet, either upstream a `Zeroize` derive on `XmssSecretKey` or implement
// `Drop` here manually (zeroize the inner buffers via accessor).
#[derive(Debug)]
#[debug("[REDACTED]")]
pub struct SecretKey(XmssSecretKey);

impl SecretKey {
    pub fn sign(&self, message: H256, epoch: u32) -> Result<Signature> {
        if !self.0.activation_slots().contains(&epoch) {
            return Err(anyhow!("epoch {epoch} outside key activation window"));
        }

        let sig = xmss_sign(&self.0, epoch, message.as_fixed_bytes())
            .map_err(|err| anyhow!("failed to sign message: {err:?}"))?;
        Ok(Signature::from_lean(sig))
    }

    pub fn generate_key_pair<R: CryptoRng>(
        rng: &mut R,
        activation_epoch: u32,
        num_active_epochs: u32,
    ) -> (PublicKey, SecretKey) {
        let (pk, sk) = xmss_key_gen(rng, activation_epoch as u64, num_active_epochs as u64)
            .expect("activation range must fit within the 2^32 key lifetime");
        (PublicKey::from_lean(pk), SecretKey(sk))
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sk = postcard::from_bytes::<XmssSecretKey>(value)
            .map_err(|_| anyhow!("value is not valid secret key"))?;
        Ok(Self(sk))
    }
}
