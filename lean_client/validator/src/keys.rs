use containers::attestation::U3112;
use containers::ssz::ByteVector;
use containers::Signature;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

#[cfg(feature = "xmss-signing")]
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
#[cfg(feature = "xmss-signing")]
use leansig::signature::SignatureScheme;
#[cfg(feature = "xmss-signing")]
use leansig::serialization::Serializable;

#[cfg(not(feature = "xmss-signing"))]
use tracing::warn;

/// Manages XMSS secret keys for validators
pub struct KeyManager {
    /// Map of validator index to secret key bytes
    keys: HashMap<u64, Vec<u8>>,
    /// Path to keys directory
    keys_dir: PathBuf,
}

impl KeyManager {
    /// Load keys from the hash-sig-keys directory
    pub fn new(keys_dir: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let keys_dir = keys_dir.as_ref().to_path_buf();

        if !keys_dir.exists() {
            return Err(format!("Keys directory not found: {:?}", keys_dir).into());
        }

        info!(path = ?keys_dir, "Initializing key manager");

        Ok(KeyManager {
            keys: HashMap::new(),
            keys_dir,
        })
    }

    /// Load a secret key for a specific validator index
    pub fn load_key(&mut self, validator_index: u64) -> Result<(), Box<dyn std::error::Error>> {
        let sk_path = self
            .keys_dir
            .join(format!("validator_{}_sk.ssz", validator_index));

        if !sk_path.exists() {
            return Err(format!("Secret key file not found: {:?}", sk_path).into());
        }

        let key_bytes = std::fs::read(&sk_path)?;

        info!(
            validator = validator_index,
            size = key_bytes.len(),
            "Loaded secret key"
        );

        self.keys.insert(validator_index, key_bytes);
        Ok(())
    }

    /// Sign a message with the validator's secret key
    pub fn sign(
        &self,
        validator_index: u64,
        epoch: u32,
        message: &[u8; 32],
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        #[cfg(feature = "xmss-signing")]
        {
            let key_bytes = self
                .keys
                .get(&validator_index)
                .ok_or_else(|| format!("No key loaded for validator {}", validator_index))?;

            type SecretKey =
                <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::SecretKey;

            let secret_key = SecretKey::from_bytes(key_bytes)
                .map_err(|e| format!("Failed to deserialize secret key: {:?}", e))?;

            let leansig_signature =
                SIGTopLevelTargetSumLifetime32Dim64Base8::sign(&secret_key, epoch, message)
                    .map_err(|e| format!("Failed to sign message: {:?}", e))?;

            let sig_bytes = leansig_signature.to_bytes();

            if sig_bytes.len() != 3112 {
                return Err(format!(
                    "Invalid signature size: expected 3112, got {}",
                    sig_bytes.len()
                )
                .into());
            }

            // Convert to ByteVector<U3112> using unsafe pointer copy (same pattern as PublicKey)
            let mut byte_vec: ByteVector<U3112> = ByteVector::default();
            unsafe {
                let dest = &mut byte_vec as *mut ByteVector<U3112> as *mut u8;
                std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), dest, 3112);
            }

            Ok(byte_vec)
        }

        #[cfg(not(feature = "xmss-signing"))]
        {
            let _ = (epoch, message); // Suppress unused warnings
            warn!(
                validator = validator_index,
                "XMSS signing disabled - using zero signature"
            );
            Ok(Signature::default())
        }
    }

    /// Check if a key is loaded for a validator
    pub fn has_key(&self, validator_index: u64) -> bool {
        self.keys.contains_key(&validator_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_manager_creation() {
        // This will fail if directory doesn't exist, which is expected
        let result = KeyManager::new("/nonexistent/path");
        assert!(result.is_err());
    }
}
