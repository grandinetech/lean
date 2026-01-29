use ssz::H256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

use anyhow::anyhow;
use anyhow::{Context, Result, ensure};
use xmss::{SecretKey, Signature};

/// Manages XMSS secret keys for validators
pub struct KeyManager {
    /// Map of validator index to secret key bytes
    keys: HashMap<u64, SecretKey>,
    /// Path to keys directory
    keys_dir: PathBuf,
}

impl KeyManager {
    /// Load keys from the hash-sig-keys directory
    pub fn new(keys_dir: impl AsRef<Path>) -> Result<Self> {
        let keys_dir = keys_dir.as_ref().to_path_buf();

        ensure!(keys_dir.exists(), "Keys directory not found: {keys_dir:?}");

        info!(path = ?keys_dir, "Initializing key manager");

        Ok(KeyManager {
            keys: HashMap::new(),
            keys_dir,
        })
    }

    /// Load a secret key for a specific validator index
    pub fn load_key(&mut self, validator_index: u64) -> Result<()> {
        let sk_path = self
            .keys_dir
            .join(format!("validator_{}_sk.ssz", validator_index));

        // todo(security): this probably should be zeroized
        let key_bytes = std::fs::read(&sk_path)
            .context(format!("Failed to read secret key file: {sk_path:?}"))?;

        let key = SecretKey::try_from(key_bytes.as_slice())?;

        info!(
            validator = validator_index,
            size = key_bytes.len(),
            "Loaded secret key"
        );

        self.keys.insert(validator_index, key);
        Ok(())
    }

    /// Sign a message with the validator's secret key
    pub fn sign(&self, validator_index: u64, epoch: u32, message: H256) -> Result<Signature> {
        let key = self
            .keys
            .get(&validator_index)
            .ok_or_else(|| anyhow!("No key loaded for validator {}", validator_index))?;

        key.sign(message, epoch)
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
