use ssz::H256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

use anyhow::anyhow;
use anyhow::{Context, Result, ensure};
use containers::Validator;
use xmss::{SecretKey, Signature};

/// Manages XMSS secret keys for validators (attestation + proposal keys per validator)
pub struct KeyManager {
    /// Map of validator index to attestation secret key
    attestation_keys: HashMap<u64, SecretKey>,
    /// Map of validator index to proposal secret key
    proposal_keys: HashMap<u64, SecretKey>,
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
            attestation_keys: HashMap::new(),
            proposal_keys: HashMap::new(),
            keys_dir,
        })
    }

    /// Load both attestation and proposal keys for a specific validator index.
    ///
    /// Expects files named:
    ///   `validator_{idx}_attestation_sk.ssz` — attestation signing key
    ///   `validator_{idx}_proposal_sk.ssz`    — block proposal signing key
    pub fn load_keys(&mut self, validator_index: u64) -> Result<()> {
        let attest_path = self
            .keys_dir
            .join(format!("validator_{validator_index}_attestation_sk.ssz"));
        let proposal_path = self
            .keys_dir
            .join(format!("validator_{validator_index}_proposal_sk.ssz"));

        // todo(security): this probably should be zeroized
        let attest_bytes = std::fs::read(&attest_path).context(format!(
            "Failed to read attestation key file: {attest_path:?}"
        ))?;
        let attest_key = SecretKey::try_from(attest_bytes.as_slice())?;

        let proposal_bytes = std::fs::read(&proposal_path).context(format!(
            "Failed to read proposal key file: {proposal_path:?}"
        ))?;
        let proposal_key = SecretKey::try_from(proposal_bytes.as_slice())?;

        info!(
            validator = validator_index,
            attest_size = attest_bytes.len(),
            proposal_size = proposal_bytes.len(),
            "Loaded attestation and proposal keys"
        );

        self.attestation_keys.insert(validator_index, attest_key);
        self.proposal_keys.insert(validator_index, proposal_key);
        Ok(())
    }

    /// Load attestation and proposal keys from explicit file paths.
    /// Used when annotated_validators.yaml provides the filenames directly.
    pub fn load_keys_from_files(
        &mut self,
        validator_index: u64,
        attest_path: &std::path::Path,
        proposal_path: &std::path::Path,
    ) -> Result<()> {
        let attest_bytes = std::fs::read(attest_path).context(format!(
            "Failed to read attestation key file: {attest_path:?}"
        ))?;
        let attest_key = SecretKey::try_from(attest_bytes.as_slice())?;

        let proposal_bytes = std::fs::read(proposal_path).context(format!(
            "Failed to read proposal key file: {proposal_path:?}"
        ))?;
        let proposal_key = SecretKey::try_from(proposal_bytes.as_slice())?;

        info!(
            validator = validator_index,
            attest_size = attest_bytes.len(),
            proposal_size = proposal_bytes.len(),
            "Loaded attestation and proposal keys"
        );

        self.attestation_keys.insert(validator_index, attest_key);
        self.proposal_keys.insert(validator_index, proposal_key);
        Ok(())
    }

    /// Check a validator's loaded keys against its registry entry.
    ///
    /// The attestation and proposal keys must differ: a validator signs a proposal and an
    /// attestation in the same slot, and XMSS is a stateful one-time signature, so one key
    /// shared by both roles would be reused (leanSpec `ValidatorRegistry`). Each key must
    /// also equal the registry's public key, or every signature fails verification at peers.
    pub fn check_keys(&self, validator_index: u64, validator: &Validator) -> Result<()> {
        let attestation_key = self
            .attestation_keys
            .get(&validator_index)
            .ok_or_else(|| anyhow!("No attestation key loaded for validator {validator_index}"))?
            .public_key();
        let proposal_key = self
            .proposal_keys
            .get(&validator_index)
            .ok_or_else(|| anyhow!("No proposal key loaded for validator {validator_index}"))?
            .public_key();

        ensure!(
            attestation_key != proposal_key,
            "Attestation and proposal keys must differ for validator {validator_index}, but the same key is loaded for both"
        );
        ensure!(
            attestation_key == validator.attestation_pubkey,
            "Attestation key for validator {validator_index} does not match the validator registry"
        );
        ensure!(
            proposal_key == validator.proposal_pubkey,
            "Proposal key for validator {validator_index} does not match the validator registry"
        );
        Ok(())
    }

    /// Sign an attestation message with the validator's attestation secret key.
    pub fn sign_attestation(
        &self,
        validator_index: u64,
        epoch: u32,
        message: H256,
    ) -> Result<Signature> {
        let key = self.attestation_keys.get(&validator_index).ok_or_else(|| {
            anyhow!(
                "No attestation key loaded for validator {}",
                validator_index
            )
        })?;

        key.sign(message, epoch)
    }

    /// Sign a block with the validator's proposal secret key.
    pub fn sign_proposal(
        &self,
        validator_index: u64,
        epoch: u32,
        message: H256,
    ) -> Result<Signature> {
        let key = self
            .proposal_keys
            .get(&validator_index)
            .ok_or_else(|| anyhow!("No proposal key loaded for validator {}", validator_index))?;

        key.sign(message, epoch)
    }

    /// Check if both attestation and proposal keys are loaded for a validator.
    pub fn has_key(&self, validator_index: u64) -> bool {
        self.attestation_keys.contains_key(&validator_index)
            && self.proposal_keys.contains_key(&validator_index)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use xmss::PublicKey;

    use super::*;

    #[test]
    fn test_key_manager_creation() {
        // This will fail if directory doesn't exist, which is expected
        let result = KeyManager::new("/nonexistent/path");
        assert!(result.is_err());
    }

    fn key_manager(attestation: SecretKey, proposal: SecretKey) -> KeyManager {
        KeyManager {
            attestation_keys: HashMap::from([(0, attestation)]),
            proposal_keys: HashMap::from([(0, proposal)]),
            keys_dir: PathBuf::new(),
        }
    }

    fn validator(attestation_pubkey: &PublicKey, proposal_pubkey: &PublicKey) -> Validator {
        Validator {
            attestation_pubkey: attestation_pubkey.clone(),
            proposal_pubkey: proposal_pubkey.clone(),
            index: 0,
        }
    }

    #[test]
    fn check_keys_matches_registry_and_distinct_roles() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let (attestation_pk, attestation_sk) = SecretKey::generate_key_pair(&mut rng, 0, 4);
        let (proposal_pk, proposal_sk) = SecretKey::generate_key_pair(&mut rng, 0, 4);
        let keys = key_manager(attestation_sk, proposal_sk);

        keys.check_keys(0, &validator(&attestation_pk, &proposal_pk))
            .expect("matching keys");

        let cases = [
            (
                "swapped roles",
                validator(&proposal_pk, &attestation_pk),
                "Attestation key for validator 0 does not match",
            ),
            (
                "proposal key not in registry",
                validator(&attestation_pk, &attestation_pk),
                "Proposal key for validator 0 does not match",
            ),
        ];
        for (name, registry_entry, want) in cases {
            let err = keys
                .check_keys(0, &registry_entry)
                .expect_err(name)
                .to_string();
            assert!(
                err.contains(want),
                "{name}: error {err:?} does not contain {want:?}"
            );
        }
    }

    #[test]
    fn check_keys_rejects_one_key_for_both_roles() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let (public_key, secret_key) = SecretKey::generate_key_pair(&mut rng, 0, 4);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let (_, same_secret_key) = SecretKey::generate_key_pair(&mut rng, 0, 4);

        let err = key_manager(secret_key, same_secret_key)
            .check_keys(0, &validator(&public_key, &public_key))
            .expect_err("one key for both roles")
            .to_string();
        assert!(err.contains("must differ"), "error {err:?}");
    }
}
