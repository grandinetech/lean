use core::fmt::{self, Display};
use std::{str::FromStr, sync::Once};

use crate::{PublicKey, Signature};
use anyhow::{Context, Error, Result, anyhow, bail};
use ethereum_types::H256;
use leansig_wrapper::XmssPublicKey;
use metrics::{METRICS, stop_and_discard};
use rec_aggregation::{
    SingleMessageAggregateSignature, aggregate_single_message_signatures,
    init_aggregation_bytecode, verify_single_message_aggregate,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use ssz::{ByteList, ReadError, Size, SszHash, SszRead, SszSize, SszWrite, U1, WriteError};
use typenum::U524288;

/// Spec: `SingleMessageAggregate.proof: ByteList512KiB` (524 288 bytes).
type AggregatedSignatureSizeLimit = U524288;

/// Cryptographic proof that a set of validators signed a message.
///
/// Wire form: the lean-multisig `compress_without_pubkeys()` output. Pubkeys
/// are not baked into the bytes — verifiers must supply them externally,
/// matching `SingleMessageAggregate.proof: ByteList512KiB` in leanSpec
/// (`forks/lstar/containers/aggregation.py`) and zeam's `xmss_verify_type_1`
/// FFI which takes `pks + msg + slot + wire` as separate args.
#[derive(Debug, Clone)]
pub struct AggregatedSignature(ByteList<AggregatedSignatureSizeLimit>);

impl SszSize for AggregatedSignature {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C> SszRead<C> for AggregatedSignature {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let inner = ByteList::<AggregatedSignatureSizeLimit>::from_ssz_unchecked(context, bytes)?;
        Ok(Self(inner))
    }
}

impl SszWrite for AggregatedSignature {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl SszHash for AggregatedSignature {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        self.0.hash_tree_root()
    }
}

pub fn setup_aggregation() {
    static SETUP: Once = Once::new();
    SETUP.call_once(|| {
        init_aggregation_bytecode();
        backend::precompute_dft_twiddles::<backend::KoalaBear>(1 << 24);
    });
}

/// Cap the global rayon pool so the leansig prover doesn't oversubscribe physical
/// cores. Idempotent; safe to call once at process startup before any aggregation.
pub fn configure_rayon_pool(num_threads: usize) {
    drop(
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global(),
    );
}

impl AggregatedSignature {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let bytes = ByteList::try_from(bytes.to_vec())
            .context("signature too large - exceeds 512 KiB cap")?;
        Ok(Self(bytes))
    }

    pub fn aggregate(
        public_keys: impl IntoIterator<Item = PublicKey>,
        signatures: impl IntoIterator<Item = Signature>,
        message: H256,
        slot: u32,
        log_inv_rate: usize,
    ) -> Result<Self> {
        Self::aggregate_with_children(&[], public_keys, signatures, message, slot, log_inv_rate)
    }

    /// Aggregate signatures with optional recursive child proofs.
    ///
    /// `children` is a list of `(public_keys_covered_by_child, child_proof)` pairs.
    /// Each child proof was previously produced by aggregating the listed public keys,
    /// allowing recursive / hierarchical proof compaction.
    pub fn aggregate_with_children(
        children: &[(&[PublicKey], &AggregatedSignature)],
        public_keys: impl IntoIterator<Item = PublicKey>,
        signatures: impl IntoIterator<Item = Signature>,
        message: H256,
        slot: u32,
        log_inv_rate: usize,
    ) -> Result<Self> {
        setup_aggregation();

        let timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_aggregated_signatures_building_time_seconds
                .start_timer()
        });

        let public_keys = public_keys.into_iter().collect::<Vec<_>>();
        let signatures = signatures.into_iter().collect::<Vec<_>>();

        if public_keys.len() != signatures.len() {
            stop_and_discard(timer);
            bail!(
                "public key & signature count mismatch ({} != {})",
                public_keys.len(),
                signatures.len()
            );
        }

        if public_keys.is_empty() && children.len() < 2 {
            stop_and_discard(timer);
            bail!(
                "cannot aggregate: no raw signatures provided, at least 2 children required (got {})",
                children.len()
            );
        }

        let sig_count = public_keys.len();

        #[cfg(feature = "shadow-integration")]
        if crate::shadow_cost::fake_xmss() {
            stop_and_discard(timer);
            let slot_bytes = slot.to_le_bytes();
            let count_bytes = sig_count.to_le_bytes();
            let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + children.len() + 1);
            parts.push(message.as_bytes());
            parts.push(&slot_bytes);
            for (_, child) in children {
                parts.push(child.0.as_bytes());
            }
            parts.push(&count_bytes);
            let bytes =
                crate::shadow_cost::fill_fake_proof(crate::shadow_cost::fake_proof_size(), &parts);
            crate::shadow_cost::sleep(crate::shadow_cost::aggregate_delay(sig_count));
            return Self::new(&bytes);
        }

        let raw_xmss = public_keys
            .into_iter()
            .zip(signatures)
            .map(|(pk, sig)| (pk.as_lean(), sig.as_lean()))
            .collect::<Vec<_>>();

        let children_arg: Vec<SingleMessageAggregateSignature> = children
            .iter()
            .map(|(pks, agg)| agg.as_lean(sorted_dedup_lean_pubkeys(pks)))
            .collect::<Result<Vec<_>>>()?;

        let agg = aggregate_single_message_signatures(
            &children_arg,
            raw_xmss,
            *message.as_fixed_bytes(),
            slot,
            log_inv_rate,
        )?;

        METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_aggregated_signatures_total
                .inc_by(sig_count as u64)
        });

        let bytes = agg.compress_without_pubkeys();
        Ok(Self(ByteList::try_from(bytes).context(
            "aggregated proof too large - exceeds 512 KiB cap",
        )?))
    }

    pub fn verify(
        &self,
        public_keys: impl IntoIterator<Item = PublicKey>,
        message: H256,
        slot: u32,
    ) -> Result<()> {
        setup_aggregation();

        #[cfg(feature = "shadow-integration")]
        if crate::shadow_cost::fake_xmss() {
            let n = public_keys.into_iter().count();
            crate::shadow_cost::sleep(crate::shadow_cost::verify_delay(n));
            let _ = message;
            let _ = slot;
            return Ok(());
        }

        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_aggregated_signatures_verification_time_seconds
                .start_timer()
        });

        let mut expected_pubkeys = public_keys
            .into_iter()
            .map(|k| k.as_lean())
            .collect::<Vec<_>>();
        expected_pubkeys.sort();
        expected_pubkeys.dedup();

        let agg = self.as_lean(expected_pubkeys)?;

        if agg.info.without_pubkeys.message != *message.as_fixed_bytes() {
            bail!("aggregated signature bound to a different message than expected");
        }
        if agg.info.without_pubkeys.slot != slot {
            bail!("aggregated signature bound to a different slot than expected");
        }

        let result = verify_single_message_aggregate(&agg)
            .map(|_| ())
            .map_err(|err| anyhow!("{err:?}"));

        match &result {
            Ok(()) => {
                METRICS
                    .get()
                    .map(|metrics| metrics.lean_pq_sig_aggregated_signatures_valid_total.inc());
            }
            Err(_) => {
                METRICS.get().map(|metrics| {
                    metrics
                        .lean_pq_sig_aggregated_signatures_invalid_total
                        .inc()
                });
            }
        }
        result
    }

    pub(crate) fn as_lean(
        &self,
        pubkeys: Vec<XmssPublicKey>,
    ) -> Result<SingleMessageAggregateSignature> {
        SingleMessageAggregateSignature::decompress_without_pubkeys(self.0.as_bytes(), pubkeys)
            .ok_or_else(|| anyhow!("invalid aggregated XMSS signature"))
    }

    // todo(xmss): this is a function used only for testing. ideally, it should not exist
    pub fn is_empty(&self) -> bool {
        self.0.as_bytes().is_empty()
    }

    #[cfg(feature = "shadow-integration")]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

fn sorted_dedup_lean_pubkeys(pks: &[PublicKey]) -> Vec<XmssPublicKey> {
    let mut lean: Vec<XmssPublicKey> = pks.iter().map(|pk| pk.as_lean()).collect();
    lean.sort();
    lean.dedup();
    lean
}

impl Display for AggregatedSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for AggregatedSignature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.strip_prefix("0x").unwrap_or(s);

        let bytes = hex::decode(data)?;

        Self::new(&bytes).map_err(|err| anyhow!("{err:?}"))
    }
}

impl Serialize for AggregatedSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for AggregatedSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct DataWrapper {
            data: String,
        }

        let value = DataWrapper::deserialize(deserializer)?;

        value.data.parse().map_err(de::Error::custom)
    }
}
