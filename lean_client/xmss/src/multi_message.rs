use core::fmt::{self, Display};
use std::str::FromStr;

use anyhow::{Context, Error, Result, anyhow, bail};
use ethereum_types::H256;
use leansig_wrapper::XmssPublicKey;
use rec_aggregation::{
    MultiMessageAggregateSignature, merge_single_message_aggregates,
    split_multi_message_aggregate_by_message, verify_multi_message_aggregate,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use ssz::{ByteList, Ssz};
use typenum::U524288;

use crate::{AggregatedSignature, PublicKey, aggregated_signature::setup_aggregation};

type MultiMessageAggregateSizeLimit = U524288;

#[derive(Clone, Debug, Default, Ssz)]
pub struct MultiMessageAggregate {
    proof: ByteList<MultiMessageAggregateSizeLimit>,
}

impl MultiMessageAggregate {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let proof = ByteList::try_from(bytes.to_vec())
            .context("multi-message aggregate too large - max 512 KiB")?;
        Ok(Self { proof })
    }

    pub fn aggregate(
        parts: &[(&AggregatedSignature, &[PublicKey])],
        log_inv_rate: usize,
    ) -> Result<Self> {
        setup_aggregation();

        if parts.is_empty() {
            bail!("multi-message aggregate requires at least one Type-1 component");
        }

        #[cfg(feature = "shadow-integration")]
        if crate::shadow_cost::fake_xmss() {
            let merge_n = parts.len();
            let count_bytes = merge_n.to_le_bytes();
            let mut seed: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
            for (sig, _) in parts {
                seed.push(sig.as_bytes());
            }
            seed.push(&count_bytes);
            let bytes =
                crate::shadow_cost::fill_fake_proof(crate::shadow_cost::fake_proof_size(), &seed);
            crate::shadow_cost::sleep(crate::shadow_cost::merge_delay(merge_n));
            let _ = log_inv_rate;
            return Self::new(&bytes);
        }

        let parts_lean = parts
            .iter()
            .map(|(sig, pks)| {
                let mut lean: Vec<XmssPublicKey> = pks.iter().map(|pk| pk.as_lean()).collect();
                lean.sort();
                lean.dedup();
                sig.as_lean(lean)
            })
            .collect::<Result<Vec<_>>>()?;

        let merged = merge_single_message_aggregates(parts_lean, log_inv_rate)?;
        let bytes = merged.compress_without_pubkeys();
        Self::new(&bytes)
    }

    pub fn verify(
        &self,
        pubkeys_per_message: &[&[PublicKey]],
        messages: &[(H256, u32)],
    ) -> Result<()> {
        setup_aggregation();

        if pubkeys_per_message.len() != messages.len() {
            bail!(
                "binding length mismatch: {} pubkey sets vs {} messages",
                pubkeys_per_message.len(),
                messages.len()
            );
        }

        #[cfg(feature = "shadow-integration")]
        if crate::shadow_cost::fake_xmss() {
            return Ok(());
        }

        let pubkeys_per_info = sorted_dedup_lean_pubkeys(pubkeys_per_message);

        let sig = MultiMessageAggregateSignature::decompress_without_pubkeys(
            self.proof.as_bytes(),
            pubkeys_per_info,
        )
        .ok_or_else(|| anyhow!("invalid multi-message aggregate bytes"))?;

        if sig.info.len() != messages.len() {
            bail!(
                "component count mismatch: proof has {}, expected {}",
                sig.info.len(),
                messages.len()
            );
        }
        for (i, (expected_message, expected_slot)) in messages.iter().enumerate() {
            if sig.info[i].without_pubkeys.message != *expected_message.as_fixed_bytes() {
                bail!("component {i} bound to a different message than expected");
            }
            if sig.info[i].without_pubkeys.slot != *expected_slot {
                bail!("component {i} bound to a different slot than expected");
            }
        }

        verify_multi_message_aggregate(&sig)
            .map(|_| ())
            .map_err(|err| anyhow!("{err:?}"))
    }

    pub fn split_by_message(
        &self,
        pubkeys_per_message: &[&[PublicKey]],
        message: H256,
        log_inv_rate: usize,
    ) -> Result<AggregatedSignature> {
        setup_aggregation();

        #[cfg(feature = "shadow-integration")]
        if crate::shadow_cost::fake_xmss() {
            let bytes = crate::shadow_cost::fill_fake_proof(
                crate::shadow_cost::fake_proof_size(),
                &[self.proof.as_bytes(), message.as_bytes()],
            );
            let _ = pubkeys_per_message;
            let _ = log_inv_rate;
            return AggregatedSignature::new(&bytes);
        }

        let pubkeys_per_info = sorted_dedup_lean_pubkeys(pubkeys_per_message);
        let sig = MultiMessageAggregateSignature::decompress_without_pubkeys(
            self.proof.as_bytes(),
            pubkeys_per_info,
        )
        .ok_or_else(|| anyhow!("invalid multi-message aggregate bytes"))?;

        let recovered =
            split_multi_message_aggregate_by_message(sig, *message.as_fixed_bytes(), log_inv_rate)?;
        let bytes = recovered.compress_without_pubkeys();
        AggregatedSignature::new(&bytes)
    }
}

fn sorted_dedup_lean_pubkeys(per_component: &[&[PublicKey]]) -> Vec<Vec<XmssPublicKey>> {
    per_component
        .iter()
        .map(|pks| {
            let mut lean: Vec<XmssPublicKey> = pks.iter().map(|pk| pk.as_lean()).collect();
            lean.sort();
            lean.dedup();
            lean
        })
        .collect()
}

impl Display for MultiMessageAggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.proof.as_bytes()))
    }
}

impl FromStr for MultiMessageAggregate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(data)?;
        Self::new(&bytes)
    }
}

impl Serialize for MultiMessageAggregate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for MultiMessageAggregate {
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
