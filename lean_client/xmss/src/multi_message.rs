use core::fmt::{self, Display};
use std::str::FromStr;

use anyhow::{Context, Error, Result, anyhow, bail};
use ethereum_types::H256;
use leanvm::{ClaimSelection, EthereumProof, SignatureClaims, XmssClaimGroup, aggregate};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use ssz::{ByteList, Ssz};
use typenum::U524288;

use crate::{
    AggregatedSignature, PublicKey,
    aggregated_signature::{PROVER_PERMIT, setup_aggregation},
};

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

    /// Merge Type-1 components, each bound to its own `(message, slot)`, into
    /// one Type-2 proof. leanVM groups claims by `(epoch, message)`, so a slot
    /// may carry several messages; components sharing a `(slot, message)` have
    /// their keys unioned into one group.
    pub fn aggregate(
        parts: &[(&AggregatedSignature, &[PublicKey], H256, u32)],
        log_inv_rate: usize,
    ) -> Result<Self> {
        setup_aggregation();

        if parts.is_empty() {
            bail!("multi-message aggregate requires at least one Type-1 component");
        }

        #[cfg(shadow_mode)]
        if crate::shadow_cost::fake_xmss() {
            let merge_n = parts.len();
            let count_bytes = merge_n.to_le_bytes();
            let mut seed: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
            for (sig, _, _, _) in parts {
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
            .map(|(sig, pks, message, slot)| {
                sig.as_lean(*message, *slot, pks.iter().map(|pk| pk.as_lean()).collect())
            })
            .collect::<Result<Vec<_>>>()?;

        let _permit = PROVER_PERMIT.lock().unwrap();

        let merged = aggregate(&parts_lean, vec![], vec![], &[], None, log_inv_rate)?;
        let bytes = merged.to_bytes_without_pubkeys();
        Self::new(&bytes)
    }

    pub fn verify(
        &self,
        pubkeys_per_message: &[&[PublicKey]],
        messages: &[(H256, u32)],
    ) -> Result<()> {
        setup_aggregation();

        #[cfg(shadow_mode)]
        if crate::shadow_cost::fake_xmss() {
            return Ok(());
        }

        let sig = self.as_lean(pubkeys_per_message, messages)?;

        sig.verify().map_err(|err| anyhow!("{err:?}"))
    }

    /// Narrow the Type-2 down to the single claim bound to `message`, yielding
    /// a Type-1 for it. leanVM does this by re-aggregating the parent with a
    /// declaration of the one group to keep, so it generates a fresh SNARK.
    ///
    /// `messages` gives every `(message, slot)` claim the parent carries, in
    /// the same order as `pubkeys_per_message`; the binding is not on the wire,
    /// so decoding needs them all even though only one survives.
    pub fn split_by_message(
        &self,
        pubkeys_per_message: &[&[PublicKey]],
        messages: &[(H256, u32)],
        message: H256,
        log_inv_rate: usize,
    ) -> Result<AggregatedSignature> {
        setup_aggregation();

        #[cfg(shadow_mode)]
        if crate::shadow_cost::fake_xmss() {
            let bytes = crate::shadow_cost::fill_fake_proof(
                crate::shadow_cost::fake_proof_size(),
                &[self.proof.as_bytes(), message.as_bytes()],
            );
            let _ = pubkeys_per_message;
            let _ = log_inv_rate;
            return AggregatedSignature::new(&bytes);
        }

        let sig = self.as_lean(pubkeys_per_message, messages)?;

        // Groups are keyed by (epoch, message), so a message appears in one
        // group unless two slots signed the very same bytes.
        let matches: Vec<&XmssClaimGroup> = sig
            .xmss_signers()
            .iter()
            .filter(|group| group.message == *message.as_fixed_bytes())
            .collect();
        let group = match matches.as_slice() {
            [group] => (*group).clone(),
            [] => bail!("split-by-message target not found in multi-message components"),
            _ => bail!("split-by-message target matched multiple components"),
        };

        let kept = SignatureClaims {
            xmss: vec![group],
            sphincs: Vec::new(),
        };
        let declare = ClaimSelection {
            signatures: &kept,
            da_commitments: &[],
        };

        let _permit = PROVER_PERMIT.lock().unwrap();

        let recovered = aggregate(&[sig], vec![], vec![], &[], Some(declare), log_inv_rate)?;
        let bytes = recovered.to_bytes_without_pubkeys();
        AggregatedSignature::new(&bytes)
    }

    fn as_lean(
        &self,
        pubkeys_per_message: &[&[PublicKey]],
        messages: &[(H256, u32)],
    ) -> Result<EthereumProof> {
        let claims = wire_claims(pubkeys_per_message, messages)?;
        EthereumProof::from_bytes_without_pubkeys(self.proof.as_bytes(), claims)
            .map_err(|err| anyhow!("invalid multi-message aggregate bytes: {err}"))
    }
}

/// The signer set leanVM binds a Type-2 aggregate to, built from the caller's
/// view of the claims: one group per `(slot, message)` pair, holding its
/// strictly sorted, deduplicated keys, with the groups themselves strictly
/// increasing on `(epoch, message)`. Claims sharing a `(slot, message)` merge
/// into one group; a slot may carry several messages, each its own group.
fn wire_claims(
    pubkeys_per_message: &[&[PublicKey]],
    messages: &[(H256, u32)],
) -> Result<SignatureClaims> {
    if pubkeys_per_message.len() != messages.len() {
        bail!(
            "binding length mismatch: {} pubkey sets vs {} messages",
            pubkeys_per_message.len(),
            messages.len()
        );
    }

    let mut groups: Vec<XmssClaimGroup> = Vec::with_capacity(messages.len());
    for ((message, slot), pks) in messages.iter().zip(pubkeys_per_message) {
        let keys = pks.iter().map(|pk| pk.as_lean());
        match groups
            .iter_mut()
            .find(|group| group.epoch == *slot && group.message == *message.as_fixed_bytes())
        {
            Some(group) => group.keys.extend(keys),
            None => groups.push(XmssClaimGroup {
                epoch: *slot,
                message: *message.as_fixed_bytes(),
                keys: keys.collect(),
            }),
        }
    }
    for group in &mut groups {
        group.keys.sort_unstable();
        group.keys.dedup();
    }
    groups.sort_unstable_by_key(|group| (group.epoch, group.message));
    Ok(SignatureClaims {
        xmss: groups,
        sphincs: Vec::new(),
    })
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
