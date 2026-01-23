use core::fmt::{self, Display};
use std::{str::FromStr, sync::Once};

use crate::{PublicKey, Signature};
use anyhow::{Context, Error, Result, anyhow, bail};
use eth_ssz::{Decode, Encode};
use ethereum_types::H256;
use lean_multisig::{
    Devnet2XmssAggregateSignature, xmss_aggregate_signatures, xmss_aggregation_setup_prover,
    xmss_aggregation_setup_verifier, xmss_verify_aggregated_signatures,
};
use metrics::{METRICS, stop_and_discard};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use ssz::{ByteList, Ssz};
use typenum::U1048576;

/// Max size currently is 1MiB by spec.
type AggregatedSignatureSizeLimit = U1048576;

/// Cryptographic proof that a set of validators signed a message.
///
/// Note: this doesn't follow spec a bit - in spec this would be a `proof_data`
///   field of AggregatedSignatureProof type. Implemented like this to have a
///   bit of nice encapsulation, so that xmss-related types don't leak
///   abstraction into containers crate.
///
/// todo(xmss): deriving Ssz not particularly good there, as this won't validate
/// if it actually has valid proof structure, so `.as_lean()` method may panic.
#[derive(Debug, Clone, Ssz)]
pub struct AggregatedSignature(ByteList<AggregatedSignatureSizeLimit>);

fn setup_prover() {
    static PROVER_SETUP: Once = Once::new();

    PROVER_SETUP.call_once(|| xmss_aggregation_setup_prover());
}

fn setup_verifier() {
    static VERIFIER_SETUP: Once = Once::new();

    VERIFIER_SETUP.call_once(|| xmss_aggregation_setup_verifier());
}

impl AggregatedSignature {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let bytes = ByteList::try_from(bytes.to_vec())
            .context("signature too large - currently max 1MiB signatures allowed")?;

        Devnet2XmssAggregateSignature::from_ssz_bytes(bytes.as_bytes())
            .map_err(|err| anyhow!("{err:?}"))
            .context("invalid aggregated signature")?;

        Ok(Self(bytes))
    }

    pub fn aggregate(
        public_keys: impl IntoIterator<Item = PublicKey>,
        signatures: impl IntoIterator<Item = Signature>,
        message: H256,
        epoch: u32,
    ) -> Result<Self> {
        setup_prover();

        let timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_attestation_signatures_building_time_seconds
                .start_timer()
        });

        let public_keys = public_keys
            .into_iter()
            .map(|k| k.as_lean())
            .collect::<Vec<_>>();
        let signatures = signatures
            .into_iter()
            .map(|s| s.as_lean())
            .collect::<Vec<_>>();

        if public_keys.len() != signatures.len() {
            stop_and_discard(timer);
            bail!(
                "public key & signature count mismatch ({} != {})",
                public_keys.len(),
                signatures.len()
            );
        }

        let aggregate =
            xmss_aggregate_signatures(&public_keys, &signatures, message.as_fixed_bytes(), epoch)
                .map_err(|err| anyhow!("{err:?}"))?;

        METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_aggregated_signatures_total
                .inc_by(signatures.len() as u64)
        });

        Ok(Self(aggregate.as_ssz_bytes().try_into()?))
    }

    pub fn verify(
        &self,
        public_keys: impl IntoIterator<Item = PublicKey>,
        message: H256,
        epoch: u32,
    ) -> Result<()> {
        setup_verifier();

        let _timer = METRICS.get().map(|metrics| {
            metrics
                .lean_pq_sig_aggregated_signatures_verification_time_seconds
                .start_timer()
        });

        let public_keys = public_keys
            .into_iter()
            .map(|k| k.as_lean())
            .collect::<Vec<_>>();

        let aggregated_signature = self.as_lean();

        xmss_verify_aggregated_signatures(
            &public_keys,
            message.as_fixed_bytes(),
            &aggregated_signature,
            epoch,
        )
        .map_err(|err| anyhow!("{err:?}"))
        .inspect(|_| {
            METRICS
                .get()
                .map(|metrics| metrics.lean_pq_sig_aggregated_signatures_valid_total.inc());
        })
        .inspect_err(|_| {
            METRICS.get().map(|metrics| {
                metrics
                    .lean_pq_sig_aggregated_signatures_invalid_total
                    .inc()
            });
        })
    }

    fn as_lean(&self) -> Devnet2XmssAggregateSignature {
        Devnet2XmssAggregateSignature::from_ssz_bytes(self.0.as_bytes())
            .expect("AggregatedSignature was not constructed properly")
    }

    // todo(xmss): this is a function used only for testing. ideally, it should not exist
    pub fn is_empty(&self) -> bool {
        self.0.as_bytes().is_empty()
    }
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
