use core::{
    convert::TryFrom,
    fmt::{self, Debug, Display},
    str::FromStr,
};

use crate::public_key::PublicKey;
use anyhow::{Error, Result, anyhow};
use eth_ssz::{Decode as _, DecodeError, Encode as _};
use lean_multisig::{XmssSignature, xmss_verify};
use metrics::METRICS;
use serde::de::{self, Visitor};
use serde::{Deserialize, Serialize};
use ssz::{ByteVector, H256, Ssz};
use typenum::{Sum, U8, U16, U32, U128, U1024};

// 1208 = 1024 + 128 + 32 + 16 + 8
type SignatureSize = Sum<Sum<Sum<Sum<U1024, U128>, U32>, U16>, U8>;

type LeanSigSignature = XmssSignature;

// todo(xmss): default implementation doesn't make sense here, and is needed only for tests
#[derive(Clone, Default, Ssz)]
#[ssz(transparent)]
pub struct Signature(ByteVector<SignatureSize>);

impl Signature {
    pub fn new(inner: &[u8]) -> Result<Self, DecodeError> {
        XmssSignature::from_ssz_bytes(inner)
            .map_err(|_| DecodeError::BytesInvalid("invalid xmss signature".to_string()))?;

        Ok(Self(inner.try_into().expect(
            "slice of length != 1208 shouldn't deserialize as valid xmss signature",
        )))
    }

    pub fn verify(&self, public_key: &PublicKey, epoch: u32, message: H256) -> Result<()> {
        match xmss_verify(
            &public_key.as_lean(),
            epoch,
            message.as_fixed_bytes(),
            &self.as_lean(),
        ) {
            Ok(()) => {
                METRICS.get().map(|metrics| {
                    metrics.lean_pq_sig_attestation_signatures_valid_total.inc();
                });
                Ok(())
            }
            Err(err) => {
                METRICS.get().map(|metrics| {
                    metrics
                        .lean_pq_sig_attestation_signatures_invalid_total
                        .inc();
                });
                Err(anyhow!("invalid signature: {err:?}"))
            }
        }
    }

    pub(crate) fn from_lean(signature: LeanSigSignature) -> Self {
        let bytes = signature.as_ssz_bytes();

        Self(
            bytes
                .as_slice()
                .try_into()
                .expect("slice of length != 1208 shouldn't deserialize as valid xmss signature"),
        )
    }

    pub(crate) fn as_lean(&self) -> LeanSigSignature {
        XmssSignature::from_ssz_bytes(self.0.as_bytes())
            .expect("signature internal representation must be valid xmss signature")
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.strip_prefix("0x").unwrap_or(s);

        let bytes = hex::decode(data)?;

        Self::new(&bytes).map_err(|err| anyhow!("{err:?}"))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl Visitor<'_> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "hex-encoded xmss signature")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                v.parse().map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(SignatureVisitor)
    }
}

#[cfg(test)]
mod test {
    use crate::signature::SignatureSize;
    use typenum::Unsigned;

    #[test]
    fn valid_signature_size() {
        assert_eq!(SignatureSize::U64, 1208);
    }
}
