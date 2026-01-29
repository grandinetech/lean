use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display},
    str::FromStr,
};

use anyhow::{Error, anyhow};
use leansig::{serialization::Serializable, signature::SignatureScheme, signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8};
use serde::{Deserialize, Serialize, de::{self, Visitor}};
use ssz::{ByteVector, Ssz};
use eth_ssz::DecodeError;
use typenum::U52;

type PublicKeySize = U52;

type LeanSigPublicKey = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::PublicKey;

// todo(xmss): default implementation doesn't make sense here
#[derive(Clone, Ssz, Default, PartialEq, Eq)]
pub struct PublicKey(ByteVector<PublicKeySize>);

impl PublicKey {
    pub fn new(bytes: &[u8]) -> Result<Self, DecodeError> {
        LeanSigPublicKey::from_bytes(bytes)?;

        Ok(Self(bytes.try_into().expect(
            "slice of length != 52 shouldn't deserialize as valid leansig public key",
        )))
    }

    pub(crate) fn from_lean(key: LeanSigPublicKey) -> Self {
        Self(
            key.to_bytes()
                .as_slice()
                .try_into()
                .expect("slice of length != 52 shouldn't deserialize as valid leansig public key"),
        )
    }

    pub(crate) fn as_lean(&self) -> LeanSigPublicKey {
        LeanSigPublicKey::from_bytes(self.0.as_bytes())
            .expect("PublicKey was instantiated incorrectly")
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.strip_prefix("0x").unwrap_or(s);

        let bytes = hex::decode(data)?;

        Self::new(&bytes).map_err(|err| anyhow!("{err:?}"))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl Visitor<'_> for SignatureVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "public key")
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
