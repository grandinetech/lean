use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display},
    str::FromStr,
};

use anyhow::{Error, anyhow};
use eth_ssz::{Decode as _, DecodeError, Encode as _};
use lean_multisig::XmssPublicKey;
use serde::{
    Deserialize, Serialize,
    de::{self, Visitor},
};
use ssz::{BytesToDepth, MerkleTree, SszHash, SszRead, SszSize, SszWrite};
use typenum::{U1, U32, Unsigned};

type PublicKeySize = U32;

type LeanSigPublicKey = XmssPublicKey;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; PublicKeySize::USIZE]);

// todo(xmss): default implementation doesn't make sense here
impl Default for PublicKey {
    fn default() -> Self {
        Self([0u8; PublicKeySize::USIZE])
    }
}

impl SszSize for PublicKey {
    const SIZE: ssz::Size = ssz::Size::Fixed {
        size: PublicKeySize::USIZE,
    };
}

impl<C> SszRead<C> for PublicKey {
    #[inline]
    fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
        Ok(Self(
            bytes.try_into().expect("byte length should be checked"),
        ))
    }
}

impl SszWrite for PublicKey {
    #[inline]
    fn write_fixed(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0);
    }
}

impl SszHash for PublicKey {
    type PackingFactor = U1;

    #[inline]
    fn hash_tree_root(&self) -> ssz::H256 {
        MerkleTree::<BytesToDepth<PublicKeySize>>::merkleize_bytes(self.0)
    }
}

impl PublicKey {
    pub fn new(bytes: &[u8]) -> Result<Self, DecodeError> {
        XmssPublicKey::from_ssz_bytes(bytes)
            .map_err(|_| DecodeError::BytesInvalid("invalid xmss public key".to_string()))?;

        Ok(Self(bytes.try_into().expect(
            "slice of length != 32 shouldn't deserialize as valid xmss public key",
        )))
    }

    pub(crate) fn from_lean(key: LeanSigPublicKey) -> Self {
        let bytes = key.as_ssz_bytes();
        Self(
            bytes
                .as_slice()
                .try_into()
                .expect("slice of length != 32 shouldn't deserialize as valid xmss public key"),
        )
    }

    pub(crate) fn as_lean(&self) -> LeanSigPublicKey {
        XmssPublicKey::from_ssz_bytes(&self.0).expect("PublicKey was instantiated incorrectly")
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
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
