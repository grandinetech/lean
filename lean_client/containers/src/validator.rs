use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::ByteVector;
use ssz_derive::Ssz;
use typenum::{Unsigned, U52};

/// Size of XMSS public keys in bytes (as defined in lean spec)
type PublicKeySize = U52;

/// XMSS public key (as defined in lean spec)
#[derive(Clone, Debug, PartialEq, Eq, Ssz)]
#[ssz(transparent)]
pub struct PublicKey(pub ByteVector<PublicKeySize>);

impl Default for PublicKey {
    fn default() -> Self {
        PublicKey(ByteVector::default())
    }
}

// Custom serde implementation
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // ByteVector might have to_vec() or similar
        // For now, use unsafe to access the underlying bytes
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &self.0 as *const ByteVector<PublicKeySize> as *const u8,
                PublicKeySize::USIZE,
            )
        };
        let hex_string = format!("0x{}", hex::encode(bytes));
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);

        let decoded = hex::decode(s).map_err(serde::de::Error::custom)?;
        if decoded.len() != PublicKeySize::USIZE {
            return Err(serde::de::Error::custom(format!(
                "Expected {} bytes, got {}",
                PublicKeySize::USIZE,
                decoded.len()
            )));
        }

        // Create ByteVector from decoded bytes using unsafe
        let mut byte_vec = ByteVector::default();
        unsafe {
            let dest = &mut byte_vec as *mut ByteVector<PublicKeySize> as *mut u8;
            std::ptr::copy_nonoverlapping(decoded.as_ptr(), dest, PublicKeySize::USIZE);
        }

        Ok(PublicKey(byte_vec))
    }
}

impl PublicKey {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let decoded = hex::decode(s).map_err(|e| e.to_string())?;
        if decoded.len() != PublicKeySize::USIZE {
            return Err(format!(
                "Expected {} bytes, got {}",
                PublicKeySize::USIZE,
                decoded.len()
            ));
        }
        let mut byte_vec = ByteVector::default();
        unsafe {
            let dest = &mut byte_vec as *mut ByteVector<PublicKeySize> as *mut u8;
            std::ptr::copy_nonoverlapping(decoded.as_ptr(), dest, PublicKeySize::USIZE);
        }
        Ok(PublicKey(byte_vec))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Ssz, Serialize, Deserialize)]
pub struct Validator {
    pub pubkey: PublicKey,
    #[serde(default)]
    pub index: crate::Uint64,
}
