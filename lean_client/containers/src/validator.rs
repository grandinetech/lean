use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::ByteVector;
use ssz_derive::Ssz;
use typenum::U52;

/// BLS public key - 52 bytes (as defined in lean spec)
#[derive(Clone, Debug, PartialEq, Eq, Ssz)]
#[ssz(transparent)]
pub struct BlsPublicKey(pub ByteVector<U52>);

impl Default for BlsPublicKey {
    fn default() -> Self {
        BlsPublicKey(ByteVector::default())
    }
}

// Custom serde implementation
impl Serialize for BlsPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // ByteVector might have to_vec() or similar
        // For now, use unsafe to access the underlying bytes
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &self.0 as *const ByteVector<U52> as *const u8,
                52
            )
        };
        let hex_string = format!("0x{}", hex::encode(bytes));
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        
        let decoded = hex::decode(s).map_err(serde::de::Error::custom)?;
        if decoded.len() != 52 {
            return Err(serde::de::Error::custom(format!(
                "Expected 52 bytes, got {}",
                decoded.len()
            )));
        }
        
        // Create ByteVector from decoded bytes using unsafe
        let mut byte_vec = ByteVector::default();
        unsafe {
            let dest = &mut byte_vec as *mut ByteVector<U52> as *mut u8;
            std::ptr::copy_nonoverlapping(decoded.as_ptr(), dest, 52);
        }
        
        Ok(BlsPublicKey(byte_vec))
    }
}

impl BlsPublicKey {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let decoded = hex::decode(s).map_err(|e| e.to_string())?;
        if decoded.len() != 52 {
            return Err(format!("Expected 52 bytes, got {}", decoded.len()));
        }
        let mut byte_vec = ByteVector::default();
        unsafe {
            let dest = &mut byte_vec as *mut ByteVector<U52> as *mut u8;
            std::ptr::copy_nonoverlapping(decoded.as_ptr(), dest, 52);
        }
        Ok(BlsPublicKey(byte_vec))
    }
}

/// Validator record
#[derive(Clone, Debug, PartialEq, Eq, Default, Ssz, Serialize, Deserialize)]
pub struct Validator {
    pub pubkey: BlsPublicKey,
}
