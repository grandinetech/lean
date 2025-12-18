// Serde helpers for handling test vector JSON format
// Test vectors wrap SSZ collections in {"data": [...]} objects

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wrapper for deserializing {"data": T} format
#[derive(Deserialize, Serialize, Clone)]
struct DataWrapper<T> {
    data: T,
}

/// Deserialize T from {"data": T} format
pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let wrapper = DataWrapper::<T>::deserialize(deserializer)?;
    Ok(wrapper.data)
}

/// Serialize T as {"data": T} format
pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    let wrapper = DataWrapper { data: value };
    wrapper.serialize(serializer)
}

/// Special deserializer for BitList that handles {"data": []} array format from test vectors
/// BitList normally serializes as hex string, but test vectors use empty arrays
pub mod bitlist {
    use super::*;
    use ssz::BitList;
    use ssz::SszRead;
    use typenum::Unsigned;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BitListData {
        HexString(String),
        BoolArray(Vec<bool>),
    }

    pub fn deserialize<'de, D, N>(deserializer: D) -> Result<BitList<N>, D::Error>
    where
        D: Deserializer<'de>,
        N: Unsigned,
    {
        use serde::de::Error;

        // First unwrap the {"data": ...} wrapper
        let wrapper = DataWrapper::<BitListData>::deserialize(deserializer)?;

        match wrapper.data {
            BitListData::HexString(hex_str) => {
                // Handle hex string format (e.g., "0x01ff")
                let hex_str = hex_str.trim_start_matches("0x");
                if hex_str.is_empty() {
                    // Empty hex string means empty bitlist
                    return Ok(BitList::default());
                }

                let bytes = hex::decode(hex_str)
                    .map_err(|e| D::Error::custom(format!("Invalid hex string: {}", e)))?;

                // Decode SSZ bitlist (with delimiter bit)
                BitList::from_ssz_unchecked(&(), &bytes)
                    .map_err(|e| D::Error::custom(format!("Invalid SSZ bitlist: {:?}", e)))
            }
            BitListData::BoolArray(bools) => {
                // Handle array format (e.g., [true, false, true])
                let mut bitlist = BitList::with_length(bools.len());
                for (index, bit) in bools.into_iter().enumerate() {
                    bitlist.set(index, bit);
                }
                Ok(bitlist)
            }
        }
    }

    pub fn serialize<S, N>(value: &BitList<N>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        N: Unsigned,
    {
        use ssz::SszWrite;

        // Serialize as hex string in {"data": "0x..."} format
        let mut bytes = Vec::new();
        value
            .write_variable(&mut bytes)
            .map_err(|e| serde::ser::Error::custom(format!("Failed to write SSZ: {:?}", e)))?;

        let hex_str = format!("0x{}", hex::encode(&bytes));
        let wrapper = DataWrapper { data: hex_str };
        wrapper.serialize(serializer)
    }
}

/// Special deserializer for Signature that handles structured XMSS format from test vectors
/// Signatures in test vectors are structured with {path, rho, hashes} instead of hex bytes
pub mod signature {
    use super::*;
    use crate::Signature;
    use serde_json::Value;

    /// Structured XMSS signature format from test vectors
    #[derive(Deserialize)]
    struct XmssSignature {
        path: XmssPath,
        rho: DataWrapper<Vec<u32>>,
        hashes: DataWrapper<Vec<DataWrapper<Vec<u32>>>>,
    }

    #[derive(Deserialize)]
    struct XmssPath {
        siblings: DataWrapper<Vec<DataWrapper<Vec<u32>>>>,
    }

    pub fn deserialize_single<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        // First, try to parse as a JSON value to inspect the structure
        let value = Value::deserialize(deserializer)?;

        // Check if it's a hex string (normal format)
        if let Value::String(hex_str) = &value {
            let hex_str = hex_str.trim_start_matches("0x");
            let bytes = hex::decode(hex_str)
                .map_err(|e| D::Error::custom(format!("Invalid hex string: {}", e)))?;

            return Signature::try_from(bytes.as_slice())
                .map_err(|_| D::Error::custom("Invalid signature length"));
        }

        // Otherwise, parse as structured XMSS signature
        let xmss_sig: XmssSignature = serde_json::from_value(value)
            .map_err(|e| D::Error::custom(format!("Failed to parse XMSS signature: {}", e)))?;

        // Serialize the XMSS signature to bytes
        // Format: siblings (variable length) + rho (28 bytes) + hashes (variable length)
        let mut bytes = Vec::new();

        // Write siblings
        for sibling in &xmss_sig.path.siblings.data {
            for val in &sibling.data {
                bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // Write rho (7 u32s = 28 bytes)
        for val in &xmss_sig.rho.data {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // Write hashes
        for hash in &xmss_sig.hashes.data {
            for val in &hash.data {
                bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // Pad or truncate to 3112 bytes
        bytes.resize(3112, 0);

        Signature::try_from(bytes.as_slice())
            .map_err(|_| D::Error::custom("Failed to create signature"))
    }

    pub fn serialize<S>(value: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as hex string
        let hex_str = format!("0x{}", hex::encode(value.as_bytes()));
        hex_str.serialize(serializer)
    }
}

/// Custom deserializer for BlockSignatures that handles the {"data": [sig, ...]} format
/// where each signature can be either hex string or structured XMSS format
pub mod block_signatures {
    use super::*;
    use crate::Signature;
    use serde_json::Value;
    use ssz::PersistentList;
    use typenum::U4096;

    /// Structured XMSS signature format from test vectors
    #[derive(Deserialize, Clone)]
    struct XmssSignature {
        path: XmssPath,
        rho: DataWrapper<Vec<u32>>,
        hashes: DataWrapper<Vec<DataWrapper<Vec<u32>>>>,
    }

    #[derive(Deserialize, Clone)]
    struct XmssPath {
        siblings: DataWrapper<Vec<DataWrapper<Vec<u32>>>>,
    }

    fn parse_single_signature(value: &Value) -> Result<Signature, String> {
        // Check if it's a hex string (normal format)
        if let Value::String(hex_str) = value {
            let hex_str = hex_str.trim_start_matches("0x");
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex string: {}", e))?;

            return Signature::try_from(bytes.as_slice())
                .map_err(|_| "Invalid signature length".to_string());
        }

        // Otherwise, parse as structured XMSS signature
        let xmss_sig: XmssSignature = serde_json::from_value(value.clone())
            .map_err(|e| format!("Failed to parse XMSS signature: {}", e))?;

        // Serialize the XMSS signature to bytes
        // Format: siblings (variable length) + rho (28 bytes) + hashes (variable length)
        let mut bytes = Vec::new();

        // Write siblings
        for sibling in &xmss_sig.path.siblings.data {
            for val in &sibling.data {
                bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // Write rho (7 u32s = 28 bytes)
        for val in &xmss_sig.rho.data {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // Write hashes
        for hash in &xmss_sig.hashes.data {
            for val in &hash.data {
                bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // Pad or truncate to 3112 bytes
        bytes.resize(3112, 0);

        Signature::try_from(bytes.as_slice()).map_err(|_| "Failed to create signature".to_string())
    }

    #[cfg(feature = "devnet1")]
    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<PersistentList<Signature, U4096>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        // Parse the {"data": [...]} wrapper
        let wrapper: DataWrapper<Vec<Value>> = DataWrapper::deserialize(deserializer)?;

        let mut signatures = PersistentList::default();

        for (idx, sig_value) in wrapper.data.into_iter().enumerate() {
            let sig = parse_single_signature(&sig_value)
                .map_err(|e| D::Error::custom(format!("Signature {}: {}", idx, e)))?;
            signatures
                .push(sig)
                .map_err(|e| D::Error::custom(format!("Signature {} push failed: {:?}", idx, e)))?;
        }

        Ok(signatures)
    }

    #[cfg(feature = "devnet2")]
    pub fn deserialize<'de, D>(_: D) -> Result<BlockSignatures, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "BlockSignatures deserialization not implemented for devnet2",
        ))
    }

    #[cfg(feature = "devnet1")]
    pub fn serialize<S>(
        value: &PersistentList<Signature, U4096>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Collect all signatures as hex strings
        let mut sigs: Vec<String> = Vec::new();
        let mut i = 0u64;
        loop {
            match value.get(i) {
                Ok(sig) => {
                    sigs.push(format!("0x{}", hex::encode(sig.as_bytes())));
                    i += 1;
                }
                Err(_) => break,
            }
        }

        let wrapper = DataWrapper { data: sigs };
        wrapper.serialize(serializer)
    }

    #[cfg(feature = "devnet2")]
    pub fn serialize<S>(value: &BlockSignatures, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(serde::de::Error::custom(
            "BlockSignatures serialization not implemented for devnet2",
        ))
    }
}
