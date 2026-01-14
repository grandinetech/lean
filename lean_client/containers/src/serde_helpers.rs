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

        let wrapper = DataWrapper::<BitListData>::deserialize(deserializer)?;

        match wrapper.data {
            BitListData::HexString(hex_str) => {
                let hex_str = hex_str.trim_start_matches("0x");
                if hex_str.is_empty() {
                    return Ok(BitList::default());
                }

                let bytes = hex::decode(hex_str)
                    .map_err(|e| D::Error::custom(format!("Invalid hex string: {}", e)))?;

                BitList::from_ssz_unchecked(&(), &bytes)
                    .map_err(|e| D::Error::custom(format!("Invalid SSZ bitlist: {:?}", e)))
            }
            BitListData::BoolArray(bools) => {
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
pub mod signature {
    use super::*;
    use crate::Signature;
    use serde_json::Value;

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

        let value = Value::deserialize(deserializer)?;

        if let Value::String(hex_str) = &value {
            let hex_str = hex_str.trim_start_matches("0x");
            let bytes = hex::decode(hex_str)
                .map_err(|e| D::Error::custom(format!("Invalid hex string: {}", e)))?;

            return Signature::try_from(bytes.as_slice())
                .map_err(|_| D::Error::custom("Invalid signature length"));
        }

        let xmss_sig: XmssSignature = serde_json::from_value(value)
            .map_err(|e| D::Error::custom(format!("Failed to parse XMSS signature: {}", e)))?;

        let mut bytes = Vec::new();

        for sibling in &xmss_sig.path.siblings.data {
            for val in &sibling.data {
                bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        for val in &xmss_sig.rho.data {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        for hash in &xmss_sig.hashes.data {
            for val in &hash.data {
                bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // Pad or truncate to 3112 bytes to match U3112
        bytes.resize(3112, 0);

        Signature::try_from(bytes.as_slice())
            .map_err(|_| D::Error::custom("Failed to create signature from XMSS structure"))
    }

    pub fn serialize<S>(value: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = format!("0x{}", hex::encode(value.as_bytes()));
        hex_str.serialize(serializer)
    }
}

/// Custom deserializer for BlockSignatures
pub mod block_signatures {
    use super::*;
    use crate::block::BlockSignatures;
    use crate::Signature;
    use serde_json::Value;
    
    

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
        if let Value::String(hex_str) = value {
            let hex_str = hex_str.trim_start_matches("0x");
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex string: {}", e))?;

            return Signature::try_from(bytes.as_slice())
                .map_err(|_| "Invalid signature length".to_string());
        }

        let xmss_sig: XmssSignature = serde_json::from_value(value.clone())
            .map_err(|e| format!("Failed to parse XMSS signature: {}", e))?;

        let mut bytes = Vec::new();

        for sibling in &xmss_sig.path.siblings.data {
            for val in &sibling.data {
                bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        for val in &xmss_sig.rho.data {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        for hash in &xmss_sig.hashes.data {
            for val in &hash.data {
                bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

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
    pub fn serialize<S>(_value: &BlockSignatures, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(serde::ser::Error::custom(
            "BlockSignatures serialization not implemented for devnet2",
        ))
    }
}