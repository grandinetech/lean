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

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        // First, try to parse as a JSON value to inspect the structure
        let value = Value::deserialize(deserializer)?;

        // Check if it's a hex string (normal format)
        if let Value::String(hex_str) = value {
            let hex_str = hex_str.trim_start_matches("0x");
            let bytes = hex::decode(hex_str)
                .map_err(|e| D::Error::custom(format!("Invalid hex string: {}", e)))?;

            return Signature::try_from(bytes.as_slice())
                .map_err(|_| D::Error::custom("Invalid signature length"));
        }

        // Otherwise, parse as structured XMSS signature
        let xmss_sig: XmssSignature = serde_json::from_value(value.clone())
            .map_err(|e| D::Error::custom(format!("Failed to parse XMSS signature: {}", e)))?;

        println!(
            "Parsed XMSS Signature | siblings: {:?}",
            xmss_sig.path.siblings.data.len()
        );
        println!("Parsed XMSS Signature | rho: {:?}", xmss_sig.rho.data.len());
        println!(
            "Parsed XMSS Signature | hashes: {:?}",
            xmss_sig.hashes.data.len()
        );

        // --- STEP 1: PREPARE DATA BUFFERS ---

        // 1. Serialize Rho (Fixed length)
        // RAND_LEN_FE = 7, assuming u32 elements -> 28 bytes
        let mut rho_bytes = Vec::new();
        for val in &xmss_sig.rho.data {
            rho_bytes.extend_from_slice(&val.to_le_bytes());
        }
        let rho_len = rho_bytes.len(); // Should be 28 (7 * 4)

        // 2. Serialize Path/Siblings (Variable length)
        let mut path_bytes = Vec::new();
        // Prepend 4 bytes (containing 4) as an offset which would come with real SSZ serialization
        let inner_offset: u32 = 4;
        path_bytes.extend_from_slice(&inner_offset.to_le_bytes()); // [04 00 00 00]
        for sibling in &xmss_sig.path.siblings.data {
            for val in &sibling.data {
                path_bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // 3. Serialize Hashes (Variable length)
        let mut hashes_bytes = Vec::new();
        for hash in &xmss_sig.hashes.data {
            for val in &hash.data {
                hashes_bytes.extend_from_slice(&val.to_le_bytes());
            }
        }

        // --- STEP 2: CALCULATE OFFSETS ---

        // The fixed part contains:
        // 1. Path Offset (4 bytes)
        // 2. Rho Data (rho_len bytes)
        // 3. Hashes Offset (4 bytes)
        let fixed_part_size = 4 + rho_len + 4;

        // Offset to 'path' starts immediately after the fixed part
        let offset_path = fixed_part_size as u32;

        // Offset to 'hashes' starts after 'path' data
        let offset_hashes = offset_path + (path_bytes.len() as u32);

        // --- STEP 3: CONSTRUCT FINAL SSZ BYTES ---

        // Print all offsets and lengths for debugging
        println!(
            "SSZ Offsets | offset_path: {} | offset_hashes: {}",
            offset_path, offset_hashes
        );
        println!(
            "SSZ Lengths | rho_len: {} | path_len: {} | hashes_len: {}",
            rho_len,
            path_bytes.len(),
            hashes_bytes.len()
        );

        let mut ssz_bytes = Vec::new();

        // 1. Write Offset to Path (u32, Little Endian)
        ssz_bytes.extend_from_slice(&offset_path.to_le_bytes());

        // 2. Write Rho Data (Fixed)
        ssz_bytes.extend_from_slice(&rho_bytes);

        // 3. Write Offset to Hashes (u32, Little Endian)
        ssz_bytes.extend_from_slice(&offset_hashes.to_le_bytes());

        // 4. Write Path Data (Variable)
        ssz_bytes.extend_from_slice(&path_bytes);

        // 5. Write Hashes Data (Variable)
        ssz_bytes.extend_from_slice(&hashes_bytes);

        println!("Total SSZ Bytes Length: {}", ssz_bytes.len());

        Signature::try_from(ssz_bytes.as_slice())
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

/// Custom deserializer for AttestationSignatures that handles the {"data": [sig, ...]} format
/// where each signature can be either hex string or structured XMSS format
pub mod attestation_signatures {
    use super::*;
    use crate::attestation::AttestationSignatures;
    use crate::AggregatedSignatureProof;
    use serde::de::Error;
    use ssz::PersistentList;
    use typenum::U4096;
    pub fn deserialize<'de, D>(deserializer: D) -> Result<AttestationSignatures, D::Error>
    where
        D: Deserializer<'de>,
    {
        let outer: DataWrapper<Vec<AggregatedSignatureProof>> =
            DataWrapper::deserialize(deserializer)?;

        let mut out: PersistentList<AggregatedSignatureProof, U4096> = PersistentList::default();

        for aggregated_proof in outer.data.into_iter() {
            out.push(aggregated_proof).map_err(|e| {
                D::Error::custom(format!(
                    "AttestationSignatures push aggregated entry failed: {e:?}"
                ))
            })?;
        }

        Ok(out)
    }

    pub fn serialize<S>(_value: &AttestationSignatures, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // let mut inner: Vec<AggregatedSignatureProof> = Vec::new();
        //
        // // inner.push(format!("0x{}", hex::encode(sig.as_bytes())));
        // for sig in value.into_iter() {
        //     inner.push(format!("0x{}", hex::encode(sig.as_bytes())));
        // }
        //
        // DataWrapper { data: inner }.serialize(serializer)
        // TODO: implement serialization
        Err(serde::ser::Error::custom(
            "AttestationSignatures serialization not implemented for devnet2",
        ))
    }
}

/// Serde helper for ssz::ByteList - serializes as hex string
pub mod byte_list {
    use super::*;
    use ssz::ByteList;
    use typenum::Unsigned;

    pub fn deserialize<'de, D, N>(deserializer: D) -> Result<ByteList<N>, D::Error>
    where
        D: Deserializer<'de>,
        N: Unsigned,
    {
        use serde::de::Error;

        println!("Deserializing ByteList...");

        // First, try to parse as a JSON value to inspect the structure
        // let value = Value::deserialize(deserializer)?;
        let wrapper = DataWrapper::<String>::deserialize(deserializer)?;

        println!("Wrapper data length: {}", wrapper.data.len());

        // Check if it's a hex string (normal format)
        match wrapper.data {
            hex_str => {
                let hex_str = hex_str.trim_start_matches("0x");

                if hex_str.is_empty() {
                    return Ok(ByteList::default());
                }

                let bytes = hex::decode(hex_str)
                    .map_err(|e| D::Error::custom(format!("Invalid hex string: {}", e)))?;

                println!("Decoded ByteList bytes length: {}", bytes.len());

                return ByteList::try_from(bytes)
                    .map_err(|_| D::Error::custom("ByteList exceeds maximum length"));
            }
        }
    }

    pub fn serialize<S, N>(value: &ByteList<N>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        N: Unsigned,
    {
        let hex_str = format!("0x{}", hex::encode(value.as_bytes()));
        hex_str.serialize(serializer)
    }
}

/// Custom deserializer for AggregatedAttestations that handles the {"data": [sig, ...]} format
/// where each signature can be either hex string or structured XMSS format
pub mod aggregated_attestations {
    use super::*;
    use crate::attestation::AggregatedAttestations;
    use crate::AggregatedAttestation;
    use serde::de::Error;
    use ssz::PersistentList;
    use typenum::U4096;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AggregatedAttestations, D::Error>
    where
        D: Deserializer<'de>,
    {
        let outer: DataWrapper<Vec<AggregatedAttestation>> =
            DataWrapper::deserialize(deserializer)?;

        let mut out: PersistentList<AggregatedAttestation, U4096> = PersistentList::default();

        for aggregated_attestations in outer.data.into_iter() {
            out.push(aggregated_attestations).map_err(|e| {
                D::Error::custom(format!(
                    "AggregatedAttestations push aggregated entry failed: {e:?}"
                ))
            })?;
        }

        Ok(out)
    }

    pub fn serialize<S>(_value: &AggregatedAttestations, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // TODO: implement serialization
        Err(serde::ser::Error::custom(
            "AttestationSignatures serialization not implemented for devnet2",
        ))
    }
}
