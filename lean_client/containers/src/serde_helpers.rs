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

/// Custom deserializer for AttestationSignatures that handles the {"data": [sig, ...]} format
/// where each signature can be either hex string or structured XMSS format
pub mod attestation_signatures {
    use super::*;
    use crate::AggregatedSignatureProof;
    use crate::attestation::AttestationSignatures;
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
    use crate::AggregatedAttestation;
    use crate::attestation::AggregatedAttestations;
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
