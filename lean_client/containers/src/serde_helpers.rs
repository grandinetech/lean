// Serde helpers for handling test vector JSON format
// Test vectors wrap SSZ collections in {"data": [...]} objects

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wrapper for deserializing {"data": T} format
#[derive(Deserialize, Serialize)]
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
    use typenum::Unsigned;
    use ssz::SszRead;
    
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
        value.write_variable(&mut bytes)
            .map_err(|e| serde::ser::Error::custom(format!("Failed to write SSZ: {:?}", e)))?;
        
        let hex_str = format!("0x{}", hex::encode(&bytes));
        let wrapper = DataWrapper { data: hex_str };
        wrapper.serialize(serializer)
    }
}

/// Serializer for finite field (Fp) elements
pub mod fp_list {
    use super:: *;

    /// Deserialize a list of finite field values from {"data": [u32, u32, ...]} format
    pub fn deserialize<'de, D, T>(deserializer:  D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T:  Deserialize<'de>,
    {
        let wrapper = DataWrapper::<T>::deserialize(deserializer)?;
        Ok(wrapper.data)
    }

    /// Serialize Fp list as {"data": [u32, u32, ...]} format
    /// Each Fp element is serialized as its inner u32 value
    pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S:: Error>
    where
        S:  Serializer,
        T: Serialize,
    {
        let wrapper = DataWrapper { data: value };
        wrapper.serialize(serializer)
    }
}

/// Deserializer for BlockSignatures from leanSpec JSON format
pub mod xmss_signature {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use crate::attestation::{BlockSignatures, Signature, U3112};
    use ssz:: ByteVector;

    const SIG_SIZE: usize = 3112;

    #[derive(Deserialize)]
    struct DataWrapper<T> {
        data: T,
    }

    /// Top-level signature structure from leanSpec
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SignatureBlockJson {
        attestation_signatures: DataWrapper<Vec<AggregatedSignaturesJson>>,
        proposer_signature: XmssSignatureJson,
    }

    /// Wrapper for aggregated attestation signatures
    /// Each aggregated attestation has multiple validator signatures
    #[derive(Deserialize)]
    struct AggregatedSignaturesJson {
        data: Vec<XmssSignatureJson>,
    }

    #[derive(Deserialize)]
    struct XmssSignatureJson {
        path: HashTreeOpeningJson,
        rho: DataWrapper<Vec<u64>>,
        hashes: DataWrapper<Vec<DataWrapper<Vec<u64>>>>,
    }

    #[derive(Deserialize)]
    struct HashTreeOpeningJson {
        siblings: DataWrapper<Vec<DataWrapper<Vec<u64>>>>,
    }

    impl XmssSignatureJson {
        fn to_ssz_bytes(&self) -> Vec<u8> {
            let path_bytes = self.serialize_path();
            let hashes_bytes = self.serialize_hashes();

            // leansig SIGTargetSumLifetime20W2NoOff expects:
            // - rho: 6 field elements (RAND_LEN = 6) = 24 bytes
            // - But test vectors may have 7 elements, take first 6
            let rho_count = 6;  // RAND_LEN from leansig
            let rho_size = rho_count * 4;  // 24 bytes

            let fixed_size = 4 + rho_size + 4;  // 4 + 24 + 4 = 32
            let offset_path = fixed_size as u32;
            let offset_hashes = (fixed_size + path_bytes.len()) as u32;

            let mut bytes = Vec::new();
            bytes.extend_from_slice(&offset_path. to_le_bytes());

            // Serialize exactly 6 rho elements (pad with 0 if fewer, truncate if more)
            for i in 0.. rho_count {
                let fe = self.rho. data. get(i).copied().unwrap_or(0);
                bytes.extend_from_slice(&(fe as u32).to_le_bytes());
            }

            bytes. extend_from_slice(&offset_hashes.to_le_bytes());
            bytes.extend_from_slice(&path_bytes);
            bytes.extend_from_slice(&hashes_bytes);

            bytes
        }

        /// Serialize HashTreeOpening (path) to SSZ bytes
        /// HashTreeOpening SSZ layout:
        /// 1. offset (4 bytes) - always 4
        /// 2. co_path data (Vec<Domain>) - each Domain is 7 field elements = 28 bytes
        fn serialize_path(&self) -> Vec<u8> {
            let mut bytes = Vec::new();

            // HashTreeOpening has its own offset (always 4)
            let offset:  u32 = 4;
            bytes.extend_from_slice(&offset.to_le_bytes());

            // Each sibling is a Domain with 7 field elements (HASH_LEN_FE = 7)
            // But test vectors have 8 elements, take first 7
            let hash_len = 7;  // HASH_LEN_FE from leansig
            for sibling in &self. path. siblings. data {
                for i in 0..hash_len {
                    let fe = sibling. data.get(i).copied().unwrap_or(0);
                    bytes.extend_from_slice(&(fe as u32).to_le_bytes());
                }
            }
            bytes
        }

        /// Serialize hashes (Vec<Domain>) to SSZ bytes
        /// Each Domain is 7 field elements = 28 bytes
        fn serialize_hashes(&self) -> Vec<u8> {
            let mut bytes = Vec:: new();
            let hash_len = 7;  // HASH_LEN_FE from leansig
            for hash in &self. hashes.data {
                for i in 0..hash_len {
                    let fe = hash.data.get(i).copied().unwrap_or(0);
                    bytes.extend_from_slice(&(fe as u32).to_le_bytes());
                }
            }
            bytes
        }
    }

    fn signature_from_bytes(bytes: &[u8]) -> Signature {
        let mut padded = [0u8; SIG_SIZE];
        let copy_len = bytes.len().min(SIG_SIZE);
        padded[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let mut byte_vec:  ByteVector<U3112> = ByteVector::default();
        unsafe {
            let dest = &mut byte_vec as *mut ByteVector<U3112> as *mut u8;
            std:: ptr::copy_nonoverlapping(padded.as_ptr(), dest, SIG_SIZE);
        }
        byte_vec
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BlockSignatures, D:: Error>
    where
        D:  Deserializer<'de>,
    {
        use serde::de::Error;

        let sig_block = SignatureBlockJson:: deserialize(deserializer)?;
        let mut list = BlockSignatures:: default();

        // First add attestation signatures (flattened from aggregated attestations)
        for aggregated in sig_block.attestation_signatures.data {
            for sig_json in aggregated. data {
                let bytes = sig_json.to_ssz_bytes();
                let signature = signature_from_bytes(&bytes);
                list.push(signature)
                    .map_err(|e| D::Error::custom(format!("Failed to push attestation signature: {:?}", e)))?;
            }
        }

        // Then add proposer signature
        let proposer_bytes = sig_block. proposer_signature. to_ssz_bytes();
        let proposer_signature = signature_from_bytes(&proposer_bytes);
        list.push(proposer_signature)
            .map_err(|e| D::Error::custom(format! ("Failed to push proposer signature: {:? }", e)))?;

        Ok(list)
    }

    pub fn serialize<S>(value: &BlockSignatures, serializer: S) -> Result<S::Ok, S:: Error>
    where
        S:  Serializer,
    {
        use serde::ser::SerializeMap;

        let mut hex_sigs = Vec::new();
        let mut i = 0u64;
        loop {
            match value.get(i) {
                Ok(sig) => {
                    let bytes = unsafe {
                        std::slice::from_raw_parts(
                            &*sig as *const ByteVector<U3112> as *const u8,
                            SIG_SIZE
                        )
                    };
                    hex_sigs.push(format!("0x{}", hex::encode(bytes)));
                    i += 1;
                }
                Err(_) => break,
            }
        }

        let mut map = serializer. serialize_map(Some(1))?;
        map.serialize_entry("data", &hex_sigs)?;
        map.end()
    }
}

/// Flexible deserializer for attestations that handles both formats:
/// - Simple Attestation: { "validatorId": .. ., "data": ...  }
/// - AggregatedAttestation: { "aggregationBits": ..., "data": ... }
pub mod attestations {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use crate::attestation::{Attestation, AttestationData, Attestations};
    use crate::{Checkpoint, Slot, Uint64};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataWrapper<T> {
        data: T,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum AttestationJson {
        /// Simple attestation with validatorId
        Simple(SimpleAttestationJson),
        /// Aggregated attestation with aggregationBits
        Aggregated(AggregatedAttestationJson),
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SimpleAttestationJson {
        validator_id: u64,
        data: AttestationDataJson,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AggregatedAttestationJson {
        aggregation_bits:  AggregationBitsJson,
        data: AttestationDataJson,
    }

    #[derive(Deserialize)]
    struct AggregationBitsJson {
        data: Vec<bool>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AttestationDataJson {
        slot: u64,
        head:  CheckpointJson,
        target: CheckpointJson,
        source: CheckpointJson,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CheckpointJson {
        root: String,
        slot: u64,
    }

    impl CheckpointJson {
        fn to_checkpoint(&self) -> Checkpoint {
            use crate::types::Bytes32;
            let root_str = self.root. strip_prefix("0x").unwrap_or(&self.root);
            let root_bytes = hex::decode(root_str).unwrap_or_else(|_| vec![0u8; 32]);
            let mut arr = [0u8; 32];
            let len = root_bytes. len().min(32);
            arr[..len].copy_from_slice(&root_bytes[..len]);
            Checkpoint {
                root:  Bytes32(ssz:: H256:: from(arr)),
                slot: Slot(self.slot),
            }
        }
    }

    impl AttestationDataJson {
        fn to_attestation_data(&self) -> AttestationData {
            AttestationData {
                slot:  Slot(self.slot),
                head: self.head. to_checkpoint(),
                target: self. target.to_checkpoint(),
                source:  self.source.to_checkpoint(),
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Attestations, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let wrapper = DataWrapper::<Vec<AttestationJson>>::deserialize(deserializer)?;
        let mut list = Attestations::default();

        for att_json in wrapper. data {
            match att_json {
                AttestationJson::Simple(simple) => {
                    let attestation = Attestation {
                        validator_id:  Uint64(simple. validator_id),
                        data: simple.data.to_attestation_data(),
                    };
                    list.push(attestation)
                        .map_err(|e| D:: Error::custom(format!("Failed to push attestation: {:?}", e)))?;
                }
                AttestationJson::Aggregated(aggregated) => {
                    // Convert aggregated attestation to individual attestations
                    // Each true bit in aggregation_bits represents a validator
                    for (validator_id, &participated) in aggregated.aggregation_bits. data.iter().enumerate() {
                        if participated {
                            let attestation = Attestation {
                                validator_id: Uint64(validator_id as u64),
                                data: aggregated. data.to_attestation_data(),
                            };
                            list.push(attestation)
                                .map_err(|e| D::Error::custom(format!("Failed to push attestation: {:?}", e)))?;
                        }
                    }
                }
            }
        }

        Ok(list)
    }

    pub fn serialize<S>(value: &Attestations, serializer: S) -> Result<S::Ok, S:: Error>
    where
        S:  Serializer,
    {
        use serde::ser:: SerializeMap;

        // Serialize as simple attestations in {"data": [... ]} format
        let mut attestations_vec = Vec::new();
        let mut i = 0u64;
        loop {
            match value.get(i) {
                Ok(att) => {
                    attestations_vec.push(att.clone());
                    i += 1;
                }
                Err(_) => break,
            }
        }

        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("data", &attestations_vec)?;
        map.end()
    }
}