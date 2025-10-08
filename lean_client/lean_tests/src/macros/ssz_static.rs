#[macro_export]
macro_rules! test_consensus_type {
    ($struct_name:ident) => {
        paste::paste! {
            #[cfg(test)]
            #[allow(non_snake_case)]
            mod [<tests_ $struct_name>] {
                use super::*;
                use rstest::rstest;
                use serde_yaml::Value;
                use snap::raw::Decoder;
                use std::str::FromStr;
                use containers::Block;

                #[rstest]
                #[case("case_0")]
                #[case("case_1")]
                #[case("case_2")]
                #[case("case_3")]
                #[case("case_4")]
                fn test_type(#[case] case: &str) {
                    let path = format!(
                        "mainnet/tests/mainnet/electra/ssz_static/{}/ssz_random/{case}/",
                        stringify!($struct_name)
                    );

                    // Read and parse hash root
                    let hash_root: Bytes32 = {
                        let root_content = std::fs::read_to_string(format!("{path}roots.yaml"))
                            .expect("cannot find test asset");
                        let value: Value = serde_yaml::from_str(&root_content).unwrap();
                        Bytes32::from_str(value.get("root").unwrap().as_str().unwrap()).unwrap()
                    };

                    // Deserialize the struct from YAML
                    let content: $struct_name = {
                        let yaml = std::fs::read_to_string(format!("{path}value.yaml"))
                            .expect("cannot find test asset");
                        serde_yaml::from_str(&yaml).unwrap()
                    };

                    // Read and decompress SSZ snappy
                    let ssz_snappy = std::fs::read(format!("{path}serialized.ssz_snappy"))
                        .expect("cannot find test asset");
                    let mut decoder = Decoder::new();
                    let ssz_bytes = decoder.decompress_vec(&ssz_snappy).unwrap();

                    // Perform assertions
                    assert_eq!(ssz_bytes, content.as_ssz_bytes());
                    assert_eq!(content, $struct_name::from_ssz_bytes(&ssz_bytes).unwrap());
                    assert_eq!(hash_root, containers::Block::hash_tree_root(&content));
                }
            }
        }
    };
}
