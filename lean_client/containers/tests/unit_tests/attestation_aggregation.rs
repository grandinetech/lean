#[cfg(test)]
mod tests {
    use containers::attestation::{
        AggregatedAttestation, AggregationBits, Attestation, AttestationData,
    };
    use containers::checkpoint::Checkpoint;
    use containers::slot::Slot;
    use containers::{Bytes32, Uint64};

    #[test]
    fn test_aggregated_attestation_structure() {
        let att_data = AttestationData {
            slot: Slot(5),
            head: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(4),
            },
            target: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(3),
            },
            source: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(2),
            },
        };

        let bits = AggregationBits::from_validator_indices(&vec![2, 7]);
        let agg = AggregatedAttestation {
            aggregation_bits: bits.clone(),
            data: att_data.clone(),
        };

        let indices = agg.aggregation_bits.to_validator_indices();
        assert_eq!(
            indices
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            vec![2, 7].into_iter().collect()
        );
        assert_eq!(agg.data, att_data);
    }

    #[test]
    fn test_aggregate_attestations_by_common_data() {
        let att_data1 = AttestationData {
            slot: Slot(5),
            head: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(4),
            },
            target: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(3),
            },
            source: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(2),
            },
        };
        let att_data2 = AttestationData {
            slot: Slot(6),
            head: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(5),
            },
            target: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(4),
            },
            source: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(3),
            },
        };

        let attestations = vec![
            Attestation {
                validator_id: Uint64(1),
                data: att_data1.clone(),
            },
            Attestation {
                validator_id: Uint64(3),
                data: att_data1.clone(),
            },
            Attestation {
                validator_id: Uint64(5),
                data: att_data2.clone(),
            },
        ];

        let aggregated = AggregatedAttestation::aggregate_by_data(&attestations);
        assert_eq!(aggregated.len(), 2);

        let agg1 = aggregated.iter().find(|agg| agg.data == att_data1).unwrap();
        let validator_ids1 = agg1.aggregation_bits.to_validator_indices();
        assert_eq!(
            validator_ids1
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            vec![1, 3].into_iter().collect()
        );

        let agg2 = aggregated.iter().find(|agg| agg.data == att_data2).unwrap();
        let validator_ids2 = agg2.aggregation_bits.to_validator_indices();
        assert_eq!(validator_ids2, vec![5]);
    }

    #[test]
    fn test_aggregate_empty_attestations() {
        let aggregated = AggregatedAttestation::aggregate_by_data(&[]);
        assert!(aggregated.is_empty());
    }

    #[test]
    fn test_aggregate_single_attestation() {
        let att_data = AttestationData {
            slot: Slot(5),
            head: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(4),
            },
            target: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(3),
            },
            source: Checkpoint {
                root: Bytes32::default(),
                slot: Slot(2),
            },
        };

        let attestations = vec![Attestation {
            validator_id: Uint64(5),
            data: att_data.clone(),
        }];
        let aggregated = AggregatedAttestation::aggregate_by_data(&attestations);

        assert_eq!(aggregated.len(), 1);
        let validator_ids = aggregated[0].aggregation_bits.to_validator_indices();
        assert_eq!(validator_ids, vec![5]);
    }
}
