// // Tests generated using AI, manual changes coming...
// // We leave it like this for now, just use test vectors
// use containers::{Root, ValidatorIndex};
// use fork_choice::store::{get_fork_choice_head, Store};
// use std::collections::HashMap;
// mod common;
// use common::*;
//
// #[test]
// fn test_fc_no_votes_follows_longest_chain() {
//     let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");
//     let (block_a_root, block_a) = build_test_block(1, genesis_root, "block_a");
//     let (block_b_root, block_b) = build_test_block(2, block_a_root, "block_b");
//     let (block_c_root, block_c) = build_test_block(1, genesis_root, "block_c");
//
//     let store = Store {
//         blocks: HashMap::from([
//             (genesis_root, genesis_block),
//             (block_a_root, block_a),
//             (block_b_root, block_b),
//             (block_c_root, block_c),
//         ]),
//         ..Default::default()
//     };
//
//     let head = get_fork_choice_head(&store, genesis_root, &HashMap::new(), 0);
//
//     assert_eq!(head, block_b_root);
// }
//
// #[test]
// fn test_fc_single_vote_chooses_correct_head() {
//     let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");
//     let (block_a_root, block_a) = build_test_block(1, genesis_root, "block_a");
//     let (block_b_root, block_b) = build_test_block(2, block_a_root, "block_b");
//
//     let store = Store {
//         blocks: HashMap::from([
//             (genesis_root, genesis_block),
//             (block_a_root, block_a),
//             (block_b_root, block_b),
//         ]),
//         ..Default::default()
//     };
//
//     let votes = HashMap::from([(ValidatorIndex(0), build_checkpoint(block_b_root, 2))]);
//
//     let head = get_fork_choice_head(&store, genesis_root, &votes, 0);
//     assert_eq!(head, block_b_root);
// }
//
// #[test]
// fn test_fc_majority_vote_wins_over_minority() {
//     let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");
//     let (block_a_root, block_a) = build_test_block(1, genesis_root, "block_a");
//     let (block_b_root, block_b) = build_test_block(2, block_a_root, "block_b");
//
//     let (block_c_root, block_c) = build_test_block(1, genesis_root, "block_c");
//     let (block_d_root, block_d) = build_test_block(2, block_c_root, "block_d");
//
//     let store = Store {
//         blocks: HashMap::from([
//             (genesis_root, genesis_block),
//             (block_a_root, block_a),
//             (block_b_root, block_b),
//             (block_c_root, block_c),
//             (block_d_root, block_d),
//         ]),
//         ..Default::default()
//     };
//
//     let votes = HashMap::from([
//         (ValidatorIndex(0), build_checkpoint(block_d_root, 2)),
//         (ValidatorIndex(1), build_checkpoint(block_d_root, 2)),
//         (ValidatorIndex(2), build_checkpoint(block_b_root, 2)),
//     ]);
//
//     let head = get_fork_choice_head(&store, genesis_root, &votes, 0);
//     assert_eq!(head, block_d_root);
// }
//
// #[test]
// fn test_fc_tie_breaking_is_deterministic() {
//     let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");
//     let (block_a_root, block_a) = build_test_block(1, genesis_root, "block_a");
//     let (block_b_root, block_b) = build_test_block(1, genesis_root, "block_b");
//
//     let store = Store {
//         blocks: HashMap::from([
//             (genesis_root, genesis_block),
//             (block_a_root, block_a),
//             (block_b_root, block_b),
//         ]),
//         ..Default::default()
//     };
//
//     let votes = HashMap::from([
//         (ValidatorIndex(0), build_checkpoint(block_a_root, 1)),
//         (ValidatorIndex(1), build_checkpoint(block_b_root, 1)),
//     ]);
//
//     let expected_head = std::cmp::max(block_a_root, block_b_root);
//
//     let head1 = get_fork_choice_head(&store, genesis_root, &votes, 0);
//     let head2 = get_fork_choice_head(&store, genesis_root, &votes, 0);
//
//     assert_eq!(head1, expected_head);
//     assert_eq!(head1, head2, "Tie-breaking should be deterministic");
// }
//
// #[test]
// fn test_fc_ancestor_votes_are_counted() {
//     let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");
//     let (block_a_root, block_a) = build_test_block(1, genesis_root, "block_a");
//     let (block_b_root, block_b) = build_test_block(2, block_a_root, "block_b");
//     let (block_c_root, block_c) = build_test_block(3, block_b_root, "block_c");
//
//     let store = Store {
//         blocks: HashMap::from([
//             (genesis_root, genesis_block),
//             (block_a_root, block_a),
//             (block_b_root, block_b),
//             (block_c_root, block_c),
//         ]),
//         ..Default::default()
//     };
//
//     let votes = HashMap::from([(ValidatorIndex(0), build_checkpoint(block_a_root, 1))]);
//     let head = get_fork_choice_head(&store, genesis_root, &votes, 0);
//     assert_eq!(head, block_c_root);
// }
//
// #[test]
// fn test_fc_min_score_threshold() {
//     let (genesis_root, genesis_block) = build_test_block(0, Root::default(), "genesis");
//     let (block_a_root, block_a) = build_test_block(1, genesis_root, "block_a");
//
//     let store = Store {
//         blocks: HashMap::from([(genesis_root, genesis_block), (block_a_root, block_a)]),
//         ..Default::default()
//     };
//
//     let votes = HashMap::from([(ValidatorIndex(0), build_checkpoint(block_a_root, 1))]);
//     let min_score = 2;
//
//     let head = get_fork_choice_head(&store, genesis_root, &votes, min_score);
//
//     assert_eq!(head, genesis_root);
// }
