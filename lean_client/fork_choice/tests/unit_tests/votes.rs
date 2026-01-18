// TODO: Add vote/attestation unit tests for devnet2
//
// This file previously contained devnet1 vote tests that are no longer compatible
// with the devnet2 SignedAttestation structure (validator_id is now a direct field,
// message is AttestationData instead of Attestation wrapper).
//
// Tests to implement:
// - test_single_vote_updates_head
// - test_multiple_votes_same_block
// - test_competing_votes_different_blocks
// - test_vote_weight_accumulation
// - test_vote_from_unknown_validator
// - test_duplicate_vote_ignored
// - test_vote_for_unknown_block
// - test_late_vote_still_counted
// - test_vote_changes_fork_choice
