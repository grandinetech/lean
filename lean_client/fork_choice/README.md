# Fork-choice
Implemented based on the [forkchoice.md](https://github.com/leanEthereum/leanSpec/blob/main/docs/client/forkchoice.md) client spec.

Tests taken from the [testing part of the repository](https://github.com/leanEthereum/leanSpec/tree/main/tests/lean_spec/subspecs/forkchoice).


# About our implementation fork-choice

## Helpers

`get_fork_choice_head`

`get_latest_justified`

`Store`

`get_forkchoice_store`

`update_head`

`update_safe_target`

`get_vote_target`

`accept_new_votes`

`tick_interval`

`get_proposal_head`

## Handlers
`on_tick`

`on_attestation`

`on_block`

