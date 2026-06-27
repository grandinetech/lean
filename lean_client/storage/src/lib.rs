use database::{Database, DatabaseMode, RestartMessage};

const BLOCKS_TABLE_NAME: &str = "blocks";

const BLOCKS_CREATE_INDEX: &str = "slots_to_block_roots_index";

const STATES_TABLE_NAME: &str = "states";

const STATES_CREATE_INDEX: &str = "slots_to_state_roots_index";

const CHECKPOINTS_TABLE_NAME: &str = "checkpoints";

const CHECKPOINTS_KEY_JUSTIFIED: &str = "justified";

const CHECKPOINTS_KEY_FINALIZED: &str = "finalized";

const CHECKPOINTS_KEY_HEAD: &str = "head";

const CHECKPOINTS_KEY_GENESIS_TIME: &str = "genesis_time";

const SLOT_INDEX_TABLE_NAME: &str = "slot_index";

const STATE_ROOT_INDEX_TABLE_NAME: &str = "state_root_index";

