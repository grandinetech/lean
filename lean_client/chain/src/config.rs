#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BasisPoint(pub u64);

impl BasisPoint {
    pub const MAX: u64 = 10_000;
    pub const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAX { Some(BasisPoint(value)) } else { None }
    }
    #[inline] pub fn get(&self) -> u64 { self.0 }
}

pub const INTERVALS_PER_SLOT: u64 = 4;
pub const SLOT_DURATION_MS: u64 = 4_000;
pub const SECONDS_PER_SLOT: u64 = SLOT_DURATION_MS / 1_000;
pub const SECONDS_PER_INTERVAL: u64 = SECONDS_PER_SLOT / INTERVALS_PER_SLOT;
pub const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

pub const PROPOSER_REORG_CUTOFF_BPS: BasisPoint = match BasisPoint::new(2_500) { Some(x) => x, None => panic!() };
pub const VOTE_DUE_BPS: BasisPoint          = match BasisPoint::new(5_000) { Some(x) => x, None => panic!() };
pub const FAST_CONFIRM_DUE_BPS: BasisPoint  = match BasisPoint::new(7_500) { Some(x) => x, None => panic!() };
pub const VIEW_FREEZE_CUTOFF_BPS: BasisPoint= match BasisPoint::new(7_500) { Some(x) => x, None => panic!() };

pub const HISTORICAL_ROOTS_LIMIT: u64   = 1u64 << 18;
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 1u64 << 12;

#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub slot_duration_ms: u64,
    pub second_per_slot: u64,
    pub justification_lookback_slots: u64,
    pub proposer_reorg_cutoff_bps: BasisPoint,
    pub vote_due_bps: BasisPoint,
    pub fast_confirm_due_bps: BasisPoint,
    pub view_freeze_cutoff_bps: BasisPoint,
    pub historical_roots_limit: u64,
    pub validator_registry_limit: u64,
}

pub const DEVNET_CONFIG: ChainConfig = ChainConfig {
    slot_duration_ms: SLOT_DURATION_MS,
    second_per_slot: SECONDS_PER_SLOT,
    justification_lookback_slots: JUSTIFICATION_LOOKBACK_SLOTS,
    proposer_reorg_cutoff_bps: PROPOSER_REORG_CUTOFF_BPS,
    vote_due_bps: VOTE_DUE_BPS,
    fast_confirm_due_bps: FAST_CONFIRM_DUE_BPS,
    view_freeze_cutoff_bps: VIEW_FREEZE_CUTOFF_BPS,
    historical_roots_limit: HISTORICAL_ROOTS_LIMIT,
    validator_registry_limit: VALIDATOR_REGISTRY_LIMIT,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn time_math_is_consistent() {
        assert_eq!(SLOT_DURATION_MS, 4_000);
        assert_eq!(SECONDS_PER_SLOT, 4);
        assert_eq!(SECONDS_PER_INTERVAL, 1);
    }
}