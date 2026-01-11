#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BasisPoint(pub u64);

impl BasisPoint {
    pub const MAX: u64 = 10_000;

    pub const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAX {
            Some(BasisPoint(value))
        } else {
            None
        }
    }
    #[inline]
    pub fn get(&self) -> u64 {
        self.0
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub intervals_per_slot: u64,
    pub slot_duration_ms: u64,
    pub second_per_slot: u64,
    pub seconds_per_interval: u64,
    pub justification_lookback_slots: u64,
    pub proposer_reorg_cutoff_bps: BasisPoint,
    pub vote_due_bps: BasisPoint,
    pub fast_confirm_due_bps: BasisPoint,
    pub view_freeze_cutoff_bps: BasisPoint,
    pub historical_roots_limit: u64,
    pub validator_registry_limit: u64,
}

impl ChainConfig {
    pub fn devnet() -> Self {
        let slot_duration_ms = 4_000;
        let seconds_per_slot = slot_duration_ms / 1_000;
        let intervals_per_slot = 4;

        Self {
            slot_duration_ms,
            second_per_slot: seconds_per_slot,
            intervals_per_slot,
            seconds_per_interval: seconds_per_slot / intervals_per_slot,
            justification_lookback_slots: 3,
            proposer_reorg_cutoff_bps: BasisPoint::new(2_500).expect("Valid BPS"),
            vote_due_bps: BasisPoint::new(5_000).expect("Valid BPS"),
            fast_confirm_due_bps: BasisPoint::new(7_500).expect("Valid BPS"),
            view_freeze_cutoff_bps: BasisPoint::new(7_500).expect("Valid BPS"),
            historical_roots_limit: 1u64 << 18,
            validator_registry_limit: 1u64 << 12,
        }
    }
}
