use containers::Slot;

const SLOTS_PER_EPOCH: u64 = 32;

pub trait JustifiableSlot {
    fn is_justifiable_after(&self, other: Slot) -> bool;
}

impl JustifiableSlot for Slot {
    fn is_justifiable_after(&self, other: Slot) -> bool {
        let self_epoch = self.0 / SLOTS_PER_EPOCH;
        let other_epoch = other.0 / SLOTS_PER_EPOCH;
        self.0 >= other.0 && (self_epoch == other_epoch || self_epoch == other_epoch + 1)
    }
}
