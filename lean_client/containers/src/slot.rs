use serde::{Deserialize, Serialize};
use ssz::Ssz;
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ssz, Default, Serialize, Deserialize)]
pub struct Slot(pub u64);

impl PartialOrd for Slot {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Slot {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl Slot {
    /// Checks if this slot is a valid candidate for justification after a given finalized slot.
    ///
    /// According to the 3SF-mini specification, a slot is justifiable if its
    /// distance (`delta`) from the last finalized slot is:
    ///   1. Less than or equal to 5.
    ///   2. A perfect square (e.g., 9, 16, 25...).
    ///   3. A pronic number (of the form x^2 + x, e.g., 6, 12, 20...).
    ///
    /// # Arguments
    ///
    /// * `finalized_slot` - The last slot that was finalized.
    ///
    /// # Returns
    ///
    /// True if the slot is justifiable, False otherwise.
    ///
    /// # Panics
    ///
    /// Panics if this slot is earlier than the finalized slot.
    pub fn is_justifiable_after(self, finalized: Slot) -> bool {
        assert!(
            self >= finalized,
            "Candidate slot must not be before finalized slot"
        );
        let delta = self.0 - finalized.0;

        // Rule 1: The first 5 slots after finalization are always justifiable.
        // Examples: delta = 0, 1, 2, 3, 4, 5
        if delta <= 5 {
            return true;
        }

        // Rule 2: Slots at perfect square distances are justifiable.
        // Examples: delta = 1, 4, 9, 16, 25, 36, 49, 64, ...
        // Check: integer square root squared equals delta
        let sqrt = (delta as f64).sqrt() as u64;
        if sqrt * sqrt == delta {
            return true;
        }

        // Rule 3: Slots at pronic number distances are justifiable.
        // Pronic numbers have the form n(n+1): 2, 6, 12, 20, 30, 42, 56, ...
        // Mathematical insight: For pronic delta = n(n+1), we have:
        //   4*delta + 1 = 4n(n+1) + 1 = (2n+1)^2
        // Check: 4*delta+1 is an odd perfect square
        let test = 4 * delta + 1;
        let test_sqrt = (test as f64).sqrt() as u64;
        if test_sqrt * test_sqrt == test && test_sqrt % 2 == 1 {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_justifiable_first_five() {
        let finalized = Slot(100);
        // Rule 1: First 5 slots are justifiable
        assert!(Slot(100).is_justifiable_after(finalized)); // delta = 0
        assert!(Slot(101).is_justifiable_after(finalized)); // delta = 1
        assert!(Slot(102).is_justifiable_after(finalized)); // delta = 2
        assert!(Slot(103).is_justifiable_after(finalized)); // delta = 3
        assert!(Slot(104).is_justifiable_after(finalized)); // delta = 4
        assert!(Slot(105).is_justifiable_after(finalized)); // delta = 5
    }

    #[test]
    fn test_is_justifiable_perfect_squares() {
        let finalized = Slot(0);
        // Rule 2: Perfect square distances
        assert!(Slot(1).is_justifiable_after(finalized)); // delta = 1 = 1^2
        assert!(Slot(4).is_justifiable_after(finalized)); // delta = 4 = 2^2
        assert!(Slot(9).is_justifiable_after(finalized)); // delta = 9 = 3^2
        assert!(Slot(16).is_justifiable_after(finalized)); // delta = 16 = 4^2
        assert!(Slot(25).is_justifiable_after(finalized)); // delta = 25 = 5^2
        assert!(Slot(36).is_justifiable_after(finalized)); // delta = 36 = 6^2
    }

    #[test]
    fn test_is_justifiable_pronic() {
        let finalized = Slot(0);
        // Rule 3: Pronic numbers (n(n+1))
        assert!(Slot(2).is_justifiable_after(finalized)); // delta = 2 = 1*2
        assert!(Slot(6).is_justifiable_after(finalized)); // delta = 6 = 2*3
        assert!(Slot(12).is_justifiable_after(finalized)); // delta = 12 = 3*4
        assert!(Slot(20).is_justifiable_after(finalized)); // delta = 20 = 4*5
        assert!(Slot(30).is_justifiable_after(finalized)); // delta = 30 = 5*6
        assert!(Slot(42).is_justifiable_after(finalized)); // delta = 42 = 6*7
    }

    #[test]
    fn test_is_not_justifiable() {
        let finalized = Slot(0);
        // Not justifiable: not in first 5, not perfect square, not pronic
        assert!(!Slot(7).is_justifiable_after(finalized)); // delta = 7
        assert!(!Slot(8).is_justifiable_after(finalized)); // delta = 8
        assert!(!Slot(10).is_justifiable_after(finalized)); // delta = 10
        assert!(!Slot(11).is_justifiable_after(finalized)); // delta = 11
    }

    #[test]
    #[should_panic(expected = "Candidate slot must not be before finalized slot")]
    fn test_is_justifiable_panics_on_past_slot() {
        let finalized = Slot(100);
        let candidate = Slot(50);
        candidate.is_justifiable_after(finalized);
    }
}
