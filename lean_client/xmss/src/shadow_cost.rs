//! Shadow-simulator sim-cost + fake-proof backend. Compiled only under the
//! `shadow_mode` cfg.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

pub const DEFAULT_FAKE_PROOF_SIZE: usize = 32 * 1024;

static FAKE_ENABLED: AtomicBool = AtomicBool::new(false);
static AGG_RATE: AtomicU64 = AtomicU64::new(0);
static VERIFY_RATE: AtomicU64 = AtomicU64::new(0);
static MERGE_RATE: AtomicU64 = AtomicU64::new(0);
static FAKE_PROOF_SIZE: AtomicUsize = AtomicUsize::new(DEFAULT_FAKE_PROOF_SIZE);

fn rate_bits(v: Option<f64>) -> u64 {
    match v {
        Some(v) if v.is_finite() && v > 0.0 => v.to_bits(),
        _ => 0,
    }
}

pub fn init(
    fake: bool,
    agg: Option<f64>,
    verify: Option<f64>,
    merge: Option<f64>,
    proof_size: usize,
) {
    FAKE_ENABLED.store(fake, Ordering::Relaxed);
    AGG_RATE.store(rate_bits(agg), Ordering::Relaxed);
    VERIFY_RATE.store(rate_bits(verify), Ordering::Relaxed);
    MERGE_RATE.store(rate_bits(merge), Ordering::Relaxed);
    FAKE_PROOF_SIZE.store(proof_size, Ordering::Relaxed);
}

pub fn fake_xmss() -> bool {
    FAKE_ENABLED.load(Ordering::Relaxed)
}

pub fn fake_proof_size() -> usize {
    FAKE_PROOF_SIZE.load(Ordering::Relaxed)
}

fn compute_delay(rate: &AtomicU64, n: usize) -> Duration {
    let r = f64::from_bits(rate.load(Ordering::Relaxed));
    if r <= 0.0 || n == 0 {
        return Duration::ZERO;
    }
    let ns = (n as f64 / r) * 1e9;
    if !ns.is_finite() || ns <= 0.0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(ns.min(u64::MAX as f64) as u64)
}

pub fn aggregate_delay(n: usize) -> Duration {
    compute_delay(&AGG_RATE, n)
}

pub fn verify_delay(n: usize) -> Duration {
    compute_delay(&VERIFY_RATE, n)
}

pub fn merge_delay(n: usize) -> Duration {
    compute_delay(&MERGE_RATE, n)
}

pub fn sleep(delay: Duration) {
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
}

pub fn fill_fake_proof(len: usize, seed_parts: &[&[u8]]) -> Vec<u8> {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut state = FNV_OFFSET_BASIS;
    for part in seed_parts {
        for &byte in *part {
            state ^= u64::from(byte);
            state = state.wrapping_mul(FNV_PRIME);
        }
    }

    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let z = state.wrapping_add(0x9E3779B97F4A7C15);
        state = z;
        let z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        let z = z ^ (z >> 31);

        let chunk = z.to_le_bytes();
        let remaining = len - bytes.len();
        bytes.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
    }

    bytes
}
