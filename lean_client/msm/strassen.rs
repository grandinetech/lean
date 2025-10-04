#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct TestFr(u64);
    impl Fr for TestFr {
        fn null() -> Self {
            Self(0)
        }
        fn zero() -> Self {
            Self(0)
        }
        fn one() -> Self {
            Self(1)
        }
        #[cfg(feature = "rand")]
        fn rand() -> Self {
            Self(1)
        }
        fn from_bytes(_bytes: &[u8]) -> Result<Self, String> {
            Err("not implemented".into())
        }
        fn from_hex(_hex: &str) -> Result<Self, String> {
            Err("not implemented".into())
        }
        fn from_u64_arr(_u: &[u64; 4]) -> Self {
            Self(0)
        }
        fn from_u64(u: u64) -> Self {
            Self(u)
        }
        fn to_bytes(&self) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&self.0.to_le_bytes());
            b
        }
        fn to_u64_arr(&self) -> [u64; 4] {
            [self.0, 0, 0, 0]
        }
        fn is_one(&self) -> bool {
            self.0 == 1
        }
        fn is_zero(&self) -> bool {
            self.0 == 0
        }
        fn is_null(&self) -> bool {
            self.0 == 0
        }
        fn sqr(&self) -> Self {
            Self(self.0 * self.0)
        }
        fn mul(&self, b: &Self) -> Self {
            Self(self.0 * b.0)
        }
        fn add(&self, b: &Self) -> Self {
            Self(self.0 + b.0)
        }
        fn sub(&self, b: &Self) -> Self {
            Self(self.0 - b.0)
        }
        fn eucl_inverse(&self) -> Self {
            Self(0)
        }
        fn negate(&self) -> Self {
            Self(0u64.wrapping_sub(self.0))
        }
        fn inverse(&self) -> Self {
            Self(0)
        }
        fn pow(&self, _n: usize) -> Self {
            Self(0)
        }
        fn div(&self, _b: &Self) -> Result<Self, String> {
            Ok(Self(0))
        }
        fn equals(&self, b: &Self) -> bool {
            self.0 == b.0
        }
        fn to_scalar(&self) -> Scalar256 {
            Scalar256::from_u64_s(self.0)
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct TestFp(u64);
    impl G1Fp for TestFp {
        fn zero() -> Self {
            Self(0)
        }
        fn one() -> Self {
            Self(1)
        }
        fn bls12_381_rx_p() -> Self {
            Self(1)
        }
        fn inverse(&self) -> Option<Self> {
            Some(*self)
        }
        fn square(&self) -> Self {
            Self(self.0 * self.0)
        }
        fn double(&self) -> Self {
            Self(self.0 * 2)
        }
        fn from_underlying_arr(_: &[u64; 6]) -> Self {
            Self(0)
        }
        fn mul3(&self) -> Self {
            Self(self.0 * 3)
        }
        fn neg_assign(&mut self) {
            *self = Self(0u64.wrapping_sub(self.0))
        }
        fn mul_assign_fp(&mut self, b: &Self) {
            self.0 = self.0.wrapping_mul(b.0)
        }
        fn sub_assign_fp(&mut self, b: &Self) {
            self.0 = self.0.wrapping_sub(b.0)
        }
        fn add_assign_fp(&mut self, b: &Self) {
            self.0 = self.0.wrapping_add(b.0)
        }
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct TestG1 {
        v: u64,
        x: TestFp,
        y: TestFp,
        z: TestFp,
    }
    impl G1 for TestG1 {
        fn zero() -> Self {
            Self {
                v: 0,
                x: TestFp(0),
                y: TestFp(0),
                z: TestFp(0),
            }
        }
        fn identity() -> Self {
            Self::zero()
        }
        fn generator() -> Self {
            Self {
                v: 1,
                x: TestFp(1),
                y: TestFp(1),
                z: TestFp(1),
            }
        }
        fn negative_generator() -> Self {
            Self::generator()
        }
        #[cfg(feature = "rand")]
        fn rand() -> Self {
            Self::generator()
        }
        fn from_bytes(_: &[u8]) -> Result<Self, String> {
            Err("not implemented".into())
        }
        fn from_hex(_: &str) -> Result<Self, String> {
            Err("not implemented".into())
        }
        fn to_bytes(&self) -> [u8; 48] {
            [0u8; 48]
        }
        fn add_or_dbl(&self, b: &Self) -> Self {
            Self {
                v: self.v + b.v,
                x: self.x,
                y: self.y,
                z: self.z,
            }
        }
        fn is_inf(&self) -> bool {
            self.v == 0
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn dbl(&self) -> Self {
            Self {
                v: self.v * 2,
                x: self.x,
                y: self.y,
                z: self.z,
            }
        }
        fn add(&self, b: &Self) -> Self {
            Self {
                v: self.v + b.v,
                x: self.x,
                y: self.y,
                z: self.z,
            }
        }
        fn sub(&self, b: &Self) -> Self {
            Self {
                v: self.v - b.v,
                x: self.x,
                y: self.y,
                z: self.z,
            }
        }
        fn equals(&self, b: &Self) -> bool {
            self.v == b.v
        }
        fn add_or_dbl_assign(&mut self, b: &Self) {
            self.v = self.v.wrapping_add(b.v)
        }
        fn add_assign(&mut self, b: &Self) {
            self.v = self.v.wrapping_add(b.v)
        }
        fn dbl_assign(&mut self) {
            self.v = self.v.wrapping_mul(2)
        }
    }

    impl G1GetFp<TestFp> for TestG1 {
        fn x(&self) -> &TestFp {
            &self.x
        }
        fn y(&self) -> &TestFp {
            &self.y
        }
        fn z(&self) -> &TestFp {
            &self.z
        }
        fn x_mut(&mut self) -> &mut TestFp {
            &mut self.x
        }
        fn y_mut(&mut self) -> &mut TestFp {
            &mut self.y
        }
        fn z_mut(&mut self) -> &mut TestFp {
            &mut self.z
        }
    }

    impl G1Mul<TestFr> for TestG1 {
        fn mul(&self, b: &TestFr) -> Self {
            Self {
                v: self.v.wrapping_mul(b.0),
                x: self.x,
                y: self.y,
                z: self.z,
            }
        }
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq, Copy)]
    struct TestG1Affine(TestFp, TestFp);
    impl G1Affine<TestG1, TestFp> for TestG1Affine {
        fn zero() -> Self {
            Self(TestFp(0), TestFp(0))
        }
        fn from_xy(x: TestFp, y: TestFp) -> Self {
            Self(x, y)
        }
        fn into_affine(_: &TestG1) -> Self {
            Self(TestFp(0), TestFp(0))
        }
        fn into_affines_loc(_: &mut [Self], _: &[TestG1]) {}
        fn to_proj(&self) -> TestG1 {
            TestG1::zero()
        }
        fn x(&self) -> &TestFp {
            &self.0
        }
        fn y(&self) -> &TestFp {
            &self.1
        }
        fn x_mut(&mut self) -> &mut TestFp {
            &mut (self.0)
        }
        fn y_mut(&mut self) -> &mut TestFp {
            &mut (self.1)
        }
        fn is_infinity(&self) -> bool {
            false
        }
        fn neg(&self) -> Self {
            *self
        }
    }

    struct TestProjAdd;
    impl G1ProjAddAffine<TestG1, TestFp, TestG1Affine> for TestProjAdd {
        fn add_assign_affine(_: &mut TestG1, _: &TestG1Affine) {}
        fn add_or_double_assign_affine(_: &mut TestG1, _: &TestG1Affine) {}
    }

    #[test]
    fn straus_unwindowed_matches_naive_for_small_n() {
        for n in 1..7 {
            let mut points: Vec<TestG1> = Vec::new();
            let mut scalars: Vec<TestFr> = Vec::new();
            for i in 0..n {
                points.push(TestG1 {
                    v: (i as u64) + 2,
                    x: TestFp(0),
                    y: TestFp(0),
                    z: TestFp(0),
                });
                scalars.push(TestFr((i as u64) + 3));
            }
            let res =
                straus_unwindowed::<TestG1, TestFp, TestG1Affine, TestFr>(&points, &scalars, n);
            let mut expect = TestG1::zero();
            for i in 0..n {
                let tmp = points[i].mul(&scalars[i]);
                expect.add_or_dbl_assign(&tmp);
            }
            assert_eq!(res.v, expect.v, "n = {}", n);
        }
    }
}

// Straus (joint) unwindowed multi-scalar multiplication for small counts (n < 8).
fn straus_unwindowed<
    TG1: G1 + G1GetFp<TG1Fp> + G1Mul<TFr>,
    TG1Fp: G1Fp,
    TG1Affine: G1Affine<TG1, TG1Fp>,
    TFr: Fr,
>(
    points: &[TG1],
    scalars: &[TFr],
    len: usize,
) -> TG1 {
    let mut svals: Vec<crate::Scalar256> = Vec::with_capacity(len);
    for i in 0..len {
        svals.push(scalars[i].to_scalar());
    }
    let mut max_bit: isize = -1;
    for s in &svals {
        for limb in (0..4).rev() {
            let v = s.data[limb];
            if v != 0 {
                let leading = 63 - v.leading_zeros() as usize;
                let bit = (limb * 64 + leading) as isize;
                if bit > max_bit {
                    max_bit = bit;
                }
                break;
            }
        }
    }
    if max_bit < 0 {
        return TG1::zero();
    }
    let n = len;
    let table_size = 1usize << n;
    let mut table: Vec<TG1> = Vec::with_capacity(table_size);
    table.push(TG1::zero());
    for mask in 1..table_size {
        let lb = mask.trailing_zeros() as usize;
        let prev = table[mask ^ (1 << lb)].clone();
        let mut cur = prev;
        cur.add_or_dbl_assign(&points[lb]);
        table.push(cur);
    }
    let mut out = TG1::zero();
    for b in (0..=max_bit as usize).rev() {
        out.dbl_assign();
        let mut mask = 0usize;
        let limb = b / 64;
        let off = b % 64;
        for i in 0..n {
            if (svals[i].data[limb] >> off) & 1u64 == 1u64 {
                mask |= 1 << i;
            }
        }
        if mask != 0 {
            out.add_or_dbl_assign(&table[mask]);
        }
    }
    out
}

// Explanation:
// Straus (joint) unwindowed multi-scalar multiplication implementation.
//
// High level:
// - This routine computes sum_i (scalars[i] * points[i]) for small counts of
//   input points (the code expects n to be small; the test harness uses n < 8).
// - Each scalar is converted to a 256-bit-like `Scalar256` (4 x u64 limbs) and
//   examined bit-by-bit from the most significant set bit down to 0.
//
// Key steps:
// 1) Convert scalars -> `svals: Vec<Scalar256>` so we can access individual
//    64-bit limbs and test arbitrary bit positions.
// 2) Find `max_bit`: the index of the highest set bit across all scalars. If
//    no bits are set, the result is zero and the function returns early.
// 3) Build a precomputation table of size 2^n where table[mask] is the group
//    element equal to the sum of `points[j]` for each set bit j in `mask`.
//    The table is built incrementally using the relation
//      table[mask] = table[mask ^ (1 << lb)] + points[lb]
//    where `lb` is the index of the least-significant set bit of `mask`.
//    This dynamic construction costs O(2^n) group operations and avoids
//    recomputing subsets repeatedly.
// 4) Scan bits from `max_bit` down to 0. For each bit position `b`:
//    - Double the accumulator `out` (equivalent to shifting the current
//      accumulation by one bit of weight).
//    - Build a `mask` by checking each scalar's bit `b`. The code computes the
//      limb index (`b / 64`) and bit offset (`b % 64`) then inspects
//      `(svals[i].data[limb] >> off) & 1` to see if that scalar has bit `b` set.
//    - If the mask != 0, add the precomputed `table[mask]` to `out`.
//
// Properties, assumptions and notes:
// - Endianness/limb layout: this code assumes `Scalar256::data[0]` is the
//   least-significant 64-bit limb and `data[3]` the most-significant limb.
//   `to_scalar()` on the scalar type must produce this layout for bit tests to
//   be correct (the test stubs do this by placing the u64 into limb 0).
// - Intended for small n because the table is size 2^n. For n >= 8 the table
//   already grows to 256 entries; for larger n this becomes impractical.
// - Complexity: O(2^n) to build the table + O(B * n) to scan B bits (B is the
//   position of the highest set bit). For typical small n and small scalars
//   this is efficient and straightforward.
// - Correctness: the algorithm is the standard (unwindowed) Straus method.
//   It is functionally equivalent to computing each scalar*point and adding the
//   results but reduces repeated doublings/additions by using the precomputed
//   subset table and shared bit scanning.
// - Edge cases:
//   - If all scalars are zero the function returns `TG1::zero()` immediately.
//   - The code uses `usize` to store masks (1 << i). That limits n to at most
//     the machine word size; practically n should be << 64 and the design here
//     expects n small (tests use up to 6).
//   - The group operations (`add_or_dbl_assign`, `dbl_assign`, etc.) are used
//     generically via the `G1` trait and must behave correctly for the caller's
//     group type.
//
// This comment should help future maintainers understand the algorithm,
// performance trade-offs, and assumptions required for correct usage.
