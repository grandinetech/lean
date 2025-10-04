#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::{vec::Vec, string::String};
use core::fmt::Debug;

pub trait Fr: Default + Clone + PartialEq + Sync {
    fn null() -> Self;
    fn zero() -> Self;
    fn one() -> Self;
    #[cfg(feature = "rand")]
    fn rand() -> Self;
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>;
    fn from_hex(hex: &str) -> Result<Self, String>;
    fn from_u64_arr(u: &[u64; 4]) -> Self;
    fn from_u64(u: u64) -> Self;
    fn to_bytes(&self) -> [u8; 32];
    fn to_u64_arr(&self) -> [u64; 4];
    fn is_one(&self) -> bool;
    fn is_zero(&self) -> bool;
    fn is_null(&self) -> bool;
    fn sqr(&self) -> Self;
    fn mul(&self, b: &Self) -> Self;
    fn add(&self, b: &Self) -> Self;
    fn sub(&self, b: &Self) -> Self;
    fn eucl_inverse(&self) -> Self;
    fn negate(&self) -> Self;
    fn inverse(&self) -> Self;
    fn pow(&self, n: usize) -> Self;
    fn div(&self, b: &Self) -> Result<Self, String>;
    fn equals(&self, b: &Self) -> bool;
    fn to_scalar(&self) -> Scalar256;
}

pub trait G1: Clone + Default + PartialEq + Sync + Debug + Send {
    fn zero() -> Self;
    fn identity() -> Self;
    fn generator() -> Self;
    fn negative_generator() -> Self;
    #[cfg(feature = "rand")]
    fn rand() -> Self;
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>;
    fn from_hex(hex: &str) -> Result<Self, String>;
    fn to_bytes(&self) -> [u8; 48];
    fn add_or_dbl(&self, b: &Self) -> Self;
    fn is_inf(&self) -> bool;
    fn is_valid(&self) -> bool;
    fn dbl(&self) -> Self;
    fn add(&self, b: &Self) -> Self;
    fn sub(&self, b: &Self) -> Self;
    fn equals(&self, b: &Self) -> bool;
    fn add_or_dbl_assign(&mut self, b: &Self);
    fn add_assign(&mut self, b: &Self);
    fn dbl_assign(&mut self);
}

pub trait G1GetFp<TFp: G1Fp>: G1 + Clone {
    fn x(&self) -> &TFp;
    fn y(&self) -> &TFp;
    fn z(&self) -> &TFp;
    fn x_mut(&mut self) -> &mut TFp;
    fn y_mut(&mut self) -> &mut TFp;
    fn z_mut(&mut self) -> &mut TFp;
}

pub trait G1Mul<TFr: Fr>: G1 + Clone {
    fn mul(&self, b: &TFr) -> Self;
}

pub trait G1Fp: Clone + Default + Sync + Copy + PartialEq + Debug + Send {
    fn zero() -> Self;
    fn one() -> Self;
    fn bls12_381_rx_p() -> Self;
    fn inverse(&self) -> Option<Self>;
    fn square(&self) -> Self;
    fn double(&self) -> Self;
    fn from_underlying_arr(arr: &[u64; 6]) -> Self;
    fn mul3(&self) -> Self;
    fn neg_assign(&mut self);
    fn mul_assign_fp(&mut self, b: &Self);
    fn sub_assign_fp(&mut self, b: &Self);
    fn add_assign_fp(&mut self, b: &Self);
}

pub trait G1Affine<TG1: G1, TG1Fp: G1Fp>: Clone + Default + PartialEq + Sync + Copy + Send + Debug {
    fn zero() -> Self;
    fn from_xy(x: TG1Fp, y: TG1Fp) -> Self;
    fn into_affine(g1: &TG1) -> Self;
    fn into_affines_loc(out: &mut [Self], g1: &[TG1]);
    fn to_proj(&self) -> TG1;
    fn x(&self) -> &TG1Fp;
    fn y(&self) -> &TG1Fp;
    fn x_mut(&mut self) -> &mut TG1Fp;
    fn y_mut(&mut self) -> &mut TG1Fp;
    fn is_infinity(&self) -> bool;
    fn neg(&self) -> Self;
}

pub trait G1ProjAddAffine<TG1: G1, TG1Fp: G1Fp, TG1Affine: G1Affine<TG1, TG1Fp>>: Sized + Sync + Send {
    fn add_assign_affine(proj: &mut TG1, aff: &TG1Affine);
    fn add_or_double_assign_affine(proj: &mut TG1, aff: &TG1Affine);
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct Scalar256 { data: [u64; 4] }
impl Scalar256 { pub fn from_u64_s(u: u64) -> Self { Scalar256 { data: [u, 0, 0, 0] } } }

// include the test file
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../msm/strassen.rs"));
