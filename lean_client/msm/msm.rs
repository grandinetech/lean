// Re-export MSM implementation files
pub mod strassen {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/msm/strassen.rs"));
}
