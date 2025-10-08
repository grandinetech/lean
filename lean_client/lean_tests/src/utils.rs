use std::path::Path;
use anyhow::anyhow;
use snap::raw::Decoder;

pub fn read_snappy_compressed(path: &Path) -> anyhow::Result<Vec<u8>> {
    let ssz_snappy = std::fs::read(path)?;
    let mut decoder = Decoder::new();
    decoder.decompress_vec(&ssz_snappy).map_err(|e| anyhow!("Failed to decompress: {:?}", e))
}