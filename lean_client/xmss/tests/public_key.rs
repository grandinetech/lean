use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use xmss::{PublicKey, SecretKey};

#[test]
pub fn display_parse_roundtrip() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let (public_key, _) = SecretKey::generate_key_pair(&mut rng, 0, 1);

    let str = public_key.to_string();
    let parsed = str.parse::<PublicKey>();

    assert!(parsed.is_ok());
    assert_eq!(parsed.unwrap(), public_key);
}
