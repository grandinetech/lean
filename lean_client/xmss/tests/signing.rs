use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use ssz::H256;
use xmss::SecretKey;

#[test]
pub fn sign_verify_roundtrip() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let (public_key, private_key) = SecretKey::generate_key_pair(&mut rng, 0, 1);

    let sig = private_key.sign(H256::zero(), 0).unwrap();

    sig.verify(&public_key, 0, H256::zero()).unwrap();
}
