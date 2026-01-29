use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use ssz::H256;
use xmss::{AggregatedSignature, SecretKey};

#[test]
fn aggregate_two() {
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let (public_key1, secret_key1) = SecretKey::generate_key_pair(&mut rng, 0, 1);
    let (public_key2, secret_key2) = SecretKey::generate_key_pair(&mut rng, 0, 1);

    let message = H256([1; 32]);

    let sig1 = secret_key1.sign(message.clone(), 0).unwrap();
    let sig2 = secret_key2.sign(message.clone(), 0).unwrap();

    let aggr_sig = AggregatedSignature::aggregate(
        vec![public_key1.clone(), public_key2.clone()],
        vec![sig1, sig2],
        message.clone(),
        0,
    )
    .unwrap();

    aggr_sig
        .verify(vec![public_key1, public_key2], message, 0)
        .unwrap();
}
