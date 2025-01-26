use divan::{black_box, counter::BytesCount, Bencher};

use ascon_prng::{ascon_prf_short_128, AsconMac, AsconPrf, AsconPrng};
use rand_core::{block::BlockRng64, RngCore, SeedableRng};

fn main() {
    // Run registered benchmarks.
    divan::main();
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn prng_init() -> AsconPrng {
    AsconPrng::from_seed(black_box([0; 16]))
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn prng_feed(b: Bencher) {
    let prng = AsconPrng::from_seed([0; 16]);
    b.counter(BytesCount::new(32_u64))
        .bench(|| prng.clone().feed(&black_box([0; 32])));
}

#[divan::bench(args = [1, 2, 4, 16, 256, 4096], sample_count=1000, sample_size=1000)]
fn prng_fetch(b: Bencher, len: usize) {
    let mut v = vec![0u8; len];
    let prng = BlockRng64::new(AsconPrng::from_seed([0; 16]));
    b.counter(BytesCount::of_slice(&v))
        .bench_local(|| prng.clone().fill_bytes(&mut v));
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn prf_init() -> AsconPrf {
    use digest::KeyInit;
    AsconPrf::new(&black_box([0; 16]).into())
}

#[divan::bench(args = [1, 2, 4, 16, 256, 4096], sample_count=1000, sample_size=1000)]
fn prf_update(b: Bencher, len: usize) {
    use digest::{KeyInit, Update};

    let v = vec![0u8; len];
    let prf = AsconPrf::new(&[0; 16].into());
    b.counter(BytesCount::of_slice(&v))
        .bench(|| prf.clone().chain(black_box(&v)));
}

#[divan::bench(args = [1, 2, 4, 16, 256, 4096], sample_count=1000, sample_size=1000)]
fn prf_xof_read(b: Bencher, len: usize) {
    use digest::{ExtendableOutput, KeyInit, XofReader};

    let mut v = vec![0u8; len];
    let xof = AsconPrf::new(&[0; 16].into()).finalize_xof();
    b.counter(BytesCount::of_slice(&v))
        .bench_local(|| black_box(xof.clone()).read(&mut v));
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn prf_short() -> [u8; 16] {
    ascon_prf_short_128(black_box([0; 16]), &black_box([0; 16]))
}

#[divan::bench(args = [1, 2, 4, 16, 256, 4096], sample_count=1000, sample_size=1000)]
fn mac(b: Bencher, len: usize) {
    use digest::Mac;

    let v = vec![0u8; len];
    b.counter(BytesCount::of_slice(&v)).bench(|| -> [u8; 16] {
        AsconMac::new(&black_box([0; 16]).into())
            .chain_update(&v)
            .finalize()
            .into_bytes()
            .into()
    });
}
