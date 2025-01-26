use divan::{black_box, counter::BytesCount, Bencher};

use ascon_prng::{ascon_prf_short_128, AsconMac, AsconPrng};
use rand_core::{block::BlockRng64, RngCore, SeedableRng};

fn main() {
    // Run registered benchmarks.
    divan::main();
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn prf_init() -> AsconPrng {
    AsconPrng::from_seed(black_box([0; 16]))
}

#[divan::bench(args = [1, 2, 4, 16, 256, 4096], sample_count=1000, sample_size=1000)]
fn prf_feed(b: Bencher, len: usize) {
    let v = vec![0u8; len];
    let prf = AsconPrng::from_seed([0; 16]);
    b.counter(BytesCount::of_slice(&v))
        .bench(|| prf.clone().feed(&v));
}

#[divan::bench(args = [1, 2, 4, 16, 256, 4096], sample_count=1000, sample_size=1000)]
fn prf_fetch(b: Bencher, len: usize) {
    let mut v = vec![0u8; len];
    let prf = BlockRng64::new(AsconPrng::from_seed([0; 16]));
    b.counter(BytesCount::of_slice(&v))
        .bench_local(|| prf.clone().fill_bytes(&mut v));
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
