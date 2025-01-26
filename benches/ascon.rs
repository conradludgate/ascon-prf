use divan::{black_box, counter::BytesCount, Bencher};

use ascon_prng::{ascon_prf_short_128, AsconPrf};
use rand_core::{block::BlockRng64, RngCore};

fn main() {
    // Run registered benchmarks.
    divan::main();
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn init() -> AsconPrf {
    AsconPrf::init(black_box([0; 16]))
}

#[divan::bench(args = [1, 2, 4, 16, 256, 4096], sample_count=1000, sample_size=1000)]
fn feed(b: Bencher, len: usize) {
    let v = vec![0u8; len];
    let prf = AsconPrf::init([0; 16]);
    b.counter(BytesCount::of_slice(&v))
        .bench(|| prf.clone().feed(&v));
}

#[divan::bench(args = [1, 2, 4, 16, 256, 4096], sample_count=1000, sample_size=1000)]
fn fetch(b: Bencher, len: usize) {
    let mut v = vec![0u8; len];
    let prf = BlockRng64::new(AsconPrf::init([0; 16]));
    b.counter(BytesCount::of_slice(&v))
        .bench_local(|| prf.clone().fill_bytes(&mut v));
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn short() -> [u8; 16] {
    ascon_prf_short_128(black_box([0; 16]), &black_box([0; 16]))
}
