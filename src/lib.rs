//! # Ascon-PRNG
//!
//! A Psuedo Random Function and [`CryptoRng`](rand_core::CryptoRng) based on [Ascon](ascon).
//!
//! Based on these papers:
//!
//! Ascon MAC, PRF, and Short-Input PRF
//! Lightweight, Fast, and Efficient Pseudorandom Functions
//! <https://eprint.iacr.org/2021/1574>
//!
//! Sponge-based pseudo-random number generators
//! <https://keccak.team/files/SpongePRNG.pdf>
//!
//! This crate has not been audited. Use at your own risk.
#![no_std]

mod prf;
use ascon::State;
use digest::{
    array::Array,
    consts::{U16, U32},
};
pub use prf::{
    ascon_prf_short, ascon_prf_short_128, AsconPrf, AsconPrfCore, AsconPrfReader,
    AsconPrfReaderCore,
};

mod mac;
pub use mac::{AsconMac, AsconMacCore};

mod prng;
pub use prng::{AsconPrng, AsconPrngCore};

type B<N> = Array<u8, N>;

/// Little-endian word from exactly 8 bytes.
fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
}

fn init(iv: u64, key: &B<U16>) -> State {
    let mut state = [iv, word(&key[..8]), word(&key[8..]), 0, 0];
    ascon::permute12(&mut state);
    state
}

fn compress(s: &mut State, x: &B<U32>, last: u64) {
    s[0] ^= word(&x[..8]);
    s[1] ^= word(&x[8..16]);
    s[2] ^= word(&x[16..24]);
    s[3] ^= word(&x[24..]);
    s[4] ^= last;
    ascon::permute12(s);
}

fn extract(s: &State, b: &mut B<U16>) {
    b[..8].copy_from_slice(&s[0].to_le_bytes());
    b[8..].copy_from_slice(&s[1].to_le_bytes());
}
