//! # Ascon-PRNG
//!
//! A Psuedo Random Function and [`CryptoRng`] based on [Ascon](ascon).
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
use generic_array::{sequence::Split, GenericArray};
pub use prf::{ascon_prf_short, ascon_prf_short_128, AsconPrf};

mod mac;
pub use mac::{AsconMac, AsconMacCore};

mod prng;
pub use prng::AsconPrng;

type B<N> = GenericArray<u8, N>;

fn init(iv: u64, key: &B<typenum::consts::U16>) -> State {
    let (k0, k1): (&B<typenum::consts::U8>, &B<typenum::consts::U8>) = key.split();
    let k0 = u64::from_be_bytes((*k0).into());
    let k1 = u64::from_be_bytes((*k1).into());
    let mut state = State::new(iv, k0, k1, 0, 0);
    state.permute_12();
    state
}

fn compress(s: &mut State, x: &B<typenum::consts::U32>, last: u64) {
    let (x01, x23): (&B<typenum::consts::U16>, &B<typenum::consts::U16>) = x.split();
    let (x0, x1): (&B<typenum::consts::U8>, &B<typenum::consts::U8>) = x01.split();
    let (x2, x3): (&B<typenum::consts::U8>, &B<typenum::consts::U8>) = x23.split();
    let x0 = u64::from_be_bytes((*x0).into());
    let x1 = u64::from_be_bytes((*x1).into());
    let x2 = u64::from_be_bytes((*x2).into());
    let x3 = u64::from_be_bytes((*x3).into());

    s[0] ^= x0;
    s[1] ^= x1;
    s[2] ^= x2;
    s[3] ^= x3;
    s[4] ^= last;
    s.permute_12();
}

fn extract(s: &State, b: &mut B<typenum::consts::U16>) {
    let (o0, o1): (&mut B<typenum::consts::U8>, &mut B<typenum::consts::U8>) = b.split();
    *o0 = s[0].to_be_bytes().into();
    *o1 = s[1].to_be_bytes().into();
}
