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

mod prf;
pub use prf::{AsconPrf, ascon_prf_short, ascon_prf_short_128};

mod mac;
pub use mac::{AsconMacCore, AsconMac};
