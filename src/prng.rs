use ascon::State;
use generic_array::sequence::Split;
use rand_core::{block::BlockRngCore, CryptoRng, SeedableRng};
use typenum::consts::{U16, U32, U8};

use crate::{init, B};

#[derive(Clone, Debug)]
pub struct AsconPrng {
    state: State,
}

fn compress(s: &mut State, x: &B<U32>) {
    let (x01, x23): (&B<U16>, &B<U16>) = x.split();
    let (x0, x1): (&B<U8>, &B<U8>) = x01.split();
    let (x2, x3): (&B<U8>, &B<U8>) = x23.split();
    let x0 = u64::from_ne_bytes((*x0).into());
    let x1 = u64::from_ne_bytes((*x1).into());
    let x2 = u64::from_ne_bytes((*x2).into());
    let x3 = u64::from_ne_bytes((*x3).into());

    s[0] ^= x0;
    s[1] ^= x1;
    s[2] ^= x2;
    s[3] ^= x3;
    s.permute_12();
}

impl AsconPrng {
    /// Introduce new seed data from a true-rng source.
    pub fn feed(&mut self, trng: &[u8; 32]) {
        compress(&mut self.state, trng.into());
    }
}

impl SeedableRng for AsconPrng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            state: init(0x80808c0000000000, &seed.into()),
        }
    }
}

impl BlockRngCore for AsconPrng {
    type Item = u64;
    type Results = [u64; 2];

    fn generate(&mut self, results: &mut Self::Results) {
        results[0] = self.state[0];
        results[1] = self.state[1];
        self.state.permute_12();
    }
}

impl CryptoRng for AsconPrng {}

#[cfg(test)]
mod tests {
    use rand_core::{block::BlockRng64, RngCore, SeedableRng};

    use super::AsconPrng;

    #[test]
    fn verify() {
        let mut rng = BlockRng64::<AsconPrng>::from_seed([0x55; 16]);
        rng.core.feed(b"hello world                     ");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                160, 42, 63, 210, 71, 68, 162, 49, 112, 170, 165, 70, 99, 209, 178, 30, 213, 189,
                255, 179, 37, 125, 22, 150, 232, 192, 5, 161, 58, 147, 252, 230, 105, 190, 205,
                247, 37, 18, 147, 192, 249, 5, 187, 20, 57, 220, 140, 226, 165, 154, 193, 173, 152,
                230, 0, 132, 11, 29, 143, 219, 136, 223, 130, 41
            ]
        );

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                149, 229, 61, 129, 115, 121, 116, 45, 72, 102, 238, 171, 137, 190, 43, 157, 107,
                127, 210, 98, 236, 221, 47, 66, 168, 180, 54, 196, 119, 18, 205, 255, 164, 62, 163,
                237, 251, 155, 64, 208, 50, 101, 183, 63, 25, 81, 211, 230, 171, 243, 226, 203,
                205, 154, 38, 162, 219, 174, 155, 173, 172, 244, 106, 52
            ]
        );
    }

    #[test]
    fn verify_reseed() {
        let mut rng = BlockRng64::<AsconPrng>::from_seed([0x55; 16]);
        rng.core.feed(b"hello world                     ");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                160, 42, 63, 210, 71, 68, 162, 49, 112, 170, 165, 70, 99, 209, 178, 30, 213, 189,
                255, 179, 37, 125, 22, 150, 232, 192, 5, 161, 58, 147, 252, 230, 105, 190, 205,
                247, 37, 18, 147, 192, 249, 5, 187, 20, 57, 220, 140, 226, 165, 154, 193, 173, 152,
                230, 0, 132, 11, 29, 143, 219, 136, 223, 130, 41
            ]
        );

        rng.core.feed(b"goodbye world                   ");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                122, 6, 86, 54, 222, 10, 154, 166, 87, 156, 60, 253, 129, 203, 249, 10, 152, 142,
                29, 208, 51, 35, 33, 39, 23, 142, 1, 115, 67, 91, 79, 100, 217, 212, 220, 18, 110,
                110, 98, 247, 229, 34, 149, 140, 58, 50, 136, 178, 108, 171, 17, 243, 180, 154,
                102, 96, 74, 133, 251, 150, 51, 10, 131, 43
            ]
        );
    }
}
