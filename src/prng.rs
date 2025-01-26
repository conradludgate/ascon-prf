use ascon::State;
use rand_core::{block::BlockRngCore, CryptoRng, SeedableRng};

use crate::{compress, init};

#[derive(Clone, Debug)]
pub struct AsconPrng {
    state: State,
}

impl AsconPrng {
    /// Introduce new seed data from a true-rng source.
    pub fn feed(&mut self, trng: &[u8; 32]) {
        compress(&mut self.state, trng.into(), 0);
    }
}

impl SeedableRng for AsconPrng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            state: init(0x80808c0000000000_u64.to_be(), &seed.into()),
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
                150, 9, 91, 45, 234, 168, 9, 80, 3, 187, 6, 46, 14, 246, 8, 150, 80, 136, 233, 138,
                63, 255, 98, 184, 40, 45, 68, 136, 64, 68, 167, 109, 230, 118, 130, 196, 184, 73,
                39, 58, 219, 96, 200, 4, 166, 162, 93, 74, 229, 198, 116, 166, 249, 188, 224, 113,
                166, 206, 80, 163, 161, 133, 12, 46
            ]
        );

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                26, 205, 243, 47, 199, 149, 237, 160, 172, 160, 100, 140, 19, 94, 14, 212, 85, 15,
                101, 147, 98, 189, 144, 70, 17, 61, 8, 164, 8, 61, 38, 53, 95, 11, 34, 227, 124,
                45, 216, 115, 241, 217, 249, 167, 190, 94, 62, 216, 38, 151, 29, 82, 169, 160, 95,
                22, 111, 241, 73, 50, 100, 91, 50, 129
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
                150, 9, 91, 45, 234, 168, 9, 80, 3, 187, 6, 46, 14, 246, 8, 150, 80, 136, 233, 138,
                63, 255, 98, 184, 40, 45, 68, 136, 64, 68, 167, 109, 230, 118, 130, 196, 184, 73,
                39, 58, 219, 96, 200, 4, 166, 162, 93, 74, 229, 198, 116, 166, 249, 188, 224, 113,
                166, 206, 80, 163, 161, 133, 12, 46
            ]
        );

        rng.core.feed(b"goodbye world                   ");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                127, 137, 152, 50, 4, 133, 227, 203, 86, 233, 0, 71, 146, 198, 113, 224, 183, 69,
                190, 19, 173, 120, 5, 64, 107, 173, 206, 253, 37, 207, 135, 235, 49, 159, 255, 36,
                89, 108, 147, 13, 209, 37, 205, 247, 187, 239, 116, 69, 203, 104, 248, 33, 201,
                182, 101, 217, 11, 57, 232, 237, 240, 222, 160, 88
            ]
        );
    }
}
