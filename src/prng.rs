use core::convert::Infallible;

use ascon::State;
use rand_core::{
    block::{BlockRng, Generator},
    SeedableRng, TryCryptoRng, TryRng,
};

use crate::{compress, init};

/// Block generator behind [`AsconPrng`].
#[derive(Clone, Debug)]
pub struct AsconPrngCore {
    state: State,
}

impl AsconPrngCore {
    fn feed(&mut self, trng: &[u8; 32]) {
        compress(&mut self.state, trng.into(), 0);
    }
}

impl Generator for AsconPrngCore {
    type Output = [u64; 2];

    fn generate(&mut self, output: &mut Self::Output) {
        output[0] = self.state[0];
        output[1] = self.state[1];
        ascon::permute12(&mut self.state);
    }
}

/// Sponge-based PRNG built on the Ascon permutation.
#[derive(Clone, Debug)]
pub struct AsconPrng(BlockRng<AsconPrngCore>);

impl AsconPrng {
    /// Introduce new seed data from a true-rng source.
    ///
    /// Output buffered before the call is discarded.
    pub fn feed(&mut self, trng: &[u8; 32]) {
        self.0.core.feed(trng);
        self.0.reset_and_skip(0);
    }
}

impl SeedableRng for AsconPrng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(BlockRng::new(AsconPrngCore {
            state: init(0x80808c0000000000_u64.to_be(), &seed.into()),
        }))
    }
}

impl TryRng for AsconPrng {
    type Error = Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.0.next_word() as u32)
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.0.next_word())
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for AsconPrng {}

#[cfg(test)]
mod tests {
    use rand_core::{Rng, SeedableRng};

    use super::AsconPrng;

    #[test]
    fn verify() {
        let mut rng = AsconPrng::from_seed([0x55; 16]);
        rng.feed(b"hello world                     ");

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
        let mut rng = AsconPrng::from_seed([0x55; 16]);
        rng.feed(b"hello world                     ");

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

        rng.feed(b"goodbye world                   ");

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
