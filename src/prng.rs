use ascon::State;
use digest::block_buffer::BlockBuffer;
use rand_core::{block::BlockRngCore, CryptoRng, SeedableRng};

use crate::{compress, init};

#[derive(Clone, Debug)]
pub struct AsconPrng {
    state: State,
}

impl AsconPrng {
    pub fn feed(&mut self, input: &[u8]) {
        let mut buf = BlockBuffer::default();
        buf.digest_blocks(input, |b| {
            b.iter().for_each(|b| compress(&mut self.state, b, 0))
        });
        buf.digest_pad(0x80, &[], |b| compress(&mut self.state, b, 1));
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
        rng.core.feed(b"hello world");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                30, 64, 243, 88, 246, 203, 41, 31, 183, 60, 175, 172, 251, 175, 154, 187, 19, 247,
                152, 250, 214, 54, 21, 74, 30, 169, 196, 26, 4, 244, 141, 194, 110, 208, 249, 14,
                149, 97, 110, 84, 134, 28, 151, 72, 43, 25, 245, 149, 213, 93, 173, 35, 165, 45,
                60, 89, 121, 15, 164, 172, 207, 36, 72, 11
            ]
        );

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                40, 46, 216, 85, 191, 96, 214, 176, 93, 29, 237, 254, 55, 182, 196, 20, 160, 8,
                131, 117, 230, 99, 175, 96, 159, 72, 78, 6, 18, 177, 237, 72, 154, 5, 13, 46, 22,
                209, 106, 130, 186, 21, 249, 57, 119, 88, 118, 227, 154, 42, 151, 108, 125, 42,
                114, 143, 63, 233, 60, 240, 1, 92, 130, 93
            ]
        );
    }

    #[test]
    fn verify_reseed() {
        let mut rng = BlockRng64::<AsconPrng>::from_seed([0x55; 16]);
        rng.core.feed(b"hello world");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                30, 64, 243, 88, 246, 203, 41, 31, 183, 60, 175, 172, 251, 175, 154, 187, 19, 247,
                152, 250, 214, 54, 21, 74, 30, 169, 196, 26, 4, 244, 141, 194, 110, 208, 249, 14,
                149, 97, 110, 84, 134, 28, 151, 72, 43, 25, 245, 149, 213, 93, 173, 35, 165, 45,
                60, 89, 121, 15, 164, 172, 207, 36, 72, 11
            ]
        );

        rng.core.feed(b"goodbye world");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                79, 48, 187, 184, 4, 213, 226, 174, 81, 157, 35, 60, 0, 76, 28, 23, 104, 158, 34,
                60, 135, 190, 14, 183, 120, 60, 179, 129, 141, 170, 55, 144, 183, 162, 25, 146, 4,
                203, 234, 17, 159, 122, 104, 187, 160, 200, 86, 59, 55, 241, 210, 118, 35, 159,
                140, 174, 24, 178, 141, 62, 49, 29, 203, 107
            ]
        );
    }
}
