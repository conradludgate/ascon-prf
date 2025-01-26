
use ascon::State;
use rand_core::{block::BlockRngCore, CryptoRng, SeedableRng};

#[derive(Clone, Debug)]
pub struct AsconPrf {
    state: State,
}

impl AsconPrf {
    pub fn init(key: [u8; 16]) -> Self {
        // Initialization. The 320-bit initial state of Ascon-PRF is formed by the secret
        // key K of k bits and an IV specifying the algorithm. The 64-bit IV of Ascon-PRF
        // specifies the algorithm parameters in a similar format as for Ascon, including k
        // and the rate ro each written as an 8-bit integer, round number a encoded as an
        // 8-bit integer as 2**7 + a = 0x80 ^ a, followed by a zero byte and the
        // maximum output bitsize t as a 32-bit integer, or t = 0 for arbitrarily long output:
        //
        // IV = k || ro || (0x80 ^ a) || 0x00 || t
        // S = IV || K || 0 || 0
        //
        // In the initialization, the a-round permutation p**a is applied to the initial state:
        // S = p**a(S)

        // for Ascon-PRF:
        // k = 128 = 0x80
        // ro = 128 = 0x80
        // a = 12 = 0x0c
        // t = 0 = 0x00000000
        const IV: u64 = 0x80808c0000000000;

        let k0 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let mut state = State::new(IV, k0, k1, 0, 0);
        state.permute_12();
        Self { state }
    }

    fn absorb_block(&mut self, block: &[u8; 32], last: u64) {
        let x0 = u64::from_be_bytes(block[0..8].try_into().unwrap());
        let x1 = u64::from_be_bytes(block[8..16].try_into().unwrap());
        let x2 = u64::from_be_bytes(block[16..24].try_into().unwrap());
        let x3 = u64::from_be_bytes(block[24..32].try_into().unwrap());

        self.state[0] ^= x0;
        self.state[1] ^= x1;
        self.state[2] ^= x2;
        self.state[3] ^= x3;
        self.state[4] ^= last;
        self.state.permute_12();
    }

    pub fn feed(&mut self, mut data: &[u8]) {
        while let Some((block, rest)) = data.split_first_chunk() {
            data = rest;
            self.absorb_block(block, 0);
        }

        let mut block = [0; 32];
        block[0..data.len()].copy_from_slice(data);
        block[data.len()] ^= 0x80;
        self.absorb_block(&block, 1);
    }

    fn squeeze_block(&mut self) -> [u8; 16] {
        let a = self.state[0];
        let b = self.state[1];
        self.state.permute_12();

        let mut block = [0; 16];
        block[0..8].copy_from_slice(&a.to_be_bytes());
        block[8..16].copy_from_slice(&b.to_be_bytes());
        block
    }

    pub fn fetch(&mut self, mut output: &mut [u8]) {
        while output.len() >= 16 {
            let (block, rest) = output.split_first_chunk_mut::<16>().unwrap();
            output = rest;
            *block = self.squeeze_block();
        }
        if !output.is_empty() {
            let block = self.squeeze_block();
            let len = output.len();
            output[..len].copy_from_slice(&block[..len]);
        }
    }
}

impl SeedableRng for AsconPrf {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self::init(seed)
    }
}

impl BlockRngCore for AsconPrf {
    type Item = u64;
    type Results = [u64; 2];

    fn generate(&mut self, results: &mut Self::Results) {
        let a = self.state[0].to_be();
        let b = self.state[1].to_be();
        self.state.permute_12();
        *results = [a, b];
    }
}

impl CryptoRng for AsconPrf {}

pub fn ascon_prf_short(key: [u8; 16], data: &[u8], output: &mut [u8]) {
    assert!(
        data.len() <= 16,
        "ascon_prf_short is intended for short-inputs only"
    );
    assert!(
        output.len() <= 16,
        "ascon_prf_short is intended for short-outputs only"
    );

    let mut m = [0; 16];
    m[..data.len()].copy_from_slice(data);
    let t = ascon_prf_short_inner(key, data.len() as u64, output.len() as u64, &m);

    let len = output.len();
    output[..len].copy_from_slice(&t[..len]);
}

pub fn ascon_prf_short_128(key: [u8; 16], data: &[u8; 16]) -> [u8; 16] {
    ascon_prf_short_inner(key, 16, 16, data)
}

fn ascon_prf_short_inner(key: [u8; 16], m: u64, t: u64, data: &[u8; 16]) -> [u8; 16] {
    const IV: u64 = 0x80004c0000000000;
    let iv = IV ^ (m << 51) ^ (t << 35);
    let k0 = u64::from_be_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_be_bytes(key[8..16].try_into().unwrap());
    let m0 = u64::from_be_bytes(data[0..8].try_into().unwrap());
    let m1 = u64::from_be_bytes(data[8..16].try_into().unwrap());

    let mut state = State::new(iv, k0, k1, m0, m1);
    state.permute_12();

    let t0 = k0 ^ state[0];
    let t1 = k1 ^ state[1];
    let mut t = [0; 16];
    t[0..8].copy_from_slice(&t0.to_be_bytes());
    t[8..16].copy_from_slice(&t1.to_be_bytes());
    t
}

#[cfg(test)]
mod tests {
    use rand_core::{block::BlockRng64, RngCore, SeedableRng};

    use crate::AsconPrf;

    #[test]
    fn verify() {
        let mut rng = BlockRng64::<AsconPrf>::from_seed([0x55; 16]);
        rng.core.feed(b"hello world");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                31, 41, 203, 246, 88, 243, 64, 30, 187, 154, 175, 251, 172, 175, 60, 183, 74, 21,
                54, 214, 250, 152, 247, 19, 194, 141, 244, 4, 26, 196, 169, 30, 84, 110, 97, 149,
                14, 249, 208, 110, 149, 245, 25, 43, 72, 151, 28, 134, 89, 60, 45, 165, 35, 173,
                93, 213, 11, 72, 36, 207, 172, 164, 15, 121
            ]
        );

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                176, 214, 96, 191, 85, 216, 46, 40, 20, 196, 182, 55, 254, 237, 29, 93, 96, 175,
                99, 230, 117, 131, 8, 160, 72, 237, 177, 18, 6, 78, 72, 159, 130, 106, 209, 22, 46,
                13, 5, 154, 227, 118, 88, 119, 57, 249, 21, 186, 143, 114, 42, 125, 108, 151, 42,
                154, 93, 130, 92, 1, 240, 60, 233, 63
            ]
        );
    }

    #[test]
    fn verify_reseed() {
        let mut rng = BlockRng64::<AsconPrf>::from_seed([0x55; 16]);
        rng.core.feed(b"hello world");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                31, 41, 203, 246, 88, 243, 64, 30, 187, 154, 175, 251, 172, 175, 60, 183, 74, 21,
                54, 214, 250, 152, 247, 19, 194, 141, 244, 4, 26, 196, 169, 30, 84, 110, 97, 149,
                14, 249, 208, 110, 149, 245, 25, 43, 72, 151, 28, 134, 89, 60, 45, 165, 35, 173,
                93, 213, 11, 72, 36, 207, 172, 164, 15, 121
            ]
        );

        rng.core.feed(b"goodbye world");
        rng.reset();

        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                174, 226, 213, 4, 184, 187, 48, 79, 23, 28, 76, 0, 60, 35, 157, 81, 183, 14, 190,
                135, 60, 34, 158, 104, 144, 55, 170, 141, 129, 179, 60, 120, 17, 234, 203, 4, 146,
                25, 162, 183, 59, 86, 200, 160, 187, 104, 122, 159, 174, 140, 159, 35, 118, 210,
                241, 55, 107, 203, 29, 49, 62, 141, 178, 24
            ]
        );
    }
}
