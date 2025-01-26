use ascon::State;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, BlockSizeUser, BufferKindUser, CoreWrapper, ExtendableOutputCore,
        UpdateCore, XofReaderCore,
    },
    crypto_common::KeySizeUser,
    KeyInit,
};
use generic_array::sequence::Split;
use typenum::consts::{U16, U32, U8};

use crate::{compress, extract, B};

#[derive(Clone, Debug)]
pub struct AsconPrfCore {
    state: State,
}

impl AlgorithmName for AsconPrfCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-PRF")
    }
}

impl AlgorithmName for AsconPrfReaderCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-PRF")
    }
}

pub type AsconPrf = CoreWrapper<AsconPrfCore>;

impl KeySizeUser for AsconPrfCore {
    type KeySize = U16;
}

impl KeyInit for AsconPrfCore {
    #[inline(always)]
    fn new(key: &digest::Key<Self>) -> Self {
        const IV: u64 = 0x00000000008c8080;
        Self {
            state: crate::init(IV, key),
        }
    }
}

impl BlockSizeUser for AsconPrfCore {
    type BlockSize = U32;
}

impl BufferKindUser for AsconPrfCore {
    type BufferKind = Eager;
}

impl UpdateCore for AsconPrfCore {
    fn update_blocks(&mut self, blocks: &[digest::core_api::Block<Self>]) {
        blocks.iter().for_each(|b| compress(&mut self.state, b, 0));
    }
}

impl ExtendableOutputCore for AsconPrfCore {
    type ReaderCore = AsconPrfReaderCore;

    fn finalize_xof_core(
        &mut self,
        buffer: &mut digest::core_api::Buffer<Self>,
    ) -> Self::ReaderCore {
        buffer.digest_pad(0x01, &[], |block| {
            compress(&mut self.state, block, 1);
        });
        AsconPrfReaderCore {
            state: self.state.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AsconPrfReaderCore {
    state: State,
}

impl BlockSizeUser for AsconPrfReaderCore {
    type BlockSize = U16;
}

impl XofReaderCore for AsconPrfReaderCore {
    fn read_block(&mut self) -> digest::core_api::Block<Self> {
        let mut block = digest::core_api::Block::<Self>::default();
        extract(&self.state, &mut block);
        self.state.permute_12();
        block
    }
}

pub fn ascon_prf_short(key: [u8; 16], data: &[u8], output: &mut [u8]) {
    assert!(
        data.len() <= 16,
        "ascon_prf_short is intended for short-inputs only"
    );
    assert!(
        output.len() <= 16,
        "ascon_prf_short is intended for short-outputs only"
    );

    let mut m = B::default();
    m[..data.len()].copy_from_slice(data);
    let t = ascon_prf_short_inner(key.into(), data.len() as u64, output.len() as u64, m);

    let len = output.len();
    output[..len].copy_from_slice(&t[..len]);
}

pub fn ascon_prf_short_128(key: [u8; 16], data: &[u8; 16]) -> [u8; 16] {
    ascon_prf_short_inner(key.into(), 16, 16, (*data).into()).into()
}

fn ascon_prf_short_inner(key: B<U16>, m: u64, t: u64, data: B<U16>) -> B<U16> {
    const IV: u64 = 0x00000000004c0080;
    let iv = IV ^ (m << 11) ^ (t << 27);

    let (k0, k1): (B<U8>, B<U8>) = key.split();
    let k0 = u64::from_le_bytes(k0.into());
    let k1 = u64::from_le_bytes(k1.into());

    let (m0, m1): (B<U8>, B<U8>) = data.split();
    let m0 = u64::from_le_bytes(m0.into());
    let m1 = u64::from_le_bytes(m1.into());

    let mut state = State::new(iv, k0, k1, m0, m1);
    state.permute_12();

    let t0 = k0 ^ state[3];
    let t1 = k1 ^ state[4];

    let mut t = B::default();
    t[0..8].copy_from_slice(&t0.to_le_bytes());
    t[8..16].copy_from_slice(&t1.to_le_bytes());
    t
}

#[cfg(test)]
mod tests {
    use digest::{ExtendableOutput, KeyInit, Update, XofReader};

    use super::AsconPrf;

    #[test]
    fn xof() {
        let input = b"This is our great input sequence";

        let mut mac = AsconPrf::new(b"0123456789abcdef".into());
        mac.update(input);
        let mut reader = mac.finalize_xof();

        let mut output = [0u8; 32];
        reader.read(&mut output);

        assert_eq!(
            output,
            [
                248, 122, 131, 117, 74, 8, 141, 9, 176, 167, 131, 133, 93, 137, 113, 113, 58, 236,
                223, 69, 48, 231, 225, 74, 83, 238, 168, 10, 39, 80, 11, 155
            ]
        );
    }
}
