use ascon::State;
use digest::{
    block_buffer::Eager,
    core_api::{
        BlockSizeUser, BufferKindUser, CoreWrapper, ExtendableOutputCore, UpdateCore, XofReaderCore,
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

pub type AsconPrf = CoreWrapper<AsconPrfCore>;

impl KeySizeUser for AsconPrfCore {
    type KeySize = U16;
}

impl KeyInit for AsconPrfCore {
    fn new(key: &digest::Key<Self>) -> Self {
        const IV: u64 = 0x80808c0000000000;
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
        buffer.digest_pad(0x80, &[], |block| {
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
    const IV: u64 = 0x80004c0000000000;
    let iv = IV ^ (m << 51) ^ (t << 35);

    let (k0, k1): (B<U8>, B<U8>) = key.split();
    let k0 = u64::from_be_bytes(k0.into());
    let k1 = u64::from_be_bytes(k1.into());

    let (m0, m1): (B<U8>, B<U8>) = data.split();
    let m0 = u64::from_be_bytes(m0.into());
    let m1 = u64::from_be_bytes(m1.into());

    let mut state = State::new(iv, k0, k1, m0, m1);
    state.permute_12();

    let t0 = k0 ^ state[0];
    let t1 = k1 ^ state[1];

    let mut t = B::default();
    t[0..8].copy_from_slice(&t0.to_be_bytes());
    t[8..16].copy_from_slice(&t1.to_be_bytes());
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
                46, 104, 127, 86, 54, 152, 22, 78, 150, 134, 48, 192, 187, 185, 66, 129, 7, 212,
                156, 9, 201, 50, 248, 6, 166, 3, 165, 82, 245, 211, 37, 250
            ]
        );
    }
}
