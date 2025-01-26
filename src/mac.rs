use ascon::State;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, BlockSizeUser, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore,
    },
    crypto_common::{KeyInit, KeySizeUser},
    MacMarker, OutputSizeUser,
};
use typenum::consts::{U16, U32};

use crate::{compress, extract};

#[derive(Clone, Debug)]
pub struct AsconMacCore {
    state: State,
}

pub type AsconMac = CoreWrapper<AsconMacCore>;

impl KeySizeUser for AsconMacCore {
    type KeySize = U16;
}

impl AlgorithmName for AsconMacCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-Mac")
    }
}

impl KeyInit for AsconMacCore {
    #[inline(always)]
    fn new(key: &digest::Key<Self>) -> Self {
        const IV: u64 = 0x00000080008c8080;
        Self {
            state: crate::init(IV, key),
        }
    }
}

impl BlockSizeUser for AsconMacCore {
    type BlockSize = U32;
}

impl BufferKindUser for AsconMacCore {
    type BufferKind = Eager;
}

impl UpdateCore for AsconMacCore {
    fn update_blocks(&mut self, blocks: &[digest::core_api::Block<Self>]) {
        blocks.iter().for_each(|b| compress(&mut self.state, b, 0));
    }
}

impl OutputSizeUser for AsconMacCore {
    type OutputSize = U16;
}

impl FixedOutputCore for AsconMacCore {
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut digest::core_api::Buffer<Self>,
        out: &mut digest::Output<Self>,
    ) {
        buffer.digest_pad(0x01, &[], |block| {
            compress(&mut self.state, block, 1);
        });
        extract(&self.state, out);
    }
}

impl MacMarker for AsconMacCore {}

#[cfg(test)]
mod tests {
    use digest::Mac;

    use super::AsconMac;

    #[test]
    fn round_trip() {
        let input = b"This is our great input sequence";

        let mut mac = AsconMac::new(b"0123456789abcdef".into());
        mac.update(input);
        let output = mac.finalize().into_bytes();

        assert_eq!(
            &output[..],
            &[53, 224, 223, 219, 242, 104, 181, 209, 23, 144, 216, 69, 242, 73, 137, 139]
        );

        let mut mac = AsconMac::new(b"0123456789abcdef".into());
        mac.update(input);
        mac.verify(&output).unwrap();
    }
}
