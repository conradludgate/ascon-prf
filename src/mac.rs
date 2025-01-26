use ascon::State;
use digest::{
    block_buffer::Eager,
    core_api::{BlockSizeUser, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore},
    crypto_common::{KeyInit, KeySizeUser},
    MacMarker, OutputSizeUser,
};

pub struct AsconMacCore {
    state: State,
}

pub type AsconMac = CoreWrapper<AsconMacCore>;

impl KeySizeUser for AsconMacCore {
    type KeySize = typenum::consts::U16;
}

impl KeyInit for AsconMacCore {
    fn new(key: &digest::Key<Self>) -> Self {
        const IV: u64 = 0x80808c0000000080;

        let k0 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let mut state = State::new(IV, k0, k1, 0, 0);
        state.permute_12();
        Self { state }
    }
}

impl BlockSizeUser for AsconMacCore {
    type BlockSize = typenum::consts::U32;
}

impl BufferKindUser for AsconMacCore {
    type BufferKind = Eager;
}

impl UpdateCore for AsconMacCore {
    fn update_blocks(&mut self, blocks: &[digest::core_api::Block<Self>]) {
        for block in blocks {
            let x0 = u64::from_be_bytes(block[0..8].try_into().unwrap());
            let x1 = u64::from_be_bytes(block[8..16].try_into().unwrap());
            let x2 = u64::from_be_bytes(block[16..24].try_into().unwrap());
            let x3 = u64::from_be_bytes(block[24..32].try_into().unwrap());

            self.state[0] ^= x0;
            self.state[1] ^= x1;
            self.state[2] ^= x2;
            self.state[3] ^= x3;
            self.state.permute_12();
        }
    }
}

impl OutputSizeUser for AsconMacCore {
    type OutputSize = typenum::consts::U16;
}

impl FixedOutputCore for AsconMacCore {
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut digest::core_api::Buffer<Self>,
        out: &mut digest::Output<Self>,
    ) {
        buffer.digest_pad(0x80, &[], |block| {
            let x0 = u64::from_be_bytes(block[0..8].try_into().unwrap());
            let x1 = u64::from_be_bytes(block[8..16].try_into().unwrap());
            let x2 = u64::from_be_bytes(block[16..24].try_into().unwrap());
            let x3 = u64::from_be_bytes(block[24..32].try_into().unwrap());

            self.state[0] ^= x0;
            self.state[1] ^= x1;
            self.state[2] ^= x2;
            self.state[3] ^= x3;
            self.state[4] ^= 1;
            self.state.permute_12();
        });

        let a = self.state[0];
        let b = self.state[1];
        // self.state.permute_12();

        out[0..8].copy_from_slice(&a.to_be_bytes());
        out[8..16].copy_from_slice(&b.to_be_bytes());
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
            &[55, 200, 95, 61, 117, 243, 181, 94, 60, 50, 44, 233, 243, 135, 52, 117]
        );

        let mut mac = AsconMac::new(b"0123456789abcdef".into());
        mac.update(input);
        mac.verify(&output).unwrap();
    }
}
