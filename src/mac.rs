use ascon::State;
use digest::{
    block_buffer::Eager,
    core_api::{BlockSizeUser, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore},
    crypto_common::{KeyInit, KeySizeUser},
    MacMarker, OutputSizeUser,
};
use generic_array::{sequence::Split, GenericArray};

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

        let (k0, k1): (&B<typenum::consts::U8>, &B<typenum::consts::U8>) = key.split();
        let k0 = u64::from_be_bytes((*k0).into());
        let k1 = u64::from_be_bytes((*k1).into());
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

type B<N> = GenericArray<u8, N>;

impl UpdateCore for AsconMacCore {
    fn update_blocks(&mut self, blocks: &[digest::core_api::Block<Self>]) {
        for block in blocks {
            let (x01, x23): (&B<typenum::consts::U16>, &B<typenum::consts::U16>) = block.split();
            let (x0, x1): (&B<typenum::consts::U8>, &B<typenum::consts::U8>) = x01.split();
            let (x2, x3): (&B<typenum::consts::U8>, &B<typenum::consts::U8>) = x23.split();
            let x0 = u64::from_be_bytes((*x0).into());
            let x1 = u64::from_be_bytes((*x1).into());
            let x2 = u64::from_be_bytes((*x2).into());
            let x3 = u64::from_be_bytes((*x3).into());

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
            let (x01, x23): (&B<typenum::consts::U16>, &B<typenum::consts::U16>) = block.split();
            let (x0, x1): (&B<typenum::consts::U8>, &B<typenum::consts::U8>) = x01.split();
            let (x2, x3): (&B<typenum::consts::U8>, &B<typenum::consts::U8>) = x23.split();
            let x0 = u64::from_be_bytes((*x0).into());
            let x1 = u64::from_be_bytes((*x1).into());
            let x2 = u64::from_be_bytes((*x2).into());
            let x3 = u64::from_be_bytes((*x3).into());

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
