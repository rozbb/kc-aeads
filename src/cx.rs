//! Defines the CX[E] committing PRF scheme described in https://eprint.iacr.org/2022/268 §7

use block_padding::AnsiX923;
use cipher::{
    generic_array::{arr::AddLength, ArrayLength, GenericArray},
    typenum::{op, Unsigned, U12, U2},
    Block, BlockEncrypt, BlockSizeUser, Key, KeySizeUser,
};
use core::iter;

// Defines Cx over a generic block cipher
struct Cx<Ciph>(Ciph)
where
    Ciph: BlockEncrypt + KeySizeUser;

type NonceSize = U12;
type DoubleKeySize<Ciph> =
    <<Ciph as KeySizeUser>::KeySize as AddLength<u8, <Ciph as KeySizeUser>::KeySize>>::Output;

// Mask has to be used as an encryption key
pub(crate) type CxMask<Ciph> = Key<Ciph>;

// Com has to be collision resistant. So it should be 2x the keysize
pub(crate) type CxCom<Ciph> = GenericArray<u8, DoubleKeySize<Ciph>>;

/*
pub(crate) trait CxPrf {
    type MsgSize: ArrayLength<u8>;
    type ComSize: ArrayLength<u8>;
    type MaskSize: ArrayLength<u8>;

    /// The CX[E] PRF. Returns (P, L) where P is the "commitment" and L is the "mask"
    fn prf(
        &self,
        msg: &GenericArray<u8, Self::MsgSize>,
    ) -> (
        GenericArray<u8, Self::ComSize>,
        GenericArray<u8, Self::MaskSize>,
    );
}
*/

impl<Ciph> Cx<Ciph>
where
    Ciph: BlockEncrypt + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>,
{
    // Size of the CX com value (P), in blocks
    const COM_BLOCKS: usize =
        (DoubleKeySize::<Ciph>::USIZE + Ciph::BlockSize::USIZE - 1) / Ciph::BlockSize::USIZE;
    // Size of the CX mask value (L), in blocks
    const MASK_BLOCKS: usize = (<Ciph as KeySizeUser>::KeySize::USIZE + Ciph::BlockSize::USIZE - 1)
        / Ciph::BlockSize::USIZE;

    /// The CX[E] PRF. Returns (P, L) where P is the "commitment" and L is the "mask"
    pub(crate) fn prf(&self, nonce: &GenericArray<u8, NonceSize>) -> (CxCom<Ciph>, CxMask<Ciph>) {
        // Compute pad(nonce, 1), pad(nonce, 2), pad(nonce, 3), pad(nonce 4), where pad(M, i) is
        // the concatenation of M and a (block_size - msg_size)-bit encoding of i.

        // In stable we can't make an array of size COM_BLOCKS+MASK_BLOCKS. The error is
        //     Error: constant expression depends on a generic parameter
        // This requires the const_evaluatable_checked feature
        // Tracking issue: https://github.com/rust-lang/rust/issues/76560
        let mut block_buf = [Block::<Ciph>::default(); 6];
        let blocks = &mut block_buf[..Self::COM_BLOCKS + Self::MASK_BLOCKS];

        for (i, block) in blocks.iter_mut().enumerate() {
            block[..NonceSize::USIZE].copy_from_slice(nonce);
            block[Ciph::BlockSize::USIZE - 1] = (i + 1) as u8;
        }

        // Save block 0 for XORing
        let block0 = blocks[0].clone();

        // Now encrypt
        self.0.encrypt_blocks(blocks);

        // Finally, XOR block 0 into the 0th ciphertext
        blocks[0]
            .iter_mut()
            .zip(block0.iter())
            .for_each(|(c, m)| *c ^= m);

        // com is the first COM_BLOCKS blocks, and mask is the next MASK_BLOCKS blocks
        let com = CxCom::<Ciph>::from_exact_iter(
            blocks
                .iter()
                .take(Self::COM_BLOCKS)
                .flat_map(IntoIterator::into_iter)
                .cloned(),
        )
        .unwrap();
        let mask = CxMask::<Ciph>::from_exact_iter(
            blocks
                .iter()
                .skip(Self::COM_BLOCKS)
                .take(Self::MASK_BLOCKS)
                .flat_map(IntoIterator::into_iter)
                .cloned(),
        )
        .unwrap();

        (com, mask)
    }
}

#[test]
fn test_cx() {
    use aes::{Aes128, Aes256};
    use cipher::{Key, KeyInit};

    let key = Key::<Aes128>::default();
    let nonce = GenericArray::<u8, NonceSize>::default();
    let ciph = Aes128::new(&key);

    let (com, mask) = Cx(ciph).prf(&nonce);
    println!(" com: {:x?}", com);
    println!("mask: {:x?}", mask);

    let key = Key::<Aes256>::default();
    let nonce = GenericArray::<u8, NonceSize>::default();
    let ciph = Aes256::new(&key);

    let (com, mask) = Cx(ciph).prf(&nonce);
    println!(" com: {:x?}", com);
    println!("mask: {:x?}", mask);
}
