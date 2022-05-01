//! Defines the `CX[E]` committing PRF scheme described in https://eprint.iacr.org/2022/268 §7

use cipher::{
    generic_array::{arr::AddLength, ArrayLength, GenericArray},
    typenum::{Unsigned, U12},
    Block, BlockEncrypt, Key, KeySizeUser,
};

// The size of an AES-GCM nonce
type NonceSize = U12;

// Mask has to be used as an encryption key
pub(crate) type CxMask<Ciph> = Key<Ciph>;

// Com has to be collision resistant. So it should be 2x the keysize
type DoubleKeySize<Ciph> =
    <<Ciph as KeySizeUser>::KeySize as AddLength<u8, <Ciph as KeySizeUser>::KeySize>>::Output;
pub(crate) type CxCom<Ciph> = GenericArray<u8, DoubleKeySize<Ciph>>;

/// A helper trait for a _committing PRF_, which returns a commitment and a mask. This is defined
/// in §7.
pub(crate) trait CommittingPrf {
    type MsgSize: ArrayLength<u8>;
    type ComSize: ArrayLength<u8>;
    type MaskSize: ArrayLength<u8>;

    /// A PRF function that returns a commitment and a mask.
    fn prf(
        &self,
        msg: &GenericArray<u8, Self::MsgSize>,
    ) -> (
        GenericArray<u8, Self::ComSize>,
        GenericArray<u8, Self::MaskSize>,
    );
}

/// The `CX[E]` committing PRF, defined over any block cipher `E`.
pub(crate) struct CxPrf<'a, Ciph>(&'a Ciph)
where
    Ciph: BlockEncrypt + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>;

// Define CX[E] for any block cipher cipher. Our definition only works with messages of 12 bytes,
// since that's what we'll need for AES-GCM
impl<Ciph> CommittingPrf for CxPrf<'_, Ciph>
where
    Ciph: BlockEncrypt + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>,
{
    // Again, we only care about PRFing nonces
    type MsgSize = NonceSize;

    type ComSize = DoubleKeySize<Ciph>;
    type MaskSize = Ciph::KeySize;

    // Paraphrasing Figure 14 of the paper:
    //
    // CX[E](K, M):
    //     num_total_blocks = num_com_blocks + num_mask_blocks
    //     for i in num_total_blocks:
    //         Xᵢ ← pad(M, i)
    //         Vᵢ ← E_K(Xᵢ)
    //         V₁ ← V₁ ⊕ X₁
    //
    //      com ← (X₁, ..., X_{num_com_blocks})
    //      mask ← (X_{num_com_blocks+1}, ..., X_{num_mask_blocks})
    //
    //      return (com, mask)
    // where pad(M, i) = M || 0x00 ... 0x00 || (i as u8), padding to the size of a cipher block.

    /// The `CX[E]` PRF. Returns `(P, L)` where `P` is the "commitment" and `L` is the "mask"
    fn prf(&self, nonce: &GenericArray<u8, NonceSize>) -> (CxCom<Ciph>, CxMask<Ciph>) {
        // These should be a rounding-up division. But the numerator is always a multiple of block
        // size so it doesn't matter.
        let num_com_blocks = Self::ComSize::USIZE / Ciph::BlockSize::USIZE;
        let num_mask_blocks = Self::MaskSize::USIZE / Ciph::BlockSize::USIZE;
        let num_total_blocks = num_com_blocks + num_mask_blocks;

        // Compute pad(nonce, 1), pad(nonce, 2), pad(nonce, 3), pad(nonce 4), where pad(M, i) is
        // the concatenation of M and a (block_size - msg_size)-bit encoding of i.

        // In stable we can't make an array of size num_com_blocks + num_mask_blocks. The error is
        //     Error: constant expression depends on a generic parameter
        // This requires the const_evaluatable_checked feature
        // (https://github.com/rust-lang/rust/issues/76560). So instead we just use a buf of the
        // maximum size, 6 blocks, and take an appropriately sized slice.
        let mut block_buf = [Block::<Ciph>::default(); 6];
        let blocks = &mut block_buf[..num_total_blocks];

        for (i, block) in blocks.iter_mut().enumerate() {
            block[..NonceSize::USIZE].copy_from_slice(nonce);
            block[Ciph::BlockSize::USIZE - 1] = (i + 1) as u8;
        }

        // Save block 0 for XORing
        let block0 = blocks[0].clone();

        // Now encrypt all the blocks
        self.0.encrypt_blocks(blocks);

        // Finally, XOR block 0 into the 0th ciphertext
        blocks[0]
            .iter_mut()
            .zip(block0.iter())
            .for_each(|(c, m)| *c ^= m);

        // com is the first `num_com_blocks` blocks, and mask is the next `num_mask_blocks` blocks
        let com = CxCom::<Ciph>::from_exact_iter(
            blocks
                .iter()
                .take(num_com_blocks)
                .flat_map(IntoIterator::into_iter)
                .cloned(),
        )
        .unwrap();
        let mask = CxMask::<Ciph>::from_exact_iter(
            blocks
                .iter()
                .skip(num_com_blocks)
                .take(num_mask_blocks)
                .flat_map(IntoIterator::into_iter)
                .cloned(),
        )
        .unwrap();

        (com, mask)
    }
}

// Simple test: make sure that cx_prf() doesn't panic
#[test]
fn basic_cx_prf() {
    use aes::{Aes128, Aes256};
    use aes_gcm::Nonce;
    use cipher::{Key, KeyInit};
    use rand::RngCore;

    let mut rng = rand::thread_rng();

    let nonce = {
        let mut buf = Nonce::default();
        rng.fill_bytes(&mut buf);
        buf
    };

    // Test AES-128
    let key = {
        let mut buf = Key::<Aes128>::default();
        rng.fill_bytes(buf.as_mut_slice());
        buf
    };
    let ciph = Aes128::new(&key);
    CxPrf(&ciph).prf(&nonce);

    // Test AES-256
    let key = {
        let mut buf = Key::<Aes256>::default();
        rng.fill_bytes(buf.as_mut_slice());
        buf
    };
    let ciph = Aes256::new(&key);
    CxPrf(&ciph).prf(&nonce);
}
