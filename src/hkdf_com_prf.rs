//! Defines an HKDF-based committing PRF for generic hash functions

use crate::util::{CommittingPrf, DoubleKeySize};

use core::marker::PhantomData;

use cipher::{BlockSizeUser, Key, KeySizeUser};
use digest::{
    generic_array::{arr::AddLength, ArrayLength, GenericArray},
    Digest, KeyInit, OutputSizeUser,
};
use hkdf::SimpleHkdf;

// Here's the current definition:
//
// HkdfComPrf[H].Prf(K, N):
//     prk ← HKDF[H].Extract(salt="HkdfComPrf", ikm=K)
//     com ← HKDF[H].Expand(prk, info="P" || N, len=2*|K|)
//     mask ← HKDF[H].Expand(prk, info="L" || N, len=|K|)
//     return (com, mask)

const EXTRACT_DOMAIN_SEP: &[u8] = b"HkdfComPrf";

/// A committing PRF derived from HKDF, defined over a hash funtion `H`
pub struct HkdfComPrf<H, KeySize, MsgSize>
where
    H: BlockSizeUser + Clone + Digest + OutputSizeUser,
    MsgSize: ArrayLength<u8>,
    KeySize: ArrayLength<u8>,
{
    hkdf: SimpleHkdf<H>,
    _marker: PhantomData<(KeySize, MsgSize)>,
}

impl<H, KeySize, MsgSize> KeySizeUser for HkdfComPrf<H, KeySize, MsgSize>
where
    H: BlockSizeUser + Clone + Digest + OutputSizeUser,
    KeySize: ArrayLength<u8>,
    MsgSize: ArrayLength<u8>,
{
    type KeySize = KeySize;
}

impl<H, KeySize, MsgSize> KeyInit for HkdfComPrf<H, KeySize, MsgSize>
where
    H: BlockSizeUser + Clone + Digest + OutputSizeUser,
    KeySize: ArrayLength<u8>,
    MsgSize: ArrayLength<u8>,
{
    fn new(key: &Key<Self>) -> Self {
        // We can unwrap() below because the only possible error is InvalidPrkLength
        HkdfComPrf {
            hkdf: SimpleHkdf::extract(Some(EXTRACT_DOMAIN_SEP), key).1,
            _marker: PhantomData,
        }
    }
}

impl<H, KeySize, MsgSize> CommittingPrf for HkdfComPrf<H, KeySize, MsgSize>
where
    H: BlockSizeUser + Clone + Digest + OutputSizeUser,
    KeySize: ArrayLength<u8>,
    MsgSize: ArrayLength<u8>,
    <Self as KeySizeUser>::KeySize: AddLength<u8, <Self as KeySizeUser>::KeySize>,
{
    type MsgSize = MsgSize;
    type ComSize = DoubleKeySize<Self>;
    type MaskSize = Self::KeySize;

    fn prf(
        &self,
        msg: &GenericArray<u8, MsgSize>,
    ) -> (
        GenericArray<u8, Self::ComSize>,
        GenericArray<u8, Self::MaskSize>,
    ) {
        let mut com = GenericArray::<u8, Self::ComSize>::default();
        let mut mask = GenericArray::<u8, Self::MaskSize>::default();

        // Use HKDF-Expand to calculate com and mask. These only fail if Self::ComSize is greater
        // than 255*HashLen, which is way too big.
        // P and L refer to variable names for commitment and mask in §7
        self.hkdf
            .expand_multi_info(&[b"P", msg], &mut com)
            .expect("PRF com size is far too large");
        self.hkdf
            .expand_multi_info(&[b"L", msg], &mut mask)
            .expect("PRF com size is far too large");

        (com, mask)
    }
}
