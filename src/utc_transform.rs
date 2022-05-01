//! Defines the `UtC` unique-nonce-secure AEAD transform described in
//! <https://eprint.iacr.org/2022/268> §7

use core::marker::PhantomData;

use crate::{hkdf_com_prf::HkdfComPrf, util::CommittingPrf};

use aead::{AeadCore, AeadInPlace, Error, NewAead, Nonce, Tag};
use aes_gcm::{Aes128Gcm, Aes256Gcm, ClobberingDecrypt};
use cipher::{
    generic_array::{arr::AddLength, GenericArray},
    typenum::{Unsigned, U12, U16, U32},
};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

/// A key-committing AEAD built on top of AES-128-GCM
pub type UtcAes128Gcm = Utc<Aes128Gcm, HkdfComPrf<Sha256, U16, U12>>;
//pub type UtcAes128Gcm = Utc<Aes128Gcm, CxPrf<Aes128, U12>>;

/// A key-committing AEAD built on top of AES-256-GCM
pub type UtcAes256Gcm = Utc<Aes256Gcm, HkdfComPrf<Sha512, U32, U12>>;
//pub type UtcAes256Gcm = Utc<Aes256Gcm, CxPrf<Aes256, U12>>;

pub(crate) type DoubleKeySize<A> =
    <<A as NewAead>::KeySize as AddLength<u8, <A as NewAead>::KeySize>>::Output;

/// The UtC transformation over a generic AEAD and committing PRF. This converts a unique-nonce-secure
/// (i.e., not necessarily nonce-misuse-resistant) AEAD into a key-committing unique-nonce-secure
/// AEAD. Its construction is described in Figure 15 of [Bellare and
/// Hoang](https://eprint.iacr.org/2022/268).
pub struct Utc<A, F>
where
    A: AeadInPlace + NewAead,
    A::KeySize: AddLength<u8, A::KeySize>,
    F: CommittingPrf<KeySize = DoubleKeySize<A>, MsgSize = A::NonceSize, MaskSize = A::KeySize>,
    F::ComSize: AddLength<u8, A::TagSize>,
{
    prf: F,
    ciph: PhantomData<A>,
}

impl<A, F> AeadCore for Utc<A, F>
where
    A: AeadInPlace + NewAead,
    A::KeySize: AddLength<u8, A::KeySize>,
    F: CommittingPrf<KeySize = DoubleKeySize<A>, MsgSize = A::NonceSize, MaskSize = A::KeySize>,
    F::ComSize: AddLength<u8, A::TagSize>,
{
    /// New tag size is PRF commitment size + original tag size
    type TagSize = <F::ComSize as AddLength<u8, A::TagSize>>::Output;

    /// Nonce size is the same
    type NonceSize = A::NonceSize;

    /// Ciphertext overhead is the same
    type CiphertextOverhead = A::CiphertextOverhead;
}

impl<A, F> NewAead for Utc<A, F>
where
    A: AeadInPlace + NewAead,
    A::KeySize: AddLength<u8, A::KeySize>,
    F: CommittingPrf<KeySize = DoubleKeySize<A>, MsgSize = A::NonceSize, MaskSize = A::KeySize>,
    F::ComSize: AddLength<u8, A::TagSize>,
{
    type KeySize = F::KeySize;

    fn new(key: &GenericArray<u8, F::KeySize>) -> Self {
        Utc {
            prf: F::new(key),
            ciph: PhantomData,
        }
    }
}

impl<A, F> AeadInPlace for Utc<A, F>
where
    A: AeadInPlace + ClobberingDecrypt + NewAead,
    A::KeySize: AddLength<u8, A::KeySize>,
    F: CommittingPrf<KeySize = DoubleKeySize<A>, MsgSize = A::NonceSize, MaskSize = A::KeySize>,
    F::ComSize: AddLength<u8, A::TagSize>,
{
    // Paraphrasing from Figure 15:
    //
    // UtC[F, A].Enc(K, N, A, M):
    //     (com, mask) ← F.Prf(K, N)
    //     (C, T) ← A.Enc(mask, N, A, M)
    //     T' ← T || com
    //     return (C, T')
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        // Generate the commitment and mask
        let (prf_com, prf_mask) = self.prf.prf(nonce);

        // Now use the mask as an encryption key
        let ciph = A::new(&prf_mask);
        let ciph_tag = ciph.encrypt_in_place_detached(nonce, associated_data, buffer)?;

        Ok(pack_tag::<A, F>(ciph_tag, prf_com))
    }

    // Paraphrasing from Figure 15:
    //
    // UtC[F, A].Dec(K, N, A, C, T'):
    //     (com, T) ← T'
    //     (expected_com, mask) ← F.Prf(K, N)
    //     if com != expected_com:
    //         return ⊥
    //     else:
    //         M ← A.Dec(mask, N, A, C, T)
    //         return M
    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        // Unpack the components of the tag
        let (ciph_tag, prf_com) = unpack_tag::<A, F>(tag);

        // Generate the commitment and mask
        let (expected_prf_com, prf_mask) = self.prf.prf(nonce);

        // Now use the mask as an encryption key
        let ciph = A::new(&prf_mask);
        let decryption_success =
            ciph.clobbering_decrypt(nonce, associated_data, buffer, ciph_tag)?;

        // Check that the PRF commitments match
        let com_matches = prf_com.ct_eq(&expected_prf_com);

        // If the GCM decryption AND the PRF commitment checks succeeded, return Ok(()).
        // Otherwise, re-encrypt the plaintext and error out.
        if (decryption_success & com_matches).unwrap_u8() == 1 {
            Ok(())
        } else {
            // Unclobber so the caller doesn't see unauthenticated plaintext
            ciph.unclobber(nonce, buffer, ciph_tag);
            Err(Error)
        }
    }
}

/// Creates a `utc_tag = ciph_tag || prf_com`
fn pack_tag<A, F>(
    ciph_tag: GenericArray<u8, A::TagSize>,
    prf_com: GenericArray<u8, F::ComSize>,
) -> Tag<Utc<A, F>>
where
    A: AeadInPlace + NewAead,
    A::KeySize: AddLength<u8, A::KeySize>,
    F: CommittingPrf<KeySize = DoubleKeySize<A>, MsgSize = A::NonceSize, MaskSize = A::KeySize>,
    F::ComSize: AddLength<u8, A::TagSize>,
{
    let mut utc_tag = Tag::<Utc<A, F>>::default();

    utc_tag.as_mut_slice()[..A::TagSize::USIZE].copy_from_slice(&ciph_tag);
    utc_tag.as_mut_slice()[A::TagSize::USIZE..].copy_from_slice(&prf_com);

    utc_tag
}

/// Unpacks `utc_tag = ciph_tag || prf_com`
fn unpack_tag<A, F>(
    utc_tag: &Tag<Utc<A, F>>,
) -> (&GenericArray<u8, A::TagSize>, &GenericArray<u8, F::ComSize>)
where
    A: AeadInPlace + NewAead,
    A::KeySize: AddLength<u8, A::KeySize>,
    F: CommittingPrf<KeySize = DoubleKeySize<A>, MsgSize = A::NonceSize, MaskSize = A::KeySize>,
    F::ComSize: AddLength<u8, A::TagSize>,
{
    let ciph_tag = GenericArray::<u8, A::TagSize>::from_slice(&utc_tag[..A::TagSize::USIZE]);
    let prf_com = GenericArray::<u8, F::ComSize>::from_slice(&utc_tag[A::TagSize::USIZE..]);

    (ciph_tag, prf_com)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::test_aead_correctness;

    test_aead_correctness!(UtcAes128Gcm, utc_aes128_correctness);
    test_aead_correctness!(UtcAes256Gcm, utc_aes256_correctness);
}
