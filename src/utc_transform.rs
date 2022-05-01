use core::marker::PhantomData;

use crate::cx_prf::{CommittingPrf, CxPrf};

use aead::{AeadCore, AeadInPlace, Error, NewAead, Nonce, Tag};
use aes::{Aes128, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, ClobberingDecrypt};
use cipher::{
    generic_array::{arr::AddLength, ArrayLength, GenericArray},
    typenum::{Unsigned, U0, U12, U16},
    BlockCipher, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
};
use subtle::ConstantTimeEq;

type AesGcmNonceSize = U12;

pub type UtcAes128Gcm = Utc<Aes128Gcm, CxPrf<Aes128>>;
pub type UtcAes256Gcm = Utc<Aes256Gcm, CxPrf<Aes256>>;

/// The UtC transformation over a generic AEAD
pub struct Utc<A, F>
where
    A: AeadInPlace + NewAead,
    F: CommittingPrf<MsgSize = A::NonceSize, MaskSize = A::KeySize>,
{
    prf: F,
    ciph: PhantomData<A>,
}

impl<A, F> AeadCore for Utc<A, F>
where
    A: AeadInPlace + NewAead,
    F: CommittingPrf<MsgSize = A::NonceSize, MaskSize = A::KeySize>,
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
    F: CommittingPrf<MsgSize = A::NonceSize, MaskSize = A::KeySize>,
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
    F: CommittingPrf<MsgSize = A::NonceSize, MaskSize = A::KeySize>,
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
    F: CommittingPrf<MsgSize = A::NonceSize, MaskSize = A::KeySize>,
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
    F: CommittingPrf<MsgSize = A::NonceSize, MaskSize = A::KeySize>,
    F::ComSize: AddLength<u8, A::TagSize>,
{
    let ciph_tag = GenericArray::<u8, A::TagSize>::from_slice(&utc_tag[..A::TagSize::USIZE]);
    let prf_com = GenericArray::<u8, F::ComSize>::from_slice(&utc_tag[A::TagSize::USIZE..]);

    (ciph_tag, prf_com)
}

#[cfg(test)]
mod test {
    use super::*;

    use aead::{Aead, NewAead, Payload};
    use rand::{thread_rng, RngCore};

    // Tests that Dec(Enc(x)) == x for a lot of x
    #[test]
    fn utc_correctness() {
        let mut rng = thread_rng();

        // We test the 128 and 256 bit ciphers
        let ciph128 = {
            let key = UtcAes128Gcm::generate_key(&mut rng);
            UtcAes128Gcm::new(&key)
        };
        let ciph256 = {
            let key = UtcAes256Gcm::generate_key(&mut rng);
            UtcAes256Gcm::new(&key)
        };

        for msg_len in 0..=512 {
            // Pick random values
            let msg = {
                let mut buf = vec![0u8; msg_len];
                rng.fill_bytes(&mut buf);
                buf
            };
            let aad = {
                let mut buf = vec![0u8; msg_len];
                rng.fill_bytes(&mut buf);
                buf
            };
            let nonce = {
                let mut buf = Nonce::<UtcAes128Gcm>::default();
                rng.fill_bytes(buf.as_mut_slice());
                buf
            };

            // Organize the msg and AAD
            let pt_payload = Payload {
                msg: &msg,
                aad: &aad,
            };
            let pt_payload_copy = Payload {
                msg: &msg,
                aad: &aad,
            };

            // Encrypt the message under both ciphers
            let ciphertext128 = ciph128.encrypt(&nonce, pt_payload).unwrap();
            let ciphertext256 = ciph256.encrypt(&nonce, pt_payload_copy).unwrap();

            // Decrypt the ciphertexts
            let ct_payload128 = Payload {
                msg: &ciphertext128,
                aad: &aad,
            };
            let ct_payload256 = Payload {
                msg: &ciphertext256,
                aad: &aad,
            };
            let roundtrip_msg128 = ciph128.decrypt(&nonce, ct_payload128).unwrap();
            let roundtrip_msg256 = ciph256.decrypt(&nonce, ct_payload256).unwrap();

            // Compare the decrypted messages with the original
            assert_eq!(msg, roundtrip_msg128);
            assert_eq!(msg, roundtrip_msg256);
        }
    }
}
