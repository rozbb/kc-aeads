use crate::cx_prf::{CommittingPrf, CxPrf};

use aead::{AeadCore, AeadInPlace, Error, NewAead, Nonce, Tag};
use aes_gcm::{AesGcm, ClobberingDecrypt};
use cipher::{
    generic_array::{arr::AddLength, ArrayLength, GenericArray},
    typenum::{Unsigned, U0, U12, U16},
    Block, BlockCipher, BlockEncrypt, BlockSizeUser, Key, KeyInit, KeySizeUser,
};
use subtle::ConstantTimeEq;

type AesGcmNonceSize = U12;
type AesGcmTagSize = U16;

type CxComSize<Ciph> = <CxPrf<'static, Ciph> as CommittingPrf>::ComSize;

/// New tag size is PRF commitment size + original GCM tag size
type UtcTagSize<Ciph> = <CxComSize<Ciph> as AddLength<u8, AesGcmTagSize>>::Output;

/// The UTC transformation for AES-GCM. `Ciph` is either `Aes128` or `Aes256`
pub struct UtcOverAesGcm<Ciph>(Ciph)
where
    Ciph: BlockEncrypt + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>,
    CxComSize<Ciph>: AddLength<u8, AesGcmTagSize>;

impl<Ciph> AeadCore for UtcOverAesGcm<Ciph>
where
    Ciph: BlockEncrypt + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>,
    CxComSize<Ciph>: AddLength<u8, AesGcmTagSize>,
{
    /// New tag size is PRF commitment size + original GCM tag size
    type TagSize = UtcTagSize<Ciph>;

    /// Nonce size are the same
    type NonceSize = AesGcmNonceSize;

    /// No ciphertext overhead is incurred by this
    type CiphertextOverhead = U0;
}

fn pack_tag<Ciph>(
    gcm_tag: GenericArray<u8, AesGcmTagSize>,
    prf_com: GenericArray<u8, CxComSize<Ciph>>,
) -> GenericArray<u8, UtcTagSize<Ciph>>
where
    Ciph: BlockEncrypt + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>,
    CxComSize<Ciph>: AddLength<u8, AesGcmTagSize>,
    CxPrf<'static, Ciph>: CommittingPrf,
{
    let mut utc_tag = GenericArray::<u8, UtcTagSize<Ciph>>::default();

    utc_tag.as_mut_slice()[..AesGcmTagSize::USIZE].copy_from_slice(&gcm_tag);
    utc_tag.as_mut_slice()[AesGcmTagSize::USIZE..].copy_from_slice(&prf_com);

    utc_tag
}

fn unpack_tag<Ciph>(
    utc_tag: &GenericArray<u8, UtcTagSize<Ciph>>,
) -> (
    &GenericArray<u8, AesGcmTagSize>,
    &GenericArray<u8, CxComSize<Ciph>>,
)
where
    Ciph: BlockEncrypt + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>,
    CxComSize<Ciph>: AddLength<u8, AesGcmTagSize>,
    CxPrf<'static, Ciph>: CommittingPrf,
{
    let gcm_tag = GenericArray::<u8, AesGcmTagSize>::from_slice(&utc_tag[..AesGcmTagSize::USIZE]);
    let prf_com = GenericArray::<u8, CxComSize<Ciph>>::from_slice(&utc_tag[AesGcmTagSize::USIZE..]);

    (gcm_tag, prf_com)
}

impl<Ciph> NewAead for UtcOverAesGcm<Ciph>
where
    Ciph: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>,
    CxComSize<Ciph>: AddLength<u8, AesGcmTagSize>,
{
    type KeySize = Ciph::KeySize;

    fn new(key: &GenericArray<u8, Ciph::KeySize>) -> Self {
        UtcOverAesGcm(Ciph::new(key))
    }
}

impl<Ciph> AeadInPlace for UtcOverAesGcm<Ciph>
where
    Ciph: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit + KeySizeUser,
    <Ciph::BlockSize as ArrayLength<u8>>::ArrayType: Copy,
    Ciph::KeySize: AddLength<u8, Ciph::KeySize>,
    CxComSize<Ciph>: AddLength<u8, AesGcmTagSize>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        // Generate the commitment and mask
        let cx_prf = CxPrf(&self.0);
        let (prf_com, prf_mask) = cx_prf.prf(nonce);

        // Now use the mask as an encryption key
        let gcm = AesGcm::<Ciph, U12>::new(&prf_mask);
        let gcm_tag = gcm.encrypt_in_place_detached(nonce, associated_data, buffer)?;

        Ok(pack_tag::<Ciph>(gcm_tag, prf_com))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        // Unpack the components of the tag
        let (gcm_tag, prf_com) = unpack_tag::<Ciph>(tag);

        // Generate the commitment and mask
        let cx_prf = CxPrf(&self.0);
        let (expected_prf_com, prf_mask) = cx_prf.prf(nonce);

        // Now use the mask as an encryption key
        let gcm = AesGcm::<Ciph, U12>::new(&prf_mask);
        let decryption_success = gcm.clobbering_decrypt(nonce, associated_data, buffer, gcm_tag)?;

        // Check that the PRF commitments match
        let com_matches = prf_com.ct_eq(&expected_prf_com);

        // If the GCM decryption AND the PRF commitment checks succeeded, return Ok(()).
        // Otherwise, re-encrypt the plaintext and error out.
        if (decryption_success & com_matches).unwrap_u8() == 1 {
            Ok(())
        } else {
            // Unclobber so the caller doesn't see unauthenticated plaintext
            gcm.unclobber(nonce, buffer, gcm_tag);
            Err(Error)
        }
    }
}

pub type UtcAes128Gcm = UtcOverAesGcm<aes::Aes128>;
pub type UtcAes256Gcm = UtcOverAesGcm<aes::Aes256>;

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
