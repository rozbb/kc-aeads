//! Defines the `HtE` key-committing → context-committing (CMTD-1 → CMTD-4) AEAD transform
//! described in <https://eprint.iacr.org/2022/268> §3

use crate::utc_transform::{UtcAes128Gcm, UtcAes256Gcm};

use core::marker::PhantomData;

use aead::{AeadCore, AeadInPlace, Error, Key, NewAead, Nonce, Tag};
use cipher::BlockSizeUser;
use digest::{Digest, OutputSizeUser};
use hkdf::SimpleHkdf;
use sha2::{Sha256, Sha512};

/// A context-committing AEAD built on top of AES-128-GCM
pub type HteUtcAes128Gcm = HkdfHte<UtcAes128Gcm, Sha256>;
//pub type HteUtcAes128Gcm = HkdfHte<UtcAes128Gcm, Blake2bMac<U32>>;

/// A context-committing AEAD built on top of AES-256-GCM
pub type HteUtcAes256Gcm = HkdfHte<UtcAes256Gcm, Sha512>;
//pub type HteUtcAes256Gcm = HkdfHte<UtcAes256Gcm, Blake2bMac<U64>>;

// Here's the current definition:
//
// HkdfHte[H,A].Enc(K, N, A, M):
//     prk ← HKDF[H].Extract(salt="HkdfHte", ikm=K)
//     enc_key ← HKDF[H].Expand(prk, info=N || A, len=|K|)
//     C ← A.Enc(enc_key, N, "", M)
//     return C
//
// HkdfHte[H,A].Dec(K, N, A, C):
//     prk ← HKDF[H].Extract(salt="HkdfHte", ikm=K)
//     enc_key ← HKDF[H].Expand(prk, info=N || A, len=|K|)
//     M ← A.Dec(enc_key, N, "", C)
//     return M

const EXTRACT_DOMAIN_SEP: &[u8] = b"HkdfHte";

/// The Hash-then-Encrypt transform over a generic AEAD and hash function. This converts any
/// key-committing AEAD to a context-committing AEAD (i.e., CMTD-1 → CMTD-4). Its construction
/// is described in Figure 6 of [Bellare and Hoang](https://eprint.iacr.org/2022/268).
pub struct HkdfHte<A, H>
where
    A: AeadInPlace + NewAead,
    H: BlockSizeUser + Clone + Digest + OutputSizeUser,
{
    mac: SimpleHkdf<H>,
    _marker: PhantomData<A>,
}

impl<A, H> AeadCore for HkdfHte<A, H>
where
    A: AeadInPlace + NewAead,
    H: BlockSizeUser + Clone + Digest + OutputSizeUser,
{
    type TagSize = A::TagSize;
    type NonceSize = A::NonceSize;
    type CiphertextOverhead = A::CiphertextOverhead;
}

impl<A, H> NewAead for HkdfHte<A, H>
where
    A: AeadInPlace + NewAead,
    H: BlockSizeUser + Clone + Digest + OutputSizeUser,
{
    type KeySize = A::KeySize;

    fn new(key: &Key<Self>) -> Self {
        HkdfHte {
            mac: SimpleHkdf::extract(Some(EXTRACT_DOMAIN_SEP), key).1,
            _marker: PhantomData,
        }
    }
}

impl<A, H> AeadInPlace for HkdfHte<A, H>
where
    A: AeadInPlace + NewAead,
    H: BlockSizeUser + Clone + Digest + OutputSizeUser,
{
    // We take an underlying Enc and define an Enc'. From Figure 6:
    // Enc'(K, N, A, M):
    //     L ← H(K, (N, A))
    //     C ← Enc(L, N, ε, M)
    //     return C
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        // Derive the encryption key L. This only fails if Self::ComSize is greater than
        // 255*HashLen, which is way too big.
        let mut enc_key = Key::<A>::default();
        self.mac
            .expand_multi_info(&[nonce, associated_data], &mut enc_key)
            .expect("key size is far too large");

        // Now use L to encrypt the message. The associated data is excluded
        let ciph = A::new(&enc_key);
        ciph.encrypt_in_place_detached(nonce, &[], buffer)
    }

    // We take an underlying Dec and define a Dec'. From Figure 6:
    // Dec'(K, N, A, C):
    //     L ← H(K, (N, A))
    //     M ← Dec(L, N, ε, C)
    //     return M
    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        // Derive the encryption key L. This only fails if Self::ComSize is greater than
        // 255*HashLen, which is way too big.
        let mut enc_key = Key::<A>::default();
        self.mac
            .expand_multi_info(&[nonce, associated_data], &mut enc_key)
            .expect("key size is far too large");

        // Now use L to decrypt the message. The associated data is excluded
        let ciph = A::new(&enc_key);
        ciph.decrypt_in_place_detached(nonce, &[], buffer, tag)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::test_aead_correctness;

    test_aead_correctness!(HteUtcAes128Gcm, hte_utc_aes128_correctness);
    test_aead_correctness!(HteUtcAes256Gcm, hte_utc_aes256_correctness);
}
