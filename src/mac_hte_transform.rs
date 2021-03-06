//! Defines the `HtE` key-committing → everything committing (CMTD-1 → CMTD-4) AEAD transform
//! described in <https://eprint.iacr.org/2022/268> §3. This version of `HtE` is generic over a
//! given MAC.

use crate::utc_transform::{UtcAes128Gcm, UtcAes256Gcm};

use core::marker::PhantomData;

use aead::{AeadCore, AeadInPlace, Error, Key, NewAead, Nonce, Tag};
use digest::{
    typenum::{
        marker_traits::NonZero, operator_aliases::LeEq, type_operators::IsLessOrEqual, Unsigned,
    },
    KeyInit, Mac,
};
use hkdf::hmac::SimpleHmac;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

/// An everything-committing AEAD built on top of AES-128-GCM
pub type MacHteUtcAes128Gcm = MacHte<UtcAes128Gcm, SimpleHmac<Sha256>>;
//pub type MacHteUtcAes128Gcm = HkdfHte<UtcAes128Gcm, Blake2bMac<U32>>;

/// An everything-committing AEAD built on top of AES-256-GCM
pub type MacHteUtcAes256Gcm = MacHte<UtcAes256Gcm, SimpleHmac<Sha512>>;
//pub type MacHteUtcAes256Gcm = HkdfHte<UtcAes256Gcm, Blake2bMac<U32>>;

// Here's the current definition. In short, it just MACs the nonce and AAD, truncates the output to
// the key size of the underlying AEAD, and runs that on the plaintext (omitting AAD).
//
// MacHte[H,M].Enc(K, N, A, M):
//     m ← M.MAC(K, N || A)
//     enc_key = m[..|K|]
//     C ← A.Enc(enc_key, N, "", M)
//     return C
//
// MacHte[H,A].Dec(K, N, A, C):
//     m ← M.MAC(K, N || A)
//     enc_key = m[..|K|]
//     C ← A.Dec(enc_key, N, "", C)
//     return M

/// The Hash-then-Encrypt transform over a generic AEAD and MAC. This converts any key-committing
/// AEAD to an everything-committing AEAD (i.e., CMTD-1 → CMTD-4). Its construction is described in
/// Figure 6 of [Bellare and Hoang](https://eprint.iacr.org/2022/268).
pub struct MacHte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac + KeyInit,
    A::KeySize: IsLessOrEqual<M::OutputSize>,
    LeEq<A::KeySize, M::OutputSize>: NonZero,
{
    // We use the AEAD key as a MAC key. This is fine as long as the underlying MAC allows
    // variable-sized keys. We'll know if it doesn't because it will panic immediately.
    mac_key: Key<A>,
    _marker: PhantomData<M>,
}

impl<A, M> Zeroize for MacHte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac + KeyInit,
    A::KeySize: IsLessOrEqual<M::OutputSize>,
    LeEq<A::KeySize, M::OutputSize>: NonZero,
{
    fn zeroize(&mut self) {
        self.mac_key.zeroize()
    }
}

impl<A, M> AeadCore for MacHte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac + KeyInit,
    A::KeySize: IsLessOrEqual<M::OutputSize>,
    LeEq<A::KeySize, M::OutputSize>: NonZero,
{
    type TagSize = A::TagSize;
    type NonceSize = A::NonceSize;
    type CiphertextOverhead = A::CiphertextOverhead;
}

impl<A, M> NewAead for MacHte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac + KeyInit,
    A::KeySize: IsLessOrEqual<M::OutputSize>,
    LeEq<A::KeySize, M::OutputSize>: NonZero,
{
    type KeySize = A::KeySize;

    fn new(key: &Key<Self>) -> Self {
        MacHte {
            mac_key: key.clone(),
            _marker: PhantomData,
        }
    }
}

impl<A, M> AeadInPlace for MacHte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac + KeyInit,
    A::KeySize: IsLessOrEqual<M::OutputSize>,
    LeEq<A::KeySize, M::OutputSize>: NonZero,
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
        // Derive the encryption key L
        let digest = {
            let mut mac =
                <M as KeyInit>::new_from_slice(&self.mac_key).expect("invalid MAC key length");
            mac.update(nonce);
            mac.update(associated_data);
            mac.finalize().into_bytes()
        };

        // Truncate the MAC to get the encryption key. This cannot fail because we require
        // A::KeySize ≤ M::OutputSize.
        let enc_key = Key::<A>::from_slice(&digest[..A::KeySize::USIZE]);

        // Now use the key to encrypt the message. The associated data is excluded
        let ciph = A::new(enc_key);
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
        // Derive the encryption key L
        let digest = {
            let mut mac =
                <M as KeyInit>::new_from_slice(&self.mac_key).expect("invalid MAC key length");
            mac.update(nonce);
            mac.update(associated_data);
            mac.finalize().into_bytes()
        };

        // Truncate the MAC to get the encryption key. This cannot fail because we require
        // A::KeySize ≤ M::OutputSize.
        let enc_key = Key::<A>::from_slice(&digest[..A::KeySize::USIZE]);

        // Now use the key to decrypt the message. The associated data is excluded
        let ciph = A::new(&enc_key);
        ciph.decrypt_in_place_detached(nonce, &[], buffer, tag)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::test_aead_correctness;

    test_aead_correctness!(MacHteUtcAes128Gcm, machte_utc_aes128_correctness);
    test_aead_correctness!(MacHteUtcAes256Gcm, machte_utc_aes256_correctness);
}
