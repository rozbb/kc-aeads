//! Defines the `HtE` key-committing → everything committing (CMTD-1 → CMTD-4) AEAD transform
//! described in <https://eprint.iacr.org/2022/268> §3

use crate::utc_transform::UtcAes128Gcm;

use core::marker::PhantomData;

use aead::{AeadCore, AeadInPlace, Error, Key, NewAead, Nonce, Tag};
use aes::Aes128;
use blake2::Blake2bMac;
use digest::{
    typenum::{U32, U64},
    Key as MacKey, KeyInit, Mac,
};
use zeroize::Zeroize;

/// An everything-committing AEAD built on top of AES-128-GCM
pub type HteUtcAes128Gcm = Hte<UtcAes128Gcm, Blake2bMac<U32>>;

/// An everything-committing AEAD built on top of AES-256-GCM
pub type HteUtcAes256Gcm = Hte<UtcAes128Gcm, Blake2bMac<U64>>;

/// The Hash-then-Encrypt transform over a generic AEAD and MAC. This converts any key-committing
/// AEAD to an everything-committing AEAD (i.e., CMTD-1 → CMTD-4). Its construction is described in
/// Figure 6 of [Bellare and Hoang](https://eprint.iacr.org/2022/268).
pub struct Hte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac<OutputSize = A::KeySize> + KeyInit<KeySize = A::KeySize>,
{
    mac_key: MacKey<M>,
    ciph: PhantomData<A>,
}

impl<A, M> Zeroize for Hte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac<OutputSize = A::KeySize> + KeyInit<KeySize = A::KeySize>,
{
    fn zeroize(&mut self) {
        self.mac_key.zeroize()
    }
}

impl<A, M> AeadCore for Hte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac<OutputSize = A::KeySize> + KeyInit<KeySize = A::KeySize>,
{
    type TagSize = A::TagSize;
    type NonceSize = A::NonceSize;
    type CiphertextOverhead = A::CiphertextOverhead;
}

impl<A, M> NewAead for Hte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac<OutputSize = A::KeySize> + KeyInit<KeySize = A::KeySize>,
{
    type KeySize = A::KeySize;

    fn new(key: &Key<Self>) -> Self {
        Hte {
            mac_key: key.clone(),
            ciph: PhantomData,
        }
    }
}

impl<A, M> AeadInPlace for Hte<A, M>
where
    A: AeadInPlace + NewAead,
    M: Mac<OutputSize = A::KeySize> + KeyInit<KeySize = A::KeySize>,
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
        let enc_key = {
            let mut mac = <M as KeyInit>::new(&self.mac_key);
            mac.update(nonce);
            mac.update(associated_data);
            mac.finalize().into_bytes()
        };

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
        // Derive the encryption key L
        let enc_key = {
            let mut mac = <M as KeyInit>::new(&self.mac_key);
            mac.update(nonce);
            mac.update(associated_data);
            mac.finalize().into_bytes()
        };

        // Now use L to decrypt the message. The associated data is excluded
        let ciph = A::new(&enc_key);
        ciph.decrypt_in_place_detached(nonce, &[], buffer, tag)
    }
}
