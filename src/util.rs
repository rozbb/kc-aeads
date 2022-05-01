use cipher::{
    generic_array::{arr::AddLength, ArrayLength, GenericArray},
    KeyInit, KeySizeUser,
};

pub(crate) type DoubleKeySize<T> =
    <<T as KeySizeUser>::KeySize as AddLength<u8, <T as KeySizeUser>::KeySize>>::Output;

/// A helper trait for a _committing PRF_, which returns a commitment and a mask. This is defined
/// in §7.
pub trait CommittingPrf: KeyInit {
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

// Tests that Dec(Enc(x)) == x for a lot of x
#[cfg(test)]
macro_rules! test_aead_correctness {
    ($aead:ty, $test_name:ident) => {
        #[test]
        fn $test_name() {
            use aead::{Aead, NewAead, Nonce, Payload};
            use rand::RngCore;

            let mut rng = rand::thread_rng();

            let ciph = {
                let key = <$aead>::generate_key(&mut rng);
                <$aead>::new(&key)
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
                    let mut buf = Nonce::<$aead>::default();
                    rng.fill_bytes(buf.as_mut_slice());
                    buf
                };

                // Organize the msg and AAD
                let pt_payload = Payload {
                    msg: &msg,
                    aad: &aad,
                };

                // Encrypt the message
                let ciphertext = ciph.encrypt(&nonce, pt_payload).unwrap();

                // Decrypt the ciphertext
                let ct_payload = Payload {
                    msg: &ciphertext,
                    aad: &aad,
                };
                let roundtrip_msg = ciph.decrypt(&nonce, ct_payload).unwrap();

                // Compare the decrypted message with the original
                assert_eq!(msg, roundtrip_msg);
            }
        }
    };
}

#[cfg(test)]
pub(crate) use test_aead_correctness;
