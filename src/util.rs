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
