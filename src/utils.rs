use core::mem::size_of;
use ssb_crypto::secretbox::Nonce;
use std::slice;

pub(crate) fn zero_nonce() -> Nonce {
    Nonce([0u8; size_of::<Nonce>()])
}

pub(crate) unsafe fn bytes<T>(t: &T) -> &[u8] {
    // TODO: is it possible to check if T is a pointer type?

    let p = t as *const T as *const u8;
    slice::from_raw_parts(p, size_of::<T>())
}
