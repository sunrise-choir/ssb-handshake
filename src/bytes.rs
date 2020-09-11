use zerocopy::LayoutVerified;
pub use zerocopy::{AsBytes, FromBytes};

pub fn as_ref<T: FromBytes>(b: &[u8]) -> &T {
    LayoutVerified::<&[u8], T>::new(b).unwrap().into_ref()
}
pub fn as_mut<T: AsBytes + FromBytes>(b: &mut [u8]) -> &mut T {
    LayoutVerified::<&mut [u8], T>::new(b).unwrap().into_mut()
}
