//! Internal types used in the implementation of the handshake.
//! The ClientPublicKey, etc types are simply wrappers around basic crypto types,
//! to avoid bugs caused by e.g. using the wrong keys in the wrong places.

pub mod keys;
pub mod message;
pub mod outcome;
pub mod shared_secret;
