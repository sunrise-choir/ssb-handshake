//! Based on Duncan's fantastic
//! [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
//! ([repo](https://github.com/ssbc/scuttlebutt-protocol-guide)),
//! which he graciously released into the public domain.

#[macro_use] extern crate quick_error;
extern crate ssb_crypto;

use ssb_crypto::{
    PublicKey,
    SecretKey,
    Signature,
    NonceGen,
    secretbox,
};

use ssb_crypto::handshake::{
    EphPublicKey,
    EphSecretKey,
    derive_shared_secret,
    derive_shared_secret_pk,
    derive_shared_secret_sk,
    SharedSecret,
    generate_ephemeral_keypair,
};

use ssb_crypto::hash::{hash, Digest};

mod error;
mod utils;
pub use error::HandshakeError;
pub mod messages;

pub mod shared_secret;
pub mod shared_key;

// TODO: memzero our secrets, if sodiumoxide doesn't do it for us.

/// Client long-term public key
#[derive(Clone)]
pub struct ClientPublicKey(pub PublicKey);
impl ClientPublicKey {
    pub fn from_slice(b: &[u8]) -> Option<ClientPublicKey> {
        Some(ClientPublicKey(PublicKey::from_slice(b)?))
    }
}

/// Client long-term secret key
pub struct ClientSecretKey(pub SecretKey);
impl ClientSecretKey {
    pub fn from_slice(b: &[u8]) -> Option<ClientSecretKey> {
        Some(ClientSecretKey(SecretKey::from_slice(b)?))
    }
}

/// Server long-term public key; known to client prior to the handshake
#[derive(Clone)]
pub struct ServerPublicKey(pub PublicKey);
impl ServerPublicKey {
    pub fn from_slice(b: &[u8]) -> Option<ServerPublicKey> {
        Some(ServerPublicKey(PublicKey::from_slice(b)?))
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Server long-term secret key
pub struct ServerSecretKey(pub SecretKey);
impl ServerSecretKey {
    pub fn from_slice(b: &[u8]) -> Option<ServerSecretKey> {
        Some(ServerSecretKey(SecretKey::from_slice(b)?))
    }
}

#[derive(Clone)]
pub struct ClientSignature(Signature);
struct ServerSignature(Signature);

/// Client ephemeral public key (generated anew for each connection)
#[derive(Clone)]
pub struct ClientEphPublicKey(pub EphPublicKey);
/// Client ephemeral secret key
pub struct ClientEphSecretKey(pub EphSecretKey);

/// Server ephemeral public key (generated anew for each connection)
#[derive(Clone)]
pub struct ServerEphPublicKey(pub EphPublicKey);
/// Server ephemeral secret key
pub struct ServerEphSecretKey(pub EphSecretKey);

pub mod client {
    use super::*;

    pub fn generate_eph_keypair() -> (ClientEphPublicKey, ClientEphSecretKey) {
        let (pk, sk) = generate_ephemeral_keypair();
        (ClientEphPublicKey(pk), ClientEphSecretKey(sk))
    }
}

pub mod server {
    use super::*;

    pub fn generate_eph_keypair() -> (ServerEphPublicKey, ServerEphSecretKey) {
        let (pk, sk) = generate_ephemeral_keypair();
        (ServerEphPublicKey(pk), ServerEphSecretKey(sk))
    }
}

pub struct HandshakeOutcome {
    pub read_key: secretbox::Key,
    pub read_noncegen: NonceGen,

    pub write_key: secretbox::Key,
    pub write_noncegen: NonceGen,
}
