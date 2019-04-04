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
    NetworkKey,
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

use std::mem::size_of;
use std::slice;

mod error;
pub use error::HandshakeError;
pub mod messages;

// use sodiumoxide::utils::memzero;
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


/// Shared Secret A (client and server ephemeral keys)
#[derive(Clone)]
pub struct SharedA(SharedSecret);
impl SharedA {
    // shared_secret_ab = nacl_scalarmult(
    //   client_ephemeral_sk,
    //   server_ephemeral_pk
    // )
    pub fn client_side(
        sk: &ClientEphSecretKey,
        pk: &ServerEphPublicKey,
    ) -> Result<SharedA, HandshakeError> {
        derive_shared_secret(&sk.0, &pk.0)
            .map(SharedA)
            .ok_or(HandshakeError::SharedAInvalid)
    }

    // shared_secret_ab = nacl_scalarmult(
    //   server_ephemeral_sk,
    //   client_ephemeral_pk
    // )
    pub fn server_side(
        sk: &ServerEphSecretKey,
        pk: &ClientEphPublicKey,
    ) -> Result<SharedA, HandshakeError> {
        derive_shared_secret(&sk.0, &pk.0)
            .map(SharedA)
            .ok_or(HandshakeError::SharedAInvalid)
    }

    fn hash(&self) -> SharedAHash {
        SharedAHash(hash(&self.0[..]))
    }
}
struct SharedAHash(Digest);

/// Shared Secret B (client ephemeral key, server long-term key)
#[derive(Clone)]
pub struct SharedB(SharedSecret);
impl SharedB {
    // shared_secret_aB = nacl_scalarmult(
    //   client_ephemeral_sk,
    //   pk_to_curve25519(server_longterm_pk)
    // )
    pub fn client_side(
        sk: &ClientEphSecretKey,
        pk: &ServerPublicKey,
    ) -> Result<SharedB, HandshakeError> {
        // pk_to_curve(&pk.0)
        //     .and_then(|c| derive_shared_secret(&sk.0, &c))
        derive_shared_secret_pk(&sk.0, &pk.0)
            .map(SharedB)
            .ok_or(HandshakeError::SharedBInvalid)
    }

    // shared_secret_aB = nacl_scalarmult(
    //   sk_to_curve25519(server_longterm_sk),
    //   client_ephemeral_pk
    // )
    pub fn server_side(
        sk: &ServerSecretKey,
        pk: &ClientEphPublicKey,
    ) -> Result<SharedB, HandshakeError> {
        // sk_to_curve(&sk.0)
        //     .and_then(|c| derive_shared_secret(&c, &pk.0))
        derive_shared_secret_sk(&sk.0, &pk.0)
            .map(SharedB)
            .ok_or(HandshakeError::SharedBInvalid)
    }
}

/// Shared Secret C (client long-term key, server ephemeral key)
#[derive(Clone)]
pub struct SharedC(SharedSecret);
impl SharedC {
    pub fn client_side(
        sk: &ClientSecretKey,
        pk: &ServerEphPublicKey,
    ) -> Result<SharedC, HandshakeError> {
        // sk_to_curve(&sk.0)
        //     .and_then(|c| derive_shared_secret(&c, &pk.0))
        derive_shared_secret_sk(&sk.0, &pk.0)
            .map(SharedC)
            .ok_or(HandshakeError::SharedCInvalid)
    }

    pub fn server_side(
        sk: &ServerEphSecretKey,
        pk: &ClientPublicKey,
    ) -> Result<SharedC, HandshakeError> {
        // pk_to_curve(&pk.0)
        //     .and_then(|c| derive_shared_secret(&sk.0, &c))
        derive_shared_secret_pk(&sk.0, &pk.0)
            .map(SharedC)
            .ok_or(HandshakeError::SharedCInvalid)
    }
}

struct SharedKeyHash(Digest);

#[repr(C, packed)]
struct SharedKeyHashData {
    net_key: NetworkKey,
    shared_a: SharedA,
    shared_b: SharedB,
    shared_c: SharedC,
}
impl SharedKeyHashData {
    fn into_hash(self) -> SharedKeyHash {
        let h1 = unsafe { hash(bytes(&self)) };
        SharedKeyHash(hash(&h1[..]))
    }
}

#[repr(C, packed)]
struct SharedKeyData {
    double_hash: SharedKeyHash,
    pk: PublicKey,
}
impl SharedKeyData {
    fn into_key(self) -> secretbox::Key {
        let digest = unsafe { hash(bytes(&self)) };
        secretbox::Key::from_slice(&digest[..]).unwrap()
    }
}

fn build_shared_key(
    pk: &PublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> secretbox::Key {
    // c2s: sha256( sha256(sha256(net_key + a + b + c)) + server_pk)
    // s2c: sha256( sha256(sha256(net_key + a + b + c)) + client_pk)

    let double_hash = SharedKeyHashData {
        net_key: net_key.clone(),
        shared_a: shared_a.clone(),
        shared_b: shared_b.clone(),
        shared_c: shared_c.clone(),
    }
    .into_hash();

    SharedKeyData {
        double_hash,
        pk: pk.clone(),
    }
    .into_key()
}

/// Final shared key used to seal and open secret boxes (client to server)
pub fn client_to_server_key(
    server_pk: &ServerPublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> secretbox::Key {
    build_shared_key(
        &server_pk.0,
        net_key,
        shared_a,
        shared_b,
        shared_c,
    )
}

/// Final shared key used to seal and open secret boxes (server to client)
pub fn server_to_client_key(
    server_pk: &ClientPublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> secretbox::Key {
    build_shared_key(
        &server_pk.0,
        net_key,
        shared_a,
        shared_b,
        shared_c,
    )
}

pub struct HandshakeOutcome {
    pub read_key: secretbox::Key,
    pub read_noncegen: NonceGen,

    pub write_key: secretbox::Key,
    pub write_noncegen: NonceGen,
}

fn zero_nonce() -> secretbox::Nonce {
    secretbox::Nonce([0u8; size_of::<secretbox::Nonce>()])
}

pub(crate) unsafe fn bytes<T>(t: &T) -> &[u8] {
    // TODO: is it possible to check if T is a pointer type?

    let p = t as *const T as *const u8;
    slice::from_raw_parts(p, size_of::<T>())
}
