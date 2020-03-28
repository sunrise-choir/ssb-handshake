pub mod message;
pub mod outcome;
pub mod shared_secret;

use ssb_crypto::{
    handshake::{generate_ephemeral_keypair, EphPublicKey, EphSecretKey},
    PublicKey, SecretKey, Signature,
};

/// Client long-term public key
#[derive(Clone)]
pub struct ClientPublicKey(pub PublicKey);
impl ClientPublicKey {
    pub fn from_slice(b: &[u8]) -> Option<ClientPublicKey> {
        Some(ClientPublicKey(PublicKey::from_slice(b)?))
    }
    pub fn into_inner(self) -> PublicKey{
        self.0
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
impl ClientEphPublicKey {
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        Some(ClientEphPublicKey(EphPublicKey::from_slice(b)?))
    }
}

/// Client ephemeral secret key
pub struct ClientEphSecretKey(pub EphSecretKey);

/// Server ephemeral public key (generated anew for each connection)
#[derive(Clone)]
pub struct ServerEphPublicKey(pub EphPublicKey);
impl ServerEphPublicKey {
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        Some(ServerEphPublicKey(EphPublicKey::from_slice(b)?))
    }
}

/// Server ephemeral secret key
pub struct ServerEphSecretKey(pub EphSecretKey);

pub fn gen_client_eph_keypair() -> (ClientEphPublicKey, ClientEphSecretKey) {
    let (pk, sk) = generate_ephemeral_keypair();
    (ClientEphPublicKey(pk), ClientEphSecretKey(sk))
}

pub fn gen_server_eph_keypair() -> (ServerEphPublicKey, ServerEphSecretKey) {
    let (pk, sk) = generate_ephemeral_keypair();
    (ServerEphPublicKey(pk), ServerEphSecretKey(sk))
}
