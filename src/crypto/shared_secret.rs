use super::{
    ClientEphPublicKey,
    ClientEphSecretKey,
    ClientPublicKey,
    ClientSecretKey,

    ServerEphPublicKey,
    ServerEphSecretKey,
    ServerPublicKey,
    ServerSecretKey,
};

use crate::error::HandshakeError;

use ssb_crypto::{
    handshake::{
        derive_shared_secret,
        derive_shared_secret_pk,
        derive_shared_secret_sk,
        SharedSecret,
    },
    hash::{
        Digest,
        hash,
    },
};


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

    pub(crate) fn hash(&self) -> SharedAHash {
        SharedAHash(hash(&self.0[..]))
    }
}
pub(crate) struct SharedAHash(Digest);

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
