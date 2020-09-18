use crate::bytes::AsBytes;
use crate::crypto::keys::*;

use ssb_crypto::ephemeral::{
    derive_shared_secret, derive_shared_secret_pk, derive_shared_secret_sk, SharedSecret,
};
use ssb_crypto::{hash, Hash, Keypair};

/// Shared Secret A (client and server ephemeral keys)
#[derive(AsBytes, Clone)]
#[repr(C)]
pub struct SharedA(SharedSecret);
impl SharedA {
    // shared_secret_ab = nacl_scalarmult(
    //   client_ephemeral_sk,
    //   server_ephemeral_pk
    // )
    pub fn client_side(sk: &ClientEphSecretKey, pk: &ServerEphPublicKey) -> Option<SharedA> {
        derive_shared_secret(&sk.0, &pk.0).map(SharedA)
    }

    // shared_secret_ab = nacl_scalarmult(
    //   server_ephemeral_sk,
    //   client_ephemeral_pk
    // )
    pub fn server_side(sk: &ServerEphSecretKey, pk: &ClientEphPublicKey) -> Option<SharedA> {
        derive_shared_secret(&sk.0, &pk.0).map(SharedA)
    }

    pub(crate) fn hash(&self) -> SharedAHash {
        SharedAHash(hash(self.as_bytes()))
    }
}
#[derive(AsBytes)]
#[repr(C)]
pub(crate) struct SharedAHash(Hash);

/// Shared Secret B (client ephemeral key, server long-term key)
#[derive(AsBytes, Clone)]
#[repr(C)]
pub struct SharedB(SharedSecret);
impl SharedB {
    // shared_secret_aB = nacl_scalarmult(
    //   client_ephemeral_sk,
    //   pk_to_curve25519(server_longterm_pk)
    // )
    pub fn client_side(sk: &ClientEphSecretKey, pk: &ServerPublicKey) -> Option<SharedB> {
        // pk_to_curve(&pk.0)
        //     .and_then(|c| derive_shared_secret(&sk.0, &c))
        derive_shared_secret_pk(&sk.0, &pk.0).map(SharedB)
    }

    // shared_secret_aB = nacl_scalarmult(
    //   sk_to_curve25519(server_longterm_sk),
    //   client_ephemeral_pk
    // )
    pub fn server_side(kp: &Keypair, pk: &ClientEphPublicKey) -> Option<SharedB> {
        // sk_to_curve(&sk.0)
        //     .and_then(|c| derive_shared_secret(&c, &pk.0))
        derive_shared_secret_sk(&kp.secret, &pk.0).map(SharedB)
    }
}

/// Shared Secret C (client long-term key, server ephemeral key)
#[derive(AsBytes, Clone)]
#[repr(C)]
pub struct SharedC(SharedSecret);
impl SharedC {
    pub fn client_side(kp: &Keypair, pk: &ServerEphPublicKey) -> Option<SharedC> {
        // sk_to_curve(&sk.0)
        //     .and_then(|c| derive_shared_secret(&c, &pk.0))
        derive_shared_secret_sk(&kp.secret, &pk.0).map(SharedC)
    }

    pub fn server_side(sk: &ServerEphSecretKey, pk: &ClientPublicKey) -> Option<SharedC> {
        // pk_to_curve(&pk.0)
        //     .and_then(|c| derive_shared_secret(&sk.0, &c))
        derive_shared_secret_pk(&sk.0, &pk.0).map(SharedC)
    }
}
