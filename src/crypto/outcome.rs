use super::message::ServerAcceptVerificationToken;
use super::shared_secret::*;
use crate::*;
use ssb_crypto::{
    handshake::HandshakeKeys, hash::hash, hash::Digest, secretbox, NetworkKey, PublicKey,
};

pub fn client_side_handshake_keys(
    _v: ServerAcceptVerificationToken,
    pk: &ClientPublicKey,
    server_pk: &ServerPublicKey,
    eph_pk: &ClientEphPublicKey,
    server_eph_pk: &ServerEphPublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> HandshakeKeys {
    HandshakeKeys {
        read_key: server_to_client_key(&pk, &net_key, &shared_a, &shared_b, &shared_c),
        read_noncegen: NonceGen::new(&eph_pk.0, &net_key),

        write_key: client_to_server_key(&server_pk, &net_key, &shared_a, &shared_b, &shared_c),
        write_noncegen: NonceGen::new(&server_eph_pk.0, &net_key),
    }
}

pub fn server_side_handshake_keys(
    pk: &ServerPublicKey,
    client_pk: &ClientPublicKey,
    eph_pk: &ServerEphPublicKey,
    client_eph_pk: &ClientEphPublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> HandshakeKeys {
    HandshakeKeys {
        read_key: client_to_server_key(&pk, &net_key, &shared_a, &shared_b, &shared_c),
        read_noncegen: NonceGen::new(&eph_pk.0, &net_key),

        write_key: server_to_client_key(&client_pk, &net_key, &shared_a, &shared_b, &shared_c),
        write_noncegen: NonceGen::new(&client_eph_pk.0, &net_key),
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
        let h1 = unsafe { hash(utils::bytes(&self)) };
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
        let digest = unsafe { hash(utils::bytes(&self)) };
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
        pk: *pk,
    }
    .into_key()
}

/// Final shared key used to seal and open secret boxes (client to server)
fn client_to_server_key(
    server_pk: &ServerPublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> secretbox::Key {
    build_shared_key(&server_pk.0, net_key, shared_a, shared_b, shared_c)
}

/// Final shared key used to seal and open secret boxes (server to client)
fn server_to_client_key(
    server_pk: &ClientPublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> secretbox::Key {
    build_shared_key(&server_pk.0, net_key, shared_a, shared_b, shared_c)
}
