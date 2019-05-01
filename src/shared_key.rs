use crate::*;
use crate::shared_secret::*;
use ssb_crypto::{
    hash::Digest,
    hash::hash,
    PublicKey,
    NetworkKey,
    secretbox,
};


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
