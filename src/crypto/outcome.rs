use crate::crypto::keys::*;
use crate::crypto::shared_secret::*;

use ssb_crypto::ephemeral::EphPublicKey;
use ssb_crypto::{hash, secretbox::*, Hash, NetworkKey, PublicKey};
use zerocopy::AsBytes;

/// The keys and nonces which are the result of a successful network handshake
/// used by [ssb-boxstream] to encrypt further communications.
///
/// [ssb-boxstream]: https://crates.io/crates/ssb-boxstream
pub struct HandshakeKeys {
    /// Used to decrypt messages sent by the other party.
    pub read_key: Key,
    pub read_starting_nonce: Nonce,

    /// Used to encrypt messages sent to the other party.
    pub write_key: Key,
    pub write_starting_nonce: Nonce,

    /// PublicKey of the remote peer
    pub peer_key: PublicKey,
}

fn build_shared_key(
    pk: &PublicKey,
    net_key: &NetworkKey,
    a: &SharedA,
    b: &SharedB,
    c: &SharedC,
) -> Key {
    // c2s: sha256( sha256(sha256(net_key + a + b + c)) + server_pk)
    // s2c: sha256( sha256(sha256(net_key + a + b + c)) + client_pk)

    let double_hash = {
        #[derive(AsBytes)]
        #[repr(C)]
        struct D(NetworkKey, SharedA, SharedB, SharedC);
        hash(hash(D(net_key.clone(), a.clone(), b.clone(), c.clone()).as_bytes()).as_bytes())
    };

    #[derive(AsBytes)]
    #[repr(C)]
    struct KeyHashData(Hash, PublicKey);
    Key(hash(KeyHashData(double_hash, *pk).as_bytes()).0)
}

/// Final shared key used to seal and open secret boxes (client to server)
pub fn client_to_server_key(
    server_pk: &ServerPublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> Key {
    build_shared_key(&server_pk.0, net_key, shared_a, shared_b, shared_c)
}

/// Final shared key used to seal and open secret boxes (server to client)
pub fn server_to_client_key(
    client_pk: &ClientPublicKey,
    net_key: &NetworkKey,
    shared_a: &SharedA,
    shared_b: &SharedB,
    shared_c: &SharedC,
) -> Key {
    build_shared_key(&client_pk.0, net_key, shared_a, shared_b, shared_c)
}

pub fn starting_nonce(netkey: &NetworkKey, pk: &EphPublicKey) -> Nonce {
    let hmac = netkey.authenticate(&pk.0);
    Nonce::from_slice(&hmac.0[..Nonce::SIZE]).unwrap()
}
