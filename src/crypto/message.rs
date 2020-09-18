//! Message payloads that are sent between the client and server.
//!
//! These are implemented as #[repr(C, packed)] structs; the byte slice
//! representation of each struct is used directly for signing, etc,
//! rather than explicitly creating a buffer and copying the bytes of
//! each part of the message into it.

use crate::bytes::as_ref;
use crate::crypto::{keys::*, shared_secret::*};

use ssb_crypto::hash;
use ssb_crypto::secretbox::{self, Hmac, Nonce};
use ssb_crypto::{Keypair, NetworkAuth, NetworkKey, Signature};
use zerocopy::{AsBytes, FromBytes};

/// ## Message 1 (Client to Server)
/// Client proves that it knows the NetworkKey,
/// and sends its ephemeral public key.
#[derive(AsBytes, FromBytes)]
#[repr(C)]
pub struct ClientHello(NetworkAuth, ClientEphPublicKey);

impl ClientHello {
    // concat(nacl_auth(msg: client_ephemeral_pk,
    //                  key: network_identifier),
    //        client_ephemeral_pk)
    pub fn new(eph_pk: &ClientEphPublicKey, net_key: &NetworkKey) -> ClientHello {
        ClientHello(net_key.authenticate(eph_pk.as_bytes()), *eph_pk)
    }

    // assert_nacl_auth_verify(
    //   authenticator: client_hmac,
    //   msg: client_ephemeral_pk,
    //   key: network_identifier)
    pub fn verify(&self, net_key: &NetworkKey) -> Option<ClientEphPublicKey> {
        let ClientHello(hmac, eph_pk) = self;
        if net_key.verify(hmac, eph_pk.as_bytes()) {
            Some(*eph_pk)
        } else {
            None
        }
    }
}

/// ## Message 2 (Server to Client)
/// Server proves that it knows the NetworkKey,
/// and sends its ephemeral public key.
#[derive(AsBytes, FromBytes)]
#[repr(C)]
pub struct ServerHello(NetworkAuth, ServerEphPublicKey);

impl ServerHello {
    // concat(nacl_auth(msg: server_ephemeral_pk,
    //                  key: network_identifier),
    //        server_ephemeral_pk)
    pub fn new(eph_pk: &ServerEphPublicKey, net_key: &NetworkKey) -> ServerHello {
        ServerHello(net_key.authenticate(eph_pk.as_bytes()), *eph_pk)
    }

    // assert_nacl_auth_verify(
    //   authenticator: server_hmac,
    //   msg: server_ephemeral_pk,
    //   key: network_identifier
    // )
    pub fn verify(&self, net_key: &NetworkKey) -> Option<ServerEphPublicKey> {
        let ServerHello(hmac, eph_pk) = self;
        if net_key.verify(hmac, eph_pk.as_bytes()) {
            Some(*eph_pk)
        } else {
            None
        }
    }
}

/// ## Message 3 (Client to Server)
#[repr(C)]
pub struct ClientAuth(Hmac, [u8; 96]);
impl ClientAuth {
    // detached_signature_A = nacl_sign_detached(
    //   msg: concat(
    //     network_identifier,
    //     server_longterm_pk,
    //     sha256(shared_secret_ab)
    //   ),
    //   key: client_longterm_sk
    // )
    // nacl_secret_box(
    //   msg: concat(
    //     detached_signature_A,
    //     client_longterm_pk
    //   ),
    //   nonce: 24_bytes_of_zeros,
    //   key: sha256(
    //     concat(
    //       network_identifier,
    //       shared_secret_ab,
    //       shared_secret_aB
    //     )
    //   )
    // )
    pub fn new(
        kp: &Keypair,
        server_pk: &ServerPublicKey,
        net_key: &NetworkKey,
        sa: &SharedA,
        sb: &SharedB,
    ) -> ClientAuth {
        let payload = ClientAuthPayload(
            ClientSignature(
                kp.sign(ClientAuthSignData(net_key.clone(), *server_pk, sa.hash()).as_bytes()),
            ),
            ClientPublicKey(kp.public),
        );
        let mut buf = [0; 96];
        buf.copy_from_slice(payload.as_bytes());

        let hmac = client_auth_key(net_key, sa, sb).seal(&mut buf, &Nonce::zero());
        ClientAuth(hmac, buf)
    }

    pub fn verify(
        &mut self,
        kp: &Keypair,
        net_key: &NetworkKey,
        sa: &SharedA,
        sb: &SharedB,
    ) -> Option<(ClientSignature, ClientPublicKey)> {
        let ClientAuth(hmac, buf) = self;
        if !client_auth_key(net_key, sa, sb).open(buf, &hmac, &Nonce::zero()) {
            return None;
        }

        let ClientAuthPayload(sig, client_pk) = as_ref(buf);
        let signdata = ClientAuthSignData(net_key.clone(), ServerPublicKey(kp.public), sa.hash());
        if client_pk.0.verify(&sig.0, signdata.as_bytes()) {
            Some((*sig, *client_pk))
        } else {
            None
        }
    }
}

unsafe impl AsBytes for ClientAuth {
    fn only_derive_is_allowed_to_implement_this_trait() {}
}
unsafe impl FromBytes for ClientAuth {
    fn only_derive_is_allowed_to_implement_this_trait() {}
}

#[derive(AsBytes)]
#[repr(C)]
struct ClientAuthSignData(NetworkKey, ServerPublicKey, SharedAHash);

fn client_auth_key(net_key: &NetworkKey, sa: &SharedA, sb: &SharedB) -> secretbox::Key {
    #[derive(AsBytes)]
    #[repr(C)]
    struct D(NetworkKey, SharedA, SharedB);

    secretbox::Key(hash(D(net_key.clone(), sa.clone(), sb.clone()).as_bytes()).0)
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct ClientAuthPayload(ClientSignature, ClientPublicKey);

/// ## Message 4 (Server to Client)
#[derive(AsBytes, FromBytes)]
#[repr(C)]
pub struct ServerAccept(Hmac, [u8; 64]);
impl ServerAccept {
    pub fn new(
        kp: &Keypair,
        client_pk: &ClientPublicKey,
        net_key: &NetworkKey,
        client_sig: &ClientSignature,
        sa: &SharedA,
        sb: &SharedB,
        sc: &SharedC,
    ) -> ServerAccept {
        let Signature(mut sig) = kp.sign(
            ServerAcceptSignData(net_key.clone(), *client_sig, *client_pk, sa.hash()).as_bytes(),
        );

        let hmac = server_accept_key(net_key, sa, sb, sc).seal(&mut sig, &Nonce::zero());
        ServerAccept(hmac, sig)
    }

    /// Performed by the client
    #[must_use]
    pub fn verify(
        &self,
        kp: &Keypair,
        server_pk: &ServerPublicKey,
        net_key: &NetworkKey,
        sa: &SharedA,
        sb: &SharedB,
        sc: &SharedC,
    ) -> Option<()> {
        let server_sig = {
            let ServerAccept(hmac, mut buf) = self;
            if !server_accept_key(net_key, sa, sb, sc).open(&mut buf, &hmac, &Nonce::zero()) {
                return None;
            }
            ServerSignature(Signature(buf))
        };
        let client_sig = ClientSignature(
            kp.sign(ClientAuthSignData(net_key.clone(), *server_pk, sa.hash()).as_bytes()),
        );

        if server_pk.0.verify(
            &server_sig.0,
            ServerAcceptSignData(
                net_key.clone(),
                client_sig,
                ClientPublicKey(kp.public),
                sa.hash(),
            )
            .as_bytes(),
        ) {
            Some(())
        } else {
            None
        }
    }
}

#[derive(AsBytes)]
#[repr(C)]
struct ServerAcceptSignData(NetworkKey, ClientSignature, ClientPublicKey, SharedAHash);

fn server_accept_key(
    net_key: &NetworkKey,
    a: &SharedA,
    b: &SharedB,
    c: &SharedC,
) -> secretbox::Key {
    #[derive(AsBytes)]
    #[repr(C)]
    struct D(NetworkKey, SharedA, SharedB, SharedC);
    secretbox::Key(hash(D(net_key.clone(), a.clone(), b.clone(), c.clone()).as_bytes()).0)
}
