use core::mem::size_of;

use crate::utils::{bytes, zero_nonce};
use crate::error::HandshakeError;

use super::*;
use super::shared_secret::*;


use ssb_crypto::{
    AuthTag,
    // KeyPair,
    PublicKey,
    Signature,
    sign_detached,
    verify_detached,
    NetworkKey,
    secretbox,
};

use ssb_crypto::hash::hash;


/// ## Message 1 (Client to Server)
/// Client proves that it knows the NetworkKey,
/// and sends its ephemeral public key.
#[repr(C, packed)]
pub struct ClientHello {
    hmac: AuthTag,
    eph_pk: ClientEphPublicKey,
}

impl ClientHello {
    pub const fn size() -> usize {
        size_of::<ClientHello>()
    }

    // concat(nacl_auth(msg: client_ephemeral_pk,
    //                  key: network_identifier),
    //        client_ephemeral_pk)
    pub fn new(eph_pk: &ClientEphPublicKey, net_key: &NetworkKey) -> ClientHello {
        ClientHello {
            hmac: net_key.authenticate(&eph_pk.0[..]),
            eph_pk: eph_pk.clone(),
        }
    }

    // client_hmac = first_32_bytes(msg1)
    // client_ephemeral_pk = last_32_bytes(msg1)
    pub fn from_slice(b: &[u8]) -> Result<ClientHello, HandshakeError> {
        if b.len() == size_of::<ClientHello>() {
            let (hmac_bytes, pk_bytes) = b.split_at(size_of::<AuthTag>());

            Ok(ClientHello {
                hmac: AuthTag::from_slice(&hmac_bytes)
                    .ok_or(HandshakeError::ClientHelloDeserializeFailed)?,

                eph_pk: ClientEphPublicKey::from_slice(&pk_bytes)
                    .ok_or(HandshakeError::ClientHelloDeserializeFailed)?,
            })
        } else {
            Err(HandshakeError::ClientHelloDeserializeFailed)
        }
    }

    // assert_nacl_auth_verify(
    //   authenticator: client_hmac,
    //   msg: client_ephemeral_pk,
    //   key: network_identifier)
    pub fn verify(self, net_key: &NetworkKey) -> Result<ClientEphPublicKey, HandshakeError> {
        if net_key.verify(&self.hmac, &self.eph_pk.0[..]) {
            Ok(self.eph_pk.clone())
        } else {
            Err(HandshakeError::ClientHelloVerifyFailed)
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

/// ## Message 2 (Server to Client)
/// Server proves that it knows the NetworkKey,
/// and sends its ephemeral public key.
#[repr(C, packed)]
pub struct ServerHello {
    hmac: AuthTag,
    eph_pk: ServerEphPublicKey,
}

impl ServerHello {
    pub const fn size() -> usize {
        size_of::<ServerHello>()
    }

    // concat(nacl_auth(msg: server_ephemeral_pk,
    //                  key: network_identifier),
    //        server_ephemeral_pk)
    pub fn new(eph_pk: &ServerEphPublicKey, net_key: &NetworkKey) -> ServerHello {
        ServerHello {
            hmac: net_key.authenticate(&eph_pk.0[..]),
            eph_pk: eph_pk.clone(),
        }
    }

    // server_hmac = first_32_bytes(msg2)
    // server_ephemeral_pk = last_32_bytes(msg2)
    pub fn from_slice(b: &[u8]) -> Result<ServerHello, HandshakeError> {
        if b.len() == size_of::<ServerHello>() {
            let (hmac_bytes, pk_bytes) = b.split_at(size_of::<AuthTag>());
            Ok(ServerHello {
                hmac: AuthTag::from_slice(&hmac_bytes)
                    .ok_or(HandshakeError::ServerHelloDeserializeFailed)?,
                eph_pk: ServerEphPublicKey::from_slice(&pk_bytes)
                    .ok_or(HandshakeError::ServerHelloDeserializeFailed)?,
                })
        } else {
            Err(HandshakeError::ServerHelloDeserializeFailed)
        }
    }

    // assert_nacl_auth_verify(
    //   authenticator: server_hmac,
    //   msg: server_ephemeral_pk,
    //   key: network_identifier
    // )
    pub fn verify(self, net_key: &NetworkKey) -> Result<ServerEphPublicKey, HandshakeError> {
        if net_key.verify(&self.hmac, &self.eph_pk.0[..]) {
            Ok(self.eph_pk.clone())
        } else {
            Err(HandshakeError::ServerHelloVerifyFailed)
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}


/// ## Message 3 (Client to Server)
pub struct ClientAuth(Vec<u8>);
impl ClientAuth {
    pub const fn size() -> usize {
        112
    }

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
        sk: &ClientSecretKey,
        pk: &ClientPublicKey,
        server_pk: &ServerPublicKey,
        net_key: &NetworkKey,
        shared_a: &SharedA,
        shared_b: &SharedB,
    ) -> ClientAuth {
        let client_sig = ClientAuthSignData::new(net_key, server_pk, shared_a).sign(&sk);

        let payload = ClientAuthPayload {
            client_sig,
            client_pk: pk.clone(),
        };

        let key = ClientAuthKeyData {
            net_key: net_key.clone(),
            shared_a: shared_a.clone(),
            shared_b: shared_b.clone(),
        }
        .into_key();
        let v = secretbox::seal(payload.as_slice(), &zero_nonce(), &key);
        ClientAuth(v)
    }

    pub fn from_buffer(b: Vec<u8>) -> Result<ClientAuth, HandshakeError> {
        if b.len() == ClientAuth::size() {
            Ok(ClientAuth(b))
        } else {
            Err(HandshakeError::ClientAuthDeserializeFailed)
        }
    }

    pub fn open_and_verify(
        self,
        server_pk: &ServerPublicKey,
        net_key: &NetworkKey,
        shared_a: &SharedA,
        shared_b: &SharedB,
    ) -> Result<(ClientSignature, ClientPublicKey), HandshakeError> {
        // TODO: return Result<_, ClientAuthUnsealError>
        // Open the box
        let payload = {
            let key = ClientAuthKeyData {
                net_key: net_key.clone(),
                shared_a: shared_a.clone(),
                shared_b: shared_b.clone(),
            }
            .into_key();
            let v = secretbox::open(&self.0, &zero_nonce(), &key)
                .map_err(|_| HandshakeError::ClientAuthOpenFailed)?;
            ClientAuthPayload::from_slice(&v)
                .ok_or(HandshakeError::ClientAuthVerifyFailed)?
        };

        let ok = ClientAuthSignData::new(net_key, server_pk, shared_a)
            .verify(&payload.client_sig, &payload.client_pk);
        if ok {
            Ok((payload.client_sig, payload.client_pk))
        } else {
            Err(HandshakeError::ClientAuthVerifyFailed)
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[repr(C, packed)]
struct ClientAuthSignData {
    net_key: NetworkKey,
    server_pk: ServerPublicKey,
    hash: SharedAHash,
}

impl ClientAuthSignData {
    fn new(
        net_key: &NetworkKey,
        server_pk: &ServerPublicKey,
        shared_a: &SharedA,
    ) -> ClientAuthSignData {
        ClientAuthSignData {
            net_key: net_key.clone(),
            server_pk: server_pk.clone(),
            hash: shared_a.hash(),
        }
    }

    fn sign(self, sk: &ClientSecretKey) -> ClientSignature {
        ClientSignature(sign_detached(self.as_slice(), &sk.0))
    }

    fn verify(self, sig: &ClientSignature, pk: &ClientPublicKey) -> bool {
        verify_detached(&sig.0, self.as_slice(), &pk.0)
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
}

#[repr(C, packed)]
struct ClientAuthKeyData {
    net_key: NetworkKey,
    shared_a: SharedA,
    shared_b: SharedB,
}
impl ClientAuthKeyData {
    fn into_key(self) -> secretbox::Key {
        let digest = unsafe { hash(bytes(&self)) };
        secretbox::Key::from_slice(&digest[..]).unwrap()
    }
}

#[repr(C, packed)]
struct ClientAuthPayload {
    client_sig: ClientSignature,
    client_pk: ClientPublicKey,
}

impl ClientAuthPayload {
    pub fn from_slice(b: &[u8]) -> Option<ClientAuthPayload> {
        if b.len() == size_of::<ClientAuthPayload>() {
            let (sig_bytes, pk_bytes) = b.split_at(size_of::<Signature>());
            Some(ClientAuthPayload {
                client_sig: ClientSignature(Signature::from_slice(&sig_bytes)?),
                client_pk: ClientPublicKey(PublicKey::from_slice(pk_bytes)?),
            })
        } else {
            None
        }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
}


/// ## Message 4 (Server to Client)
pub struct ServerAccept(Vec<u8>);
impl ServerAccept {
    pub const fn size() -> usize {
        80
    }

    pub fn new(
        sk: &ServerSecretKey,
        client_pk: &ClientPublicKey,
        net_key: &NetworkKey,
        client_sig: &ClientSignature,
        shared_a: &SharedA,
        shared_b: &SharedB,
        shared_c: &SharedC,
    ) -> ServerAccept {
        let sig = ServerAcceptSignData {
            net_key: net_key.clone(),
            sig: client_sig.clone(),
            client_pk: client_pk.clone(),
            hash: shared_a.hash(),
        }
        .sign(sk);

        let key = ServerAcceptKeyData {
            net_key: net_key.clone(),
            shared_a: shared_a.clone(),
            shared_b: shared_b.clone(),
            shared_c: shared_c.clone(),
        }
        .into_key();

        ServerAccept(secretbox::seal(&sig.0[..], &zero_nonce(), &key))
    }

    pub fn from_buffer(b: Vec<u8>) -> Result<ServerAccept, HandshakeError> {
        if b.len() == ServerAccept::size() {
            Ok(ServerAccept(b))
        } else {
            Err(HandshakeError::ServerAcceptDeserializeFailed)
        }
    }

    #[must_use]
    pub fn open_and_verify(
        self,
        client_sk: &ClientSecretKey,
        client_pk: &ClientPublicKey,
        server_pk: &ServerPublicKey,
        net_key: &NetworkKey,
        shared_a: &SharedA,
        shared_b: &SharedB,
        shared_c: &SharedC,
    ) -> Result<ServerAcceptVerificationToken, HandshakeError> {
        let server_sig = {
            let key = ServerAcceptKeyData {
                net_key: net_key.clone(),
                shared_a: shared_a.clone(),
                shared_b: shared_b.clone(),
                shared_c: shared_c.clone(),
            }
            .into_key();

            let v = secretbox::open(&self.0, &zero_nonce(), &key)
                .map_err(|_| HandshakeError::ServerAcceptOpenFailed)?;

            ServerSignature(Signature::from_slice(&v)
                            .ok_or(HandshakeError::ServerAcceptVerifyFailed)?)
        };
        // Note: this sig is computed earlier in ClientAuth::new(); could be stored.
        let client_sig = ClientAuthSignData::new(net_key, server_pk, shared_a).sign(&client_sk);

        let ok = ServerAcceptSignData {
            net_key: net_key.clone(),
            sig: client_sig,
            client_pk: client_pk.clone(),
            hash: shared_a.hash(),
        }
        .verify(&server_sig, server_pk);
        if ok {
            Ok(ServerAcceptVerificationToken(0))
        } else {
            Err(HandshakeError::ServerAcceptVerifyFailed)
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

pub struct ServerAcceptVerificationToken(u8);

#[repr(C, packed)]
struct ServerAcceptSignData {
    net_key: NetworkKey,
    sig: ClientSignature, // detached_signature_A
    client_pk: ClientPublicKey,
    hash: SharedAHash,
}

impl ServerAcceptSignData {
    fn sign(self, sk: &ServerSecretKey) -> Signature {
        sign_detached(self.as_slice(), &sk.0)
    }

    fn verify(self, sig: &ServerSignature, pk: &ServerPublicKey) -> bool {
        verify_detached(&sig.0, self.as_slice(), &pk.0)
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
}

#[repr(C, packed)]
struct ServerAcceptKeyData {
    net_key: NetworkKey,
    shared_a: SharedA,
    shared_b: SharedB,
    shared_c: SharedC,
}
impl ServerAcceptKeyData {
    fn into_key(self) -> secretbox::Key {
        let digest = unsafe { hash(bytes(&self)) };
        secretbox::Key::from_slice(&digest[..]).unwrap()
    }
}
