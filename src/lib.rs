//! Based on Duncan's fantastic
//! [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
//! ([repo](https://github.com/ssbc/scuttlebutt-protocol-guide)),
//! which he graciously released into the public domain.

#[macro_use] extern crate quick_error;
extern crate ssb_crypto;

use ssb_crypto::{
    AuthTag,
    // KeyPair,
    PublicKey,
    SecretKey,
    Signature,
    sign_detached,
    verify_detached,
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

use std::io;
use std::mem::size_of;
use std::slice;

// use sodiumoxide::utils::memzero;
// TODO: memzero our secrets, if sodiumoxide doesn't do it for us.

quick_error! {
    #[derive(Debug)]
    pub enum HandshakeError {
        Io(err: io::Error) {
            description(err.description())
        }

        ClientHelloDeserializeFailed {
            description("Failed to read client hello message")
        }
        ClientHelloVerifyFailed {
            description("Failed to verify client hello message")
        }

        ServerHelloDeserializeFailed {
            description("Failed to read server hello message")
        }
        ServerHelloVerifyFailed {
            description("Failed to verify server hello message")
        }

        ClientAuthDeserializeFailed {
            description("Failed to read client auth message")
        }
        ClientAuthOpenFailed {
            description("Failed to decrypt client auth message")
        }
        ClientAuthVerifyFailed {
            description("Failed to verify client auth message")
        }

        ServerAcceptDeserializeFailed {
            description("Failed to read server accept message")
        }
        ServerAcceptOpenFailed {
            description("Failed to decrypt server accept message")
        }
        ServerAcceptVerifyFailed {
            description("Failed to verify server accept message")
        }

        SharedAInvalid {}
        SharedBInvalid {}
        SharedCInvalid {}
    }
}
impl From<io::Error> for HandshakeError {
    fn from(err: io::Error) -> HandshakeError {
        HandshakeError::Io(err)
    }
}
impl From<HandshakeError> for io::Error {
    fn from(err: HandshakeError) -> io::Error {
        match err {
            HandshakeError::Io(err) => err,
            err => io::Error::new(io::ErrorKind::InvalidData, err)
        }
    }
}



use HandshakeError::*;

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

/// ## Message 1 (Client to Server)
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

                eph_pk: ClientEphPublicKey(
                    EphPublicKey::from_slice(&pk_bytes)
                        .ok_or(HandshakeError::ClientHelloDeserializeFailed)?,
                ),
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
                eph_pk: ServerEphPublicKey(
                    EphPublicKey::from_slice(&pk_bytes)
                        .ok_or(HandshakeError::ServerHelloDeserializeFailed)?,
                ),
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
            ClientAuthPayload::from_slice(&v).ok_or(ClientAuthVerifyFailed)?
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
            Err(ServerAcceptDeserializeFailed)
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
    ) -> Result<(), HandshakeError> {
        let server_sig = {
            let key = ServerAcceptKeyData {
                net_key: net_key.clone(),
                shared_a: shared_a.clone(),
                shared_b: shared_b.clone(),
                shared_c: shared_c.clone(),
            }
            .into_key();

            let v = secretbox::open(&self.0, &zero_nonce(), &key)
                .map_err(|_| ServerAcceptOpenFailed)?;

            ServerSignature(Signature::from_slice(&v).ok_or(ServerAcceptVerifyFailed)?)
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
            Ok(())
        } else {
            Err(ServerAcceptVerifyFailed)
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

unsafe fn bytes<T>(t: &T) -> &[u8] {
    // TODO: is it possible to check if T is a pointer type?

    let p = t as *const T as *const u8;
    slice::from_raw_parts(p, size_of::<T>())
}
