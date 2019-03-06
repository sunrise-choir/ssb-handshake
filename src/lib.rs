//! Based on Duncan's fantastic
//! [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
//! ([repo](https://github.com/ssbc/scuttlebutt-protocol-guide)),
//! which he graciously released into the public domain.

extern crate libsodium_sys;
extern crate sodiumoxide;

use std::io;
use std::slice;
use std::mem::size_of;

use sodiumoxide::crypto::{auth, box_, sign, scalarmult, secretbox};

use auth::{Key as AuthKey, Tag as HmacAuthTag};
use box_::{PublicKey as CurvePublicKey, SecretKey as CurveSecretKey};
use sign::{sign_detached, verify_detached, PublicKey, SecretKey, Signature};
use scalarmult::{scalarmult, Scalar, GroupElement};

use sodiumoxide::crypto::hash::sha256::{hash, Digest as ShaDigest};
// use sodiumoxide::utils::memzero;
// TODO: memzero our secrets, if sodiumoxide doesn't do it for us.

use libsodium_sys::{crypto_sign_ed25519_pk_to_curve25519,
                    crypto_sign_ed25519_sk_to_curve25519};

#[derive(Debug)]
pub enum HandshakeError {
    Io(io::Error),

    ClientHelloDeserializeFailed,
    ClientHelloVerifyFailed,

    ServerHelloDeserializeFailed,
    ServerHelloVerifyFailed,

    ClientAuthDeserializeFailed,
    ClientAuthOpenFailed,
    ClientAuthVerifyFailed,

    ServerAcceptDeserializeFailed,
    ServerAcceptOpenFailed,
    ServerAcceptVerifyFailed,

    SharedAInvalid,
    SharedBInvalid,
    SharedCInvalid,
}
impl From<io::Error> for HandshakeError {
    fn from(err: io::Error) -> HandshakeError {
        HandshakeError::Io(err)
    }
}

use HandshakeError::*;

/// Client long-term public key
#[derive(Clone)]
pub struct ClientPublicKey(PublicKey);
impl ClientPublicKey {
    pub fn from_slice(b: &[u8]) -> Option<ClientPublicKey> {
        Some(ClientPublicKey(PublicKey::from_slice(b)?))
    }
}

/// Client long-term secret key
pub struct ClientSecretKey(SecretKey);
impl ClientSecretKey {
    pub fn from_slice(b: &[u8]) -> Option<ClientSecretKey> {
        Some(ClientSecretKey(SecretKey::from_slice(b)?))
    }
}

/// Server long-term public key; known to client prior to the handshake
#[derive(Clone)]
pub struct ServerPublicKey(PublicKey);
impl ServerPublicKey {
    pub fn from_slice(b: &[u8]) -> Option<ServerPublicKey> {
        Some(ServerPublicKey(PublicKey::from_slice(b)?))
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Server long-term secret key
pub struct ServerSecretKey(SecretKey);
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
pub struct ClientEphPublicKey(CurvePublicKey);
/// Client ephemeral secret key
pub struct ClientEphSecretKey(CurveSecretKey);

/// Server ephemeral public key (generated anew for each connection)
#[derive(Clone)]
pub struct ServerEphPublicKey(CurvePublicKey);
/// Server ephemeral secret key
pub struct ServerEphSecretKey(CurveSecretKey);

/// 32-byte network id, known by client and server. Usually `NetworkId::SSB_MAIN_NET`
#[derive(Clone)]
pub struct NetworkId(AuthKey);
impl NetworkId {
    pub const SSB_MAIN_NET: NetworkId = NetworkId(AuthKey([
        0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8,
        0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc, 0x5d,
        0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23,
        0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb]));

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
    pub fn from_slice(b: &[u8]) -> Option<NetworkId> {
        Some(NetworkId(AuthKey::from_slice(b)?))
    }

    pub const fn size() -> usize {
        32
    }
}


pub mod client {
    use super::*;
    use sodiumoxide::crypto::{box_, sign};

    pub fn generate_eph_keypair() -> (ClientEphPublicKey, ClientEphSecretKey) {
        let (pk, sk) = box_::gen_keypair();
        (ClientEphPublicKey(pk), ClientEphSecretKey(sk))
    }

    pub fn generate_longterm_keypair() -> (ClientPublicKey, ClientSecretKey) {
        let (pk, sk) = sign::gen_keypair();
        (ClientPublicKey(pk), ClientSecretKey(sk))
    }
}

pub mod server {
    use super::*;
    use sodiumoxide::crypto::{box_, sign};

    pub fn generate_eph_keypair() -> (ServerEphPublicKey, ServerEphSecretKey) {
        let (pk, sk) = box_::gen_keypair();
        (ServerEphPublicKey(pk), ServerEphSecretKey(sk))
    }

    pub fn generate_longterm_keypair() -> (ServerPublicKey, ServerSecretKey) {
        let (pk, sk) = sign::gen_keypair();
        (ServerPublicKey(pk), ServerSecretKey(sk))
    }
}


/// ## Message 1 (Client to Server)
#[repr(C, packed)]
pub struct ClientHello {
    hmac: HmacAuthTag,
    eph_pk: ClientEphPublicKey,
}

impl ClientHello {
    pub const fn size() -> usize {
        size_of::<ClientHello>()
    }

    // concat(nacl_auth(msg: client_ephemeral_pk,
    //                  key: network_identifier),
    //        client_ephemeral_pk)
    pub fn new(eph_pk: &ClientEphPublicKey, net_id: &NetworkId) -> ClientHello {
        ClientHello {
            hmac: auth::authenticate(&eph_pk.0[..], &net_id.0),
            eph_pk: eph_pk.clone(),
        }
    }

    // client_hmac = first_32_bytes(msg1)
    // client_ephemeral_pk = last_32_bytes(msg1)
    pub fn from_slice(b: &[u8]) -> Result<ClientHello, HandshakeError> {
        if b.len() == size_of::<ClientHello>() {
            let (hmac_bytes, pk_bytes) = b.split_at(size_of::<HmacAuthTag>());

            Ok(ClientHello {
                hmac: HmacAuthTag::from_slice(&hmac_bytes)
                    .ok_or(HandshakeError::ClientHelloDeserializeFailed)?,

                eph_pk: ClientEphPublicKey(
                    CurvePublicKey::from_slice(&pk_bytes)
                        .ok_or(HandshakeError::ClientHelloDeserializeFailed)?),
            })
        } else {
            Err(HandshakeError::ClientHelloDeserializeFailed)
        }
    }

    // assert_nacl_auth_verify(
    //   authenticator: client_hmac,
    //   msg: client_ephemeral_pk,
    //   key: network_identifier)
    pub fn verify(&self, net_id: &NetworkId) -> Result<ClientEphPublicKey, HandshakeError> {
        if auth::verify(&self.hmac, &self.eph_pk.0[..], &net_id.0) {
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
    hmac: HmacAuthTag,
    eph_pk: ServerEphPublicKey,
}

impl ServerHello {
    pub const fn size() -> usize {
        size_of::<ServerHello>()
    }

    // concat(nacl_auth(msg: server_ephemeral_pk,
    //                  key: network_identifier),
    //        server_ephemeral_pk)
    pub fn new(eph_pk: &ServerEphPublicKey, net_id: &NetworkId) -> ServerHello {
        ServerHello {
            hmac: auth::authenticate(&eph_pk.0[..], &net_id.0),
            eph_pk: eph_pk.clone(),
        }
    }

    // server_hmac = first_32_bytes(msg2)
    // server_ephemeral_pk = last_32_bytes(msg2)
    pub fn from_slice(b: &[u8]) -> Result<ServerHello, HandshakeError> {
        if b.len() == size_of::<ServerHello>() {
            let (hmac_bytes, pk_bytes) = b.split_at(size_of::<HmacAuthTag>());
            Ok(ServerHello {
                hmac: HmacAuthTag::from_slice(&hmac_bytes)
                    .ok_or(HandshakeError::ServerHelloDeserializeFailed)?,
                eph_pk: ServerEphPublicKey(
                    CurvePublicKey::from_slice(&pk_bytes)
                        .ok_or(HandshakeError::ServerHelloDeserializeFailed)?),
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
    pub fn verify(&self, net_id: &NetworkId) -> Result<ServerEphPublicKey, HandshakeError> {
        if auth::verify(&self.hmac, &self.eph_pk.0[..], &net_id.0) {
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
pub struct SharedA(GroupElement);
impl SharedA {

    // shared_secret_ab = nacl_scalarmult(
    //   client_ephemeral_sk,
    //   server_ephemeral_pk
    // )
    pub fn client_side(sk: &ClientEphSecretKey, pk: &ServerEphPublicKey)
                       -> Result<SharedA, HandshakeError> {
        derive_shared_secret(&sk.0, &pk.0)
            .map(SharedA)
            .ok_or(HandshakeError::SharedAInvalid)
    }

    // shared_secret_ab = nacl_scalarmult(
    //   server_ephemeral_sk,
    //   client_ephemeral_pk
    // )
    pub fn server_side(sk: &ServerEphSecretKey, pk: &ClientEphPublicKey)
                       -> Result<SharedA, HandshakeError> {
        derive_shared_secret(&sk.0, &pk.0)
            .map(SharedA)
            .ok_or(HandshakeError::SharedAInvalid)
    }

    fn hash(&self) -> SharedAHash {
        SharedAHash(hash(&self.0[..]))
    }
}
struct SharedAHash(ShaDigest);


/// Shared Secret B (client ephemeral key, server long-term key)
#[derive(Clone)]
pub struct SharedB(GroupElement);
impl SharedB {

    // shared_secret_aB = nacl_scalarmult(
    //   client_ephemeral_sk,
    //   pk_to_curve25519(server_longterm_pk)
    // )
    pub fn client_side(sk: &ClientEphSecretKey, pk: &ServerPublicKey)
                   -> Result<SharedB, HandshakeError>
    {
        pk_to_curve(&pk.0)
            .and_then(|c| derive_shared_secret(&sk.0, &c))
            .map(SharedB)
            .ok_or(HandshakeError::SharedBInvalid)
    }

    // shared_secret_aB = nacl_scalarmult(
    //   sk_to_curve25519(server_longterm_sk),
    //   client_ephemeral_pk
    // )
    pub fn server_side(sk: &ServerSecretKey, pk: &ClientEphPublicKey)
                   -> Result<SharedB, HandshakeError>
    {
        sk_to_curve(&sk.0)
            .and_then(|c| derive_shared_secret(&c, &pk.0))
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
    pub fn new(sk: &ClientSecretKey, pk: &ClientPublicKey, server_pk: &ServerPublicKey,
               net_id: &NetworkId, shared_a: &SharedA, shared_b: &SharedB)
               -> ClientAuth {

        let client_sig = ClientAuthSignData::new(net_id, server_pk, shared_a).sign(&sk);

        let payload = ClientAuthPayload {
            client_sig,
            client_pk: pk.clone()
        };

        let key = ClientAuthKeyData {
            net_id: net_id.clone(),
            shared_a: shared_a.clone(),
            shared_b: shared_b.clone(),
        }.as_key();
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

    pub fn open_and_verify(&self,
                           server_pk: &ServerPublicKey,
                           net_id: &NetworkId,
                           shared_a: &SharedA,
                           shared_b: &SharedB)
                           -> Result<(ClientSignature, ClientPublicKey), HandshakeError> {

        // TODO: return Result<_, ClientAuthUnsealError>
        // Open the box
        let payload = {
            let key = ClientAuthKeyData {
                net_id: net_id.clone(),
                shared_a: shared_a.clone(),
                shared_b: shared_b.clone(),
            }.as_key();
            let v = secretbox::open(&self.0, &zero_nonce(), &key)
                .map_err(|_| HandshakeError::ClientAuthOpenFailed)?;
            ClientAuthPayload::from_slice(&v)
                .ok_or(ClientAuthVerifyFailed)?
        };

        let ok = ClientAuthSignData::new(net_id, server_pk, shared_a)
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
    net_id: NetworkId,
    server_pk: ServerPublicKey,
    hash: SharedAHash,
}

impl ClientAuthSignData {
    fn new(net_id: &NetworkId, server_pk: &ServerPublicKey, shared_a: &SharedA) -> ClientAuthSignData {
        ClientAuthSignData {
            net_id: net_id.clone(),
            server_pk: server_pk.clone(),
            hash: shared_a.hash(),
        }
    }
    fn sign(&self, sk: &ClientSecretKey) -> ClientSignature {
        ClientSignature(sign_detached(self.as_slice(), &sk.0))
    }

    fn verify(&self, sig: &ClientSignature, pk: &ClientPublicKey) -> bool {
        verify_detached(&sig.0, self.as_slice(), &pk.0)
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
}


#[repr(C, packed)]
struct ClientAuthKeyData {
    net_id: NetworkId,
    shared_a: SharedA,
    shared_b: SharedB,
}
impl ClientAuthKeyData {
    fn as_key(&self) -> secretbox::Key {
        let digest = unsafe { hash(bytes(self)) };
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
pub struct SharedC(GroupElement);
impl SharedC {

    pub fn client_side(sk: &ClientSecretKey, pk: &ServerEphPublicKey)
                       -> Result<SharedC, HandshakeError> {
        sk_to_curve(&sk.0)
            .and_then(|c| derive_shared_secret(&c, &pk.0))
            .map(SharedC)
            .ok_or(HandshakeError::SharedCInvalid)
    }

    pub fn server_side(sk: &ServerEphSecretKey, pk: &ClientPublicKey)
                       -> Result<SharedC, HandshakeError> {
        pk_to_curve(&pk.0)
            .and_then(|c| derive_shared_secret(&sk.0, &c))
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

    pub fn new(sk: &ServerSecretKey, client_pk: &ClientPublicKey,
           net_id: &NetworkId, client_sig: &ClientSignature,
           shared_a: &SharedA, shared_b: &SharedB,
           shared_c: &SharedC)
           -> ServerAccept
    {

        let sig = ServerAcceptSignData {
            net_id: net_id.clone(),
            sig: client_sig.clone(),
            client_pk: client_pk.clone(),
            hash: shared_a.hash()
        }.sign(sk);

        let key = ServerAcceptKeyData {
            net_id: net_id.clone(),
            shared_a: shared_a.clone(),
            shared_b: shared_b.clone(),
            shared_c: shared_c.clone(),
        }.as_key();

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
    pub fn open_and_verify(&self,
                           client_sk: &ClientSecretKey,
                           client_pk: &ClientPublicKey,
                           server_pk: &ServerPublicKey,
                           net_id: &NetworkId,
                           shared_a: &SharedA,
                           shared_b: &SharedB,
                           shared_c: &SharedC)
                           -> Result<(), HandshakeError>
    {
        let server_sig = {
            let key = ServerAcceptKeyData {
                net_id: net_id.clone(),
                shared_a: shared_a.clone(),
                shared_b: shared_b.clone(),
                shared_c: shared_c.clone(),
            }.as_key();

            let v = secretbox::open(&self.0, &zero_nonce(), &key)
                .map_err(|_| ServerAcceptOpenFailed)?;

            ServerSignature(Signature::from_slice(&v).ok_or(ServerAcceptVerifyFailed)?)
        };
        // Note: this sig is computed earlier in ClientAuth::new(); could be stored.
        let client_sig = ClientAuthSignData::new(net_id, server_pk, shared_a).sign(&client_sk);

        let ok = ServerAcceptSignData {
            net_id: net_id.clone(),
            sig: client_sig,
            client_pk: client_pk.clone(),
            hash: shared_a.hash()
        }.verify(&server_sig, server_pk);
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
    net_id: NetworkId,
    sig: ClientSignature, // detached_signature_A
    client_pk: ClientPublicKey,
    hash: SharedAHash,
}

impl ServerAcceptSignData {
    fn sign(&self, sk: &ServerSecretKey) -> Signature {
        sign_detached(self.as_slice(), &sk.0)
    }

    fn verify(&self, sig: &ServerSignature, pk: &ServerPublicKey) -> bool {
        verify_detached(&sig.0, self.as_slice(), &pk.0)
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
}

#[repr(C, packed)]
struct ServerAcceptKeyData {
    net_id: NetworkId,
    shared_a: SharedA,
    shared_b: SharedB,
    shared_c: SharedC,
}
impl ServerAcceptKeyData {
    fn as_key(&self) -> secretbox::Key {
        let digest = unsafe { hash(bytes(self)) };
        secretbox::Key::from_slice(&digest[..]).unwrap()
    }
}



struct SharedKeyHash(ShaDigest);

#[repr(C, packed)]
struct SharedKeyHashData {
    net_id: NetworkId,
    shared_a: SharedA,
    shared_b: SharedB,
    shared_c: SharedC,
}
impl SharedKeyHashData {
    fn double_hash(&self) -> SharedKeyHash {
        let h1 = unsafe { hash(bytes(self)) };
        SharedKeyHash(hash(&h1[..]))
    }
}

#[repr(C, packed)]
struct SharedKeyData {
    double_hash: SharedKeyHash,
    pk: PublicKey,
}
impl SharedKeyData {
    fn as_key(&self) -> secretbox::Key {
        let digest = unsafe { hash(bytes(self)) };
        secretbox::Key::from_slice(&digest[..]).unwrap()
    }
}

fn build_shared_key(pk: &PublicKey,
                    net_id: &NetworkId,
                    shared_a: &SharedA,
                    shared_b: &SharedB,
                    shared_c: &SharedC) -> secretbox::Key {

    // c2s: sha256( sha256(sha256(net_id + a + b + c)) + server_pk)
    // s2c: sha256( sha256(sha256(net_id + a + b + c)) + client_pk)

    let double_hash = SharedKeyHashData {
        net_id: net_id.clone(),
        shared_a: shared_a.clone(),
        shared_b: shared_b.clone(),
        shared_c: shared_c.clone(),
    }.double_hash();

    SharedKeyData {
        double_hash,
        pk: pk.clone(),
    }.as_key()
}

/// Final shared secret used to encrypt secret boxes (client to server)
pub struct ClientToServerKey(secretbox::Key);
impl ClientToServerKey {
    pub fn new(server_pk: &ServerPublicKey,
           net_id: &NetworkId,
           shared_a: &SharedA,
           shared_b: &SharedB,
           shared_c: &SharedC) -> ClientToServerKey {

        ClientToServerKey(build_shared_key(&server_pk.0, net_id,
                                           shared_a, shared_b, shared_c))
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Final shared secret used to encrypt secret boxes (server to client)
pub struct ServerToClientKey(secretbox::Key);
impl ServerToClientKey {
    pub fn new(server_pk: &ClientPublicKey,
           net_id: &NetworkId,
           shared_a: &SharedA,
           shared_b: &SharedB,
           shared_c: &SharedC) -> ServerToClientKey {

        ServerToClientKey(build_shared_key(&server_pk.0, net_id,
                                           shared_a, shared_b, shared_c))
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

struct NonceGen {
    next_nonce: secretbox::Nonce
}

impl NonceGen {
    fn new(pk: &CurvePublicKey, net_id: &NetworkId) -> NonceGen {
        let hmac = auth::authenticate(&pk[..], &net_id.0);
        const N: usize = size_of::<secretbox::Nonce>();
        NonceGen {
            next_nonce: secretbox::Nonce::from_slice(&hmac[..N]).unwrap()
        }
    }

    fn next(&mut self) -> secretbox::Nonce {
        let n = self.next_nonce.clone();

        // Increment the nonce as a big-endian u24
        for byte in self.next_nonce.0.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        n
    }
}

/// Nonce for a client-to-server secret box
pub struct ClientToServerNonce(secretbox::Nonce);
impl ClientToServerNonce {
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Generator of nonces for client-to-server secret boxes
pub struct ClientToServerNonceGen(NonceGen);
impl ClientToServerNonceGen {
    pub fn new(server_eph_pk: &ServerEphPublicKey, net_id: &NetworkId) -> ClientToServerNonceGen {
        ClientToServerNonceGen(NonceGen::new(&server_eph_pk.0, net_id))
    }

    #[must_use]
    pub fn next(&mut self) -> ClientToServerNonce {
        ClientToServerNonce(self.0.next())
    }
}

/// Nonce for a server-to-client secret box
pub struct ServerToClientNonce(secretbox::Nonce);
impl ServerToClientNonce {
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Generator of nonces for client-to-server secret boxes
pub struct ServerToClientNonceGen(NonceGen);
impl ServerToClientNonceGen {
    pub fn new(client_eph_pk: &ClientEphPublicKey, net_id: &NetworkId) -> ServerToClientNonceGen {
        ServerToClientNonceGen(NonceGen::new(&client_eph_pk.0, net_id))
    }

    #[must_use]
    pub fn next(&mut self) -> ServerToClientNonce {
        ServerToClientNonce(self.0.next())
    }
}


fn zero_nonce() -> secretbox::Nonce {
    secretbox::Nonce::from_slice(&[0u8; size_of::<secretbox::Nonce>()]) .unwrap()
}

unsafe fn bytes<T>(t: &T) -> &[u8] {
    // TODO: is it possible to check if T is a pointer type?

    let p = t as *const T as *const u8;
    slice::from_raw_parts(p, size_of::<T>())
}

fn derive_shared_secret(our_sec: &CurveSecretKey, their_pub: &CurvePublicKey) -> Option<GroupElement> {
    // Benchmarks suggest that these "copies" get optimized away.
    let n = Scalar::from_slice(&our_sec[..])?;
    let p = GroupElement::from_slice(&their_pub[..])?;
    scalarmult(&n, &p).ok()
}

fn pk_to_curve(k: &PublicKey) -> Option<CurvePublicKey> {
    let mut buf = [0; size_of::<CurvePublicKey>()];

    let ok = unsafe {
        crypto_sign_ed25519_pk_to_curve25519(buf.as_mut_ptr(), k.0.as_ptr()) == 0
    };

    if ok {
        CurvePublicKey::from_slice(&buf)
    } else {
        None
    }
}

fn sk_to_curve(k: &SecretKey) -> Option<CurveSecretKey> {
    let mut buf = [0; size_of::<CurveSecretKey>()];

    let ok = unsafe {
        crypto_sign_ed25519_sk_to_curve25519(buf.as_mut_ptr(), k.0.as_ptr()) == 0
    };

    if ok {
        CurveSecretKey::from_slice(&buf)
    } else {
        None
    }
}
