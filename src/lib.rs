//! Most of the comments are taken from Duncan's fantastic
//! [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
//! ([repo](https://github.com/ssbc/scuttlebutt-protocol-guide)),
//! which he graciously released into the public domain.

extern crate libsodium_sys;
extern crate sodiumoxide;

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

#[derive(Clone)]
pub struct ClientPublicKey(PublicKey);
pub struct ClientSecretKey(SecretKey);

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
pub struct ServerSecretKey(SecretKey);
impl ServerSecretKey {
    pub fn from_slice(b: &[u8]) -> Option<ServerSecretKey> {
        Some(ServerSecretKey(SecretKey::from_slice(b)?))
    }
}
#[derive(Clone)]
pub struct ClientSignature(Signature);
pub struct ServerSignature(Signature);

#[derive(Clone)]
pub struct ClientEphPublicKey(CurvePublicKey);
pub struct ClientEphSecretKey(CurveSecretKey);

#[derive(Clone)]
pub struct ServerEphPublicKey(CurvePublicKey);
pub struct ServerEphSecretKey(CurveSecretKey);

#[derive(Clone)]
pub struct NetworkId(AuthKey);
impl NetworkId {
    pub fn ssb_main_network() -> NetworkId {
        let b: [u8; 32] = [
            0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8,
            0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc, 0x5d,
            0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23,
            0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb];
        NetworkId(AuthKey::from_slice(&b).unwrap())
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
    pub fn from_slice(b: &[u8]) -> Option<NetworkId> {
        Some(NetworkId(AuthKey::from_slice(b)?))
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


/// ## Message 1
/// Client to Server: `ClientHello`
///
/// First the client sends their generated ephemeral key.
/// Also included is an hmac (of a network identifier)
/// that indicates that the client wishes to use their key with
/// a specific instance of the Scuttlebutt network.
///
/// The network identifier is a fixed key. On the main Scuttlebutt
/// network it is the following 32-byte sequence:
/// ```
/// let net_id: [u8; 32] = [
///   0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8,
///   0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc, 0x5d,
///   0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23,
///   0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb];
/// ```
/// Changing the key allows separate networks to be created,
/// for example private networks or testnets.
/// An eavesdropper cannot extract the network identifier directly
/// from what is sent over the wire, although they could confirm
/// a guess that it is the main Scuttlebutt network because that
/// identifier is publicly known.
///
/// The server stores the client’s ephemeral public key and uses the
/// hmac to verify that the client is using the same network identifier.
#[repr(C, packed)]
pub struct ClientHello {
    hmac: HmacAuthTag,
    eph_pk: ClientEphPublicKey,
}

impl ClientHello {
    /// Client sends (64 bytes):
    ///   concat(
    ///     nacl_auth(
    ///       msg: client_ephemeral_pk,
    ///       key: network_identifier
    ///     ),
    ///     client_ephemeral_pk
    ///   )
    pub fn new(eph_pk: &ClientEphPublicKey, net_id: &NetworkId) -> ClientHello {
        ClientHello {
            hmac: auth::authenticate(&eph_pk.0[..], &net_id.0),
            eph_pk: eph_pk.clone(),
        }
    }

    /// Server verifies: (step 1 of 2)
    ///   assert(length(msg1) == 64)
    ///   client_hmac = first_32_bytes(msg1)
    ///   client_ephemeral_pk = last_32_bytes(msg1)
    pub fn from_slice(b: &[u8]) -> Option<ClientHello> {
        if b.len() == size_of::<ClientHello>() {
            let (hmac_bytes, pk_bytes) = b.split_at(size_of::<HmacAuthTag>());
            Some(ClientHello {
                hmac: HmacAuthTag::from_slice(&hmac_bytes)?,
                eph_pk: ClientEphPublicKey(CurvePublicKey::from_slice(&pk_bytes)?),
            })
        } else {
            None
        }
    }

    /// Server verifies: (step 2 of 2)
    ///   assert_nacl_auth_verify(
    ///     authenticator: client_hmac,
    ///     msg: client_ephemeral_pk,
    ///     key: network_identifier
    ///  )
    pub fn verify(&self, net_id: &NetworkId) -> Option<ClientEphPublicKey> {
        if auth::verify(&self.hmac, &self.eph_pk.0[..], &net_id.0) {
            Some(self.eph_pk.clone())
        } else {
            None
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

/// ## Message 2
/// (Server to Client): `ServerHello`
///
/// The server responds with their own ephemeral public key
/// and hmac. The client stores the key and verifies that
/// they are also using the same network identifier.
#[repr(C, packed)]
pub struct ServerHello {
    hmac: HmacAuthTag,
    eph_pk: ServerEphPublicKey,
}

impl ServerHello {
    /// Server sends (64 bytes):
    ///   concat(
    ///     nacl_auth(
    ///       msg: server_ephemeral_pk,
    ///       key: network_identifier
    ///     ),
    ///     server_ephemeral_pk
    ///   )
    pub fn new(eph_pk: &ServerEphPublicKey, net_id: &NetworkId) -> ServerHello {
        ServerHello {
            hmac: auth::authenticate(&eph_pk.0[..], &net_id.0),
            eph_pk: eph_pk.clone(),
        }
    }

    /// Client verifies: (step 1 of 2)
    ///   assert(length(msg2) == 64)
    ///   server_hmac = first_32_bytes(msg2)
    ///   server_ephemeral_pk = last_32_bytes(msg2)
    pub fn from_slice(b: &[u8]) -> Option<ServerHello> {
        if b.len() == size_of::<ServerHello>() {
            let (hmac_bytes, pk_bytes) = b.split_at(size_of::<HmacAuthTag>());
            Some(ServerHello {
                hmac: HmacAuthTag::from_slice(&hmac_bytes)?,
                eph_pk: ServerEphPublicKey(CurvePublicKey::from_slice(&pk_bytes)?),
            })
        } else {
            None
        }
    }

    /// Client verifies: (step 2 of 2)
    ///   assert_nacl_auth_verify(
    ///     authenticator: server_hmac,
    ///     msg: server_ephemeral_pk,
    ///     key: network_identifier
    ///   )
    pub fn verify(&self, net_id: &NetworkId) -> Option<ServerEphPublicKey> {
        if auth::verify(&self.hmac, &self.eph_pk.0[..], &net_id.0) {
            Some(self.eph_pk.clone())
        } else {
            None
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { bytes(self) }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

}

/// Now that ephemeral keys have been exchanged,
/// both ends use them to derive a shared secret
/// using scalar multiplication.
///
/// Each derivation uses one public key and one
/// secret key. The resulting secrets are identical
/// between client and server.
///
/// The client and server each combine their own
/// ephemeral secret key with the other’s ephemeral
/// public key to produce the same shared secret on
/// both ends. An eavesdropper doesn’t know either
/// secret key so they can’t generate the shared secret.
/// A man-in-the-middle could swap out the ephemeral keys
/// in Messages 1 and 2 for their own keys, so the shared secret
/// alone is not enough for the client and server to
/// know that they are talking to each other and not a man-in-the-middle.
#[derive(Clone)]
pub struct SharedA(GroupElement);
impl SharedA {

    /// Client computes:
    ///   shared_secret_ab = nacl_scalarmult(
    ///     client_ephemeral_sk,
    ///     server_ephemeral_pk
    ///   )
    pub fn client_side(sk: &ClientEphSecretKey, pk: &ServerEphPublicKey) -> Option<SharedA> {
        Some(SharedA(derive_shared_secret(&sk.0, &pk.0)?))
    }

    /// Server computes:
    ///  shared_secret_ab = nacl_scalarmult(
    ///    server_ephemeral_sk,
    ///    client_ephemeral_pk
    ///  )
    pub fn server_side(sk: &ServerEphSecretKey, pk: &ClientEphPublicKey) -> Option<SharedA> {
        Some(SharedA(derive_shared_secret(&sk.0, &pk.0)?))
    }

    fn hash(&self) -> SharedAHash {
        SharedAHash(hash(&self.0[..]))
    }
}
struct SharedAHash(ShaDigest);


/// Because the client already knows the server’s long term
/// public key, both ends derive a second secret that will
/// allow the client to send a message that only the real
/// server can read and not a man-in-the-middle.
#[derive(Clone)]
pub struct SharedB(GroupElement);
impl SharedB {

    /// Client computes:
    ///   shared_secret_aB = nacl_scalarmult(
    ///     client_ephemeral_sk,
    ///     pk_to_curve25519(server_longterm_pk)
    ///   )
    pub fn client_side(sk: &ClientEphSecretKey, pk: &ServerPublicKey)
                   -> Option<SharedB>
    {
        Some(SharedB(derive_shared_secret(&sk.0, &pk_to_curve(&pk.0)?)?))
    }

    /// Server computes:
    ///   shared_secret_aB = nacl_scalarmult(
    ///     sk_to_curve25519(server_longterm_sk),
    ///     client_ephemeral_pk
    ///   )
    pub fn server_side(sk: &ServerSecretKey, pk: &ClientEphPublicKey)
                   -> Option<SharedB>
    {
        Some(SharedB(derive_shared_secret(&sk_to_curve(&sk.0)?, &pk.0)?))
    }
}


/// ## Message 3
/// Client to Server: Client authenticate
///
/// The client reveals their identity to the server by sending
/// their long term public key. The client also makes a signature
/// using their long term secret key. By signing the keys used
/// earlier in the handshake the client proves their identity
/// and confirms that they do indeed wish to be part of this handshake.
///
/// The client’s message is enclosed in a secret box to ensure that
/// only the server can read it. Upon receiving it, the server opens
/// the box, stores the client’s long term public key and verifies
/// the signature.
///
/// An all-zero nonce is used for the secret box. The secret box
/// construction requires that all secret boxes using a particular key
/// must use different nonces. It’s important to get this detail right
/// because reusing a nonce will allow an attacker to recover the key
/// and encrypt or decrypt any secret boxes using that key.
/// Using a zero nonce is allowed here because this is the only
/// secret box that ever uses the key
/// `sha256(concat(network_id, shared_secret_ab, shared_secret_aB))`.
pub struct ClientAuth(Vec<u8>);
impl ClientAuth {

    /// Client computes:
    ///   detached_signature_A = nacl_sign_detached(
    ///     msg: concat(
    ///       network_identifier,
    ///       server_longterm_pk,
    ///       sha256(shared_secret_ab)
    ///     ),
    ///     key: client_longterm_sk
    ///   )
    ///
    /// Detached signatures do not contain a copy of the message
    /// that was signed, only a tag that allows verifying the
    /// signature if you already know the message.
    ///
    /// Here it is okay because the server knows all the information
    /// needed to reconstruct the message that the client signed.
    ///
    /// Client sends: (112 bytes)
    ///   client_box = nacl_secret_box(
    ///     msg: concat(
    ///       detached_signature_A,
    ///       client_longterm_pk
    ///     ),
    ///     nonce: 24_bytes_of_zeros,
    ///     key: sha256(
    ///       concat(
    ///         network_identifier,
    ///         shared_secret_ab,
    ///         shared_secret_aB
    ///       )
    ///     )
    ///   )
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

    /// Server receives: (112 bytes)
    pub fn from_buffer(b: Vec<u8>) -> Option<ClientAuth> {
        if b.len() == 112 { // TODO
            Some(ClientAuth(b))
        } else {
            None
        }
    }

    /// Server verifies:
    ///   client_auth_payload = nacl_secretbox_open(
    ///     ciphertext: client_box,
    ///     nonce: 24_bytes_of_zeros,
    ///     key: concat(
    ///       network_identifier,
    ///       shared_secret_ab,
    ///       shared_secret_aB
    ///     )
    ///   )
    ///
    /// Server verifies:
    ///   client_auth_sign_data = ... // as constructed on the client side
    ///   assert_nacl_sign_verify_detached(
    ///     sig: detached_signature_A,
    ///     msg: client_auth_msg,
    ///     key: client_longterm_pk
    ///   )
    pub fn open_and_verify(&self,
                           server_pk: &ServerPublicKey,
                           net_id: &NetworkId,
                           shared_a: &SharedA,
                           shared_b: &SharedB)
                           -> Option<(ClientSignature, ClientPublicKey)> {

        // TODO: return Result<_, ClientAuthUnsealError>
        // Open the box
        let payload = {
            let key = ClientAuthKeyData {
                net_id: net_id.clone(),
                shared_a: shared_a.clone(),
                shared_b: shared_b.clone(),
            }.as_key();
            let v = secretbox::open(&self.0, &zero_nonce(), &key).ok()?;
            ClientAuthPayload::from_slice(&v)
        }?;

        let ok = ClientAuthSignData::new(net_id, server_pk, shared_a)
                   .verify(&payload.client_sig,
                           &payload.client_pk);
        if ok {
            Some((payload.client_sig, payload.client_pk))
        } else {
            None
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
    /// detached_signature_A = first_64_bytes(client_box_payload)
    /// client_longterm_pk   = last_32_bytes(client_box_payload)
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

/// Now that the server knows the  client’s long term
/// public key, another shared secret is derived by both ends.
/// The server uses this shared secret to send a message that
/// only the real client can read and not a man-in-the-middle.
#[derive(Clone)]
pub struct SharedC(GroupElement);
impl SharedC {

    /// Client computes:
    ///   shared_secret_Ab = nacl_scalarmult(
    ///     sk_to_curve25519(client_longterm_sk),
    ///     server_ephemeral_pk
    ///   )
    pub fn client_side(sk: &ClientSecretKey, pk: &ServerEphPublicKey)
                   -> Option<SharedC> {
        Some(SharedC(derive_shared_secret(&sk_to_curve(&sk.0)?, &pk.0)?))
    }

    /// Server computes:
    ///   shared_secret_Ab = nacl_scalarmult(
    ///     server_ephemeral_sk,
    ///     pk_to_curve25519(client_longterm_pk)
    ///   )
    pub fn server_side(sk: &ServerEphSecretKey, pk: &ClientPublicKey)
                   -> Option<SharedC> {
        Some(SharedC(derive_shared_secret(&sk.0, &pk_to_curve(&pk.0)?)?))
    }
}


/// ## Message 4
/// Server acknowledge (Server to Client)
///
/// detached_signature_B = nacl_sign_detached(
///   msg: concat(
///     network_identifier,
///     detached_signature_A,
///     client_longterm_pk,
///     sha256(shared_secret_ab)
///   ),
///   key: server_longterm_sk
/// )
/// Server sends (80 bytes):
///   nacl_secret_box(
///     msg: detached_signature_B,
///     nonce: 24_bytes_of_zeros,
///     key: sha256(
///       concat(
///         network_identifier,
///         shared_secret_ab,
///         shared_secret_aB,
///         shared_secret_Ab
///       )
///     )
///   )
pub struct ServerAccept(Vec<u8>);
impl ServerAccept {
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

    pub fn from_buffer(b: Vec<u8>) -> Option<ServerAccept> {
        if b.len() == 80 { // TODO
            Some(ServerAccept(b))
        } else {
            None
        }
    }

    ///
    /// detached_signature_B = assert_nacl_secretbox_open(
    ///  ciphertext: msg4,
    ///  nonce: 24_bytes_of_zeros,
    ///  key: sha256(
    ///    concat(
    ///      network_identifier,
    ///      shared_secret_ab,
    ///      shared_secret_aB,
    ///      shared_secret_Ab
    ///    )
    ///  )
    ///)
    ///
    ///assert_nacl_sign_verify_detached(
    ///  sig: detached_signature_B,
    ///  msg: concat(
    ///    network_identifier,
    ///    detached_signature_A,
    ///    client_longterm_pk,
    ///    sha256(shared_secret_ab)
    ///  ),
    ///  key: server_longterm_pk
    ///)
    #[must_use]
    pub fn open_and_verify(&self,
                           client_sk: &ClientSecretKey,
                           client_pk: &ClientPublicKey,
                           server_pk: &ServerPublicKey,
                           net_id: &NetworkId,
                           shared_a: &SharedA,
                           shared_b: &SharedB,
                           shared_c: &SharedC)
                           -> bool
    {
        let server_sig = {
            let key = ServerAcceptKeyData {
                net_id: net_id.clone(),
                shared_a: shared_a.clone(),
                shared_b: shared_b.clone(),
                shared_c: shared_c.clone(),
            }.as_key();

            let v = secretbox::open(&self.0, &zero_nonce(), &key).unwrap();
            ServerSignature(Signature::from_slice(&v).unwrap())
        };
        // Note: this sig is computed earlier in ClientAuth::new(); could be stored.
        let client_sig = ClientAuthSignData::new(net_id, server_pk, shared_a).sign(&client_sk);

        ServerAcceptSignData {
            net_id: net_id.clone(),
            sig: client_sig,
            client_pk: client_pk.clone(),
            hash: shared_a.hash()
        }.verify(&server_sig, server_pk)
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

pub struct ClientToServerNonce(secretbox::Nonce);
impl ClientToServerNonce {
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}
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

pub struct ServerToClientNonce(secretbox::Nonce);
impl ServerToClientNonce {
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

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
