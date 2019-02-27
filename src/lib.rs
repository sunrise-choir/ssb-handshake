#![allow(unused_imports)]
#![allow(dead_code)]
//! Most of the comments are taken from the fantastic
//! [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
//! ([repo](https://github.com/ssbc/scuttlebutt-protocol-guide))
//!

extern crate libsodium_sys;
extern crate sodiumoxide;

use std::ops::Deref;
use std::slice;
use std::mem::size_of;

use sodiumoxide::crypto::{auth, box_, sign, scalarmult, secretbox};

use auth::{Key as AuthKey, Tag as HmacAuthTag};
use box_::{PublicKey as CurvePublicKey, SecretKey as CurveSecretKey};
use sign::{sign_detached, verify_detached, PublicKey, SecretKey, Signature};
use scalarmult::{scalarmult, Scalar, GroupElement};

use sodiumoxide::crypto::hash::sha256::{hash, Digest as ShaDigest};
use sodiumoxide::utils::memzero;

use libsodium_sys::{crypto_sign_ed25519_pk_to_curve25519,
                    crypto_sign_ed25519_sk_to_curve25519};

#[derive(Clone)]
struct ClientPublicKey(PublicKey);
struct ClientSecretKey(SecretKey);

#[derive(Clone)]
struct ServerPublicKey(PublicKey);
struct ServerSecretKey(SecretKey);

#[derive(Clone)]
struct ClientEphPublicKey(CurvePublicKey);
struct ClientEphSecretKey(CurveSecretKey);

#[derive(Clone)]
struct ServerEphPublicKey(CurvePublicKey);
struct ServerEphSecretKey(CurveSecretKey);

#[derive(Clone)]
struct NetworkId(AuthKey);


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
struct ClientHello {
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
    fn new(eph_pk: &ClientEphPublicKey, net_id: &NetworkId) -> ClientHello {
        ClientHello {
            hmac: auth::authenticate(&eph_pk.0[..], &net_id.0),
            eph_pk: eph_pk.clone(),
        }
    }

    /// Server verifies: (step 1 of 2)
    ///   assert(length(msg1) == 64)
    ///   client_hmac = first_32_bytes(msg1)
    ///   client_ephemeral_pk = last_32_bytes(msg1)
    fn from_slice(b: &[u8]) -> Option<ClientHello> {
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
    fn verify(&self, net_id: &NetworkId) -> Option<ClientEphPublicKey> {
        if auth::verify(&self.hmac, &self.eph_pk.0[..], &net_id.0) {
            Some(self.eph_pk.clone())
        } else {
            None
        }
    }
}

/// ## Message 2
/// (Server to Client): `ServerHello`
///
/// The server responds with their own ephemeral public key
/// and hmac. The client stores the key and verifies that
/// they are also using the same network identifier.
#[repr(C, packed)]
struct ServerHello {
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
    fn new(net_id: &NetworkId, eph_pk: &ServerEphPublicKey) -> ServerHello {
        ServerHello {
            hmac: auth::authenticate(&eph_pk.0[..], &net_id.0),
            eph_pk: eph_pk.clone(),
        }
    }

    /// Client verifies: (step 1 of 2)
    ///   assert(length(msg2) == 64)
    ///   server_hmac = first_32_bytes(msg2)
    ///   server_ephemeral_pk = last_32_bytes(msg2)
    fn from_slice(b: &[u8]) -> Option<ServerHello> {
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
    fn verify(&self, net_id: &NetworkId) -> Option<ServerEphPublicKey> {
        if auth::verify(&self.hmac, &self.eph_pk.0[..], &net_id.0) {
            Some(self.eph_pk.clone())
        } else {
            None
        }
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
struct EphShared(GroupElement);
impl EphShared {

    /// Client computes:
    ///   shared_secret_ab = nacl_scalarmult(
    ///     client_ephemeral_sk,
    ///     server_ephemeral_pk
    ///   )
    fn client_side(sk: &ClientEphSecretKey, pk: &ServerEphPublicKey) -> Option<EphShared> {
        derive_shared_secret(&sk.0, &pk.0).map(|s| EphShared(s))
    }

    /// Server computes:
    ///  shared_secret_ab = nacl_scalarmult(
    ///    server_ephemeral_sk,
    ///    client_ephemeral_pk
    ///  )
    fn server_side(sk: &ServerEphSecretKey, pk: &ClientEphPublicKey) -> Option<EphShared> {
        derive_shared_secret(&sk.0, &pk.0).map(|s| EphShared(s))
    }
}

/// Because the client already knows the server’s long term
/// public key, both ends derive a second secret that will
/// allow the client to send a message that only the real
/// server can read and not a man-in-the-middle.
#[derive(Clone)]
struct ClientToServerShared(GroupElement);
impl ClientToServerShared {

    /// Client computes:
    ///   shared_secret_aB = nacl_scalarmult(
    ///     client_ephemeral_sk,
    ///     pk_to_curve25519(server_longterm_pk)
    ///   )
    fn client_side(sk: &ClientEphSecretKey, pk: &ServerPublicKey)
                   -> Option<ClientToServerShared>
    {
        derive_shared_secret(&sk.0, &pk_to_curve(&pk.0)?)
            .map(|s| ClientToServerShared(s))
    }

    /// Server computes:
    ///   shared_secret_aB = nacl_scalarmult(
    ///     sk_to_curve25519(server_longterm_sk),
    ///     client_ephemeral_pk
    ///   )
    fn server_side(sk: &ServerSecretKey, pk: &ClientEphPublicKey)
                   -> Option<ClientToServerShared>
    {
        derive_shared_secret(&sk_to_curve(&sk.0)?, &pk.0)
            .map(|s| ClientToServerShared(s))
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
#[repr(C, packed)]
struct ClientAuthMsg {
    id: NetworkId,
    pk: ServerPublicKey,
    hash: ShaDigest,
}

fn bytes<T>(t: &T) -> &[u8] {
    let p = t as *const T as *const u8;
    unsafe {
        slice::from_raw_parts(p, size_of::<T>())
    }
}


impl ClientAuthMsg {

    /// Client computes: (step 1 of )
    ///   client_auth_msg = concat(
    ///     network_identifier,
    ///     server_longterm_pk,
    ///     sha256(shared_secret_ab)
    ///   )
    fn new(net_id: &NetworkId, pk: &ServerPublicKey, derived: &EphShared) -> ClientAuthMsg {
        ClientAuthMsg {
            id: net_id.clone(),
            pk: pk.clone(),
            hash: hash(&derived.0[..]),
        }
    }

    /// Client computes: (step 2 of )
    ///   detached_signature_A = nacl_sign_detached(
    ///     msg: client_auth_msg,
    ///     key: client_longterm_sk
    ///   )
    ///
    /// Detached signatures do not contain a copy of the message
    /// that was signed, only a tag that allows verifying the
    /// signature if you already know the message.
    ///
    /// Here it is okay because the server knows all the information
    /// needed to reconstruct the message that the client signed.
    fn sign(&self, sk: &ClientSecretKey) -> Signature {
        sign_detached(bytes(&self), &sk.0)
    }
}


#[repr(C, packed)]
struct ClientBoxPayload {
    sig: Signature,
    pk: ClientPublicKey,
}

impl ClientBoxPayload {
    /// Client computes: (step 3 of )
    ///   client_box_payload = concat(
    ///     detached_signature_A,
    ///     client_longterm_pk
    ///   )
    fn new(sig: Signature, pk: &ClientPublicKey) -> ClientBoxPayload {
        ClientBoxPayload {
            sig,
            pk: pk.clone()
        }
    }
}

#[repr(C, packed)]
struct ClientBoxKeyData {
    net_id: NetworkId,
    eph_shared: EphShared,
    c2s_shared: ClientToServerShared,
}

struct ClientBoxKey(secretbox::Key);
impl ClientBoxKey {

    /// Client computes: (step 4 of )
    ///   client_box_key = sha256(
    ///     concat(
    ///       network_identifier,
    ///       shared_secret_ab,
    ///       shared_secret_aB
    ///     )
    ///   )
    fn new(net_id: &NetworkId, eph_shared: &EphShared, c2s_shared: &ClientToServerShared) -> ClientBoxKey {

        let data = ClientBoxKeyData {
            net_id: net_id.clone(),
            eph_shared: eph_shared.clone(),
            c2s_shared: c2s_shared.clone(),
        };

        assert_eq!(size_of::<secretbox::Key>(), size_of::<ShaDigest>());

        let digest = hash(bytes(&data));
        ClientBoxKey(secretbox::Key::from_slice(&digest[..]).unwrap())
    }
}

fn zero_nonce() -> secretbox::Nonce {
    secretbox::Nonce::from_slice(&[0u8; size_of::<secretbox::Nonce>()]) .unwrap()
}

struct ClientBox(Vec<u8>);
impl ClientBox {

    /// Client sends: (112 bytes) (step 5 of )
    ///   client_box = nacl_secret_box(
    ///     msg: client_box_payload,
    ///     nonce: 24_bytes_of_zeros,
    ///     key: client_box_key
    ///   )
    fn new(payload: &ClientBoxPayload, key: &ClientBoxKey) -> ClientBox {
        ClientBox(secretbox::seal(bytes(payload), &zero_nonce(), &key.0))
    }

    /// Server receives: (112 bytes) (step 1 of )
    fn from_buffer(b: Vec<u8>) -> ClientBox {
        ClientBox(b)
    }

    /// Server computes: (step 2 of )
    ///   client_box_key = ... // as above
    ///
    /// Server verifies: (step 3 of )
    ///   client_box_payload = nacl_secretbox_open(
    ///     ciphertext: client_box,
    ///     nonce: 24_bytes_of_zeros,
    ///     key: client_box_key
    ///   )
    fn open(&self, key: &ClientBoxKey) -> Option<ClientBoxPayload> {
        // TODO: return Result<_, ClientBoxUnsealError>
        let v = secretbox::open(&self.0, &zero_nonce(), &key.0).ok()?;
        ClientBoxPayload::from_slice(&v)
    }

}

impl ClientBoxPayload {
    /// detached_signature_A = first_64_bytes(client_box_payload)
    /// client_longterm_pk   = last_32_bytes(client_box_payload)
    fn from_slice(b: &[u8]) -> Option<ClientBoxPayload> {
        if b.len() == size_of::<ClientBoxPayload>() {
            let (sig_bytes, pk_bytes) = b.split_at(size_of::<Signature>());
            Some(ClientBoxPayload {
                sig: Signature::from_slice(&sig_bytes)?,
                pk: ClientPublicKey(PublicKey::from_slice(pk_bytes)?),
            })
        } else {
            None
        }
    }
}

impl ClientAuthMsg {
    /// Server verifies: (step 3 of )
    ///   client_auth_msg = ... // as constructed on the client side
    ///   assert_nacl_sign_verify_detached(
    ///     sig: detached_signature_A,
    ///     msg: client_auth_msg,
    ///     key: client_longterm_pk
    ///   )
    fn verify(&self, sig: &Signature, pk: &ClientPublicKey) -> bool {
        verify_detached(sig, bytes(&self), &pk.0)
    }
}

/// Now that the server knows the  client’s long term
/// public key, another shared secret is derived by both ends.
/// The server uses this shared secret to send a message that
/// only the real client can read and not a man-in-the-middle.
#[derive(Clone)]
struct ServerToClientShared(GroupElement);
impl ServerToClientShared {

    /// Client computes:
    ///   shared_secret_Ab = nacl_scalarmult(
    ///     sk_to_curve25519(client_longterm_sk),
    ///     server_ephemeral_pk
    ///   )
    fn client_side(sk: &ClientSecretKey, pk: &ServerEphPublicKey)
                   -> Option<ServerToClientShared> {
        derive_shared_secret(&sk_to_curve(&sk.0)?, &pk.0)
            .map(|s| ServerToClientShared(s))
    }

    /// Server computes:
    ///   shared_secret_Ab = nacl_scalarmult(
    ///     server_ephemeral_sk,
    ///     pk_to_curve25519(client_longterm_pk)
    ///   )
    fn server_side(sk: &ServerEphSecretKey, pk: &ClientPublicKey)
                   -> Option<ServerToClientShared> {
        derive_shared_secret(&sk.0, &pk_to_curve(&pk.0)?)
            .map(|s| ServerToClientShared(s))
    }
}


/// ## Message 4
/// Server acknowledge (Server to Client)
///

/// detached_signature_B = nacl_sign_detached(
///  msg: concat(
///    network_identifier,
///    detached_signature_A,
///    client_longterm_pk,
///    sha256(shared_secret_ab)
///  ),
///  key: server_longterm_sk
///)

// #[repr(C, packed)]
// struct ServerAckMsg {
//     net_id: NetworkId,
//     sig: Signature, // detached_signature_A
//     client_pk: ClientPublicKey,
//     hash: HashOfEphShared
// }


struct ServerBox;
struct ServerBoxPayload;
struct ServerBoxKey;

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
