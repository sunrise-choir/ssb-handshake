#![allow(unused_imports)]
#![allow(dead_code)]

//! https://ssbc.github.io/scuttlebutt-protocol-guide/

extern crate libsodium_sys;
extern crate sodiumoxide;

use std::mem::size_of;
use std::ops::Deref;

use sodiumoxide::crypto::{auth, box_, sign, scalarmult, secretbox};

use auth::{Key as AuthKey, Tag as AuthTag};
use box_::{PublicKey as CurvePublicKey, SecretKey as CurveSecretKey};
use sign::{sign_detached, verify_detached, PublicKey, SecretKey, Signature};
use scalarmult::{scalarmult, Scalar, GroupElement};

use sodiumoxide::crypto::hash::sha256::{hash, Digest as ShaDigest};
use sodiumoxide::utils::memzero;

use libsodium_sys::{crypto_sign_ed25519_pk_to_curve25519,
                    crypto_sign_ed25519_sk_to_curve25519};

struct ClientPublicKey(PublicKey);
struct ClientSecretKey(SecretKey);

struct ServerPublicKey(PublicKey);
impl Deref for ServerPublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &(self.0).0
    }
}

struct ServerSecretKey(SecretKey);

struct ClientEphPublicKey(CurvePublicKey);
struct ClientEphSecretKey(CurveSecretKey);

struct ServerEphPublicKey(CurvePublicKey);
struct ServerEphSecretKey(CurveSecretKey);

struct SharedHash(ShaDigest);
struct BoxSecret(ShaDigest);

const HELLO_BYTES: usize = size_of::<AuthTag>() + size_of::<CurvePublicKey>();

struct Hello([u8; HELLO_BYTES]);
struct ClientHello(Hello);
struct ServerHello(Hello);

impl Hello {
    fn new(net_id: &NetworkId, eph_pub: &CurvePublicKey) -> Hello {
        let auth: AuthTag = auth::authenticate(&eph_pub.0, &net_id.0);
        Hello::from_parts(&auth, &eph_pub)
    }

    fn from_parts(auth: &AuthTag, eph_pub: &CurvePublicKey) -> Hello {
        let mut hi: Hello = Hello([0; HELLO_BYTES]);

        let (authbytes, pubbytes) = hi.0.split_at_mut(size_of::<AuthTag>());
        authbytes.copy_from_slice(&auth.0);
        pubbytes.copy_from_slice(&eph_pub.0);

        hi
    }

    fn from_bytes(b: [u8; HELLO_BYTES]) -> Hello {
        Hello(b)
    }

    fn auth_tag(&self) -> AuthTag {
        AuthTag::from_slice(&self.0[..size_of::<AuthTag>()]).unwrap()
    }

    fn eph_public_key(&self) -> CurvePublicKey {
        CurvePublicKey::from_slice(self.eph_public_key_bytes()).unwrap()
    }

    fn eph_public_key_bytes(&self) -> &[u8] {
        &self.0[size_of::<AuthTag>()..]
    }

    fn verify(&self, net_id: &NetworkId) -> Option<CurvePublicKey> {
        if auth::verify(&self.auth_tag(), self.eph_public_key_bytes(), &net_id.0) {
            Some(self.eph_public_key())
        } else {
            None
        }
    }
}

impl ClientHello {
    fn new(net_id: &NetworkId, eph_pub: &ClientEphPublicKey) -> ClientHello {
        ClientHello(Hello::new(net_id, &eph_pub.0))
    }
}

impl ServerHello {
    fn new(net_id: &NetworkId, eph_pub: &ServerEphPublicKey) -> ServerHello {
        ServerHello(Hello::new(net_id, &eph_pub.0))
    }
}

struct NetworkId(AuthKey);
impl Deref for NetworkId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &(self.0).0
    }
}

pub struct SharedEphSecret([u8; size_of::<GroupElement>()]);
impl SharedEphSecret {
}

struct DerivedSecret(GroupElement);
struct EphDerivedSecret(GroupElement);
impl Deref for EphDerivedSecret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &(self.0).0
    }
}
struct PermDerivedSecret(GroupElement);


fn derive_shared_secret(our_sec: &CurveSecretKey, their_pub: &CurvePublicKey) -> Option<DerivedSecret> {
    // Benchmarks suggest that these "copies" get optimized away.
    let n = Scalar::from_slice(&our_sec.0)?;
    let p = GroupElement::from_slice(&their_pub.0)?;
    scalarmult(&n, &p).ok().map(|q| DerivedSecret(q))
}

fn client_derive_eph_secret(sk: &ClientEphSecretKey, pk: &ServerEphPublicKey) -> Option<EphDerivedSecret> {
    derive_shared_secret(&sk.0, &pk.0)
        .map(|DerivedSecret(s)| EphDerivedSecret(s))
}

fn client_derive_perm_secret(sk: &ClientEphSecretKey, pk: &ServerPublicKey) -> Option<PermDerivedSecret> {
    derive_shared_secret(&sk.0, &pub_key_to_curve(&pk.0)?)
        .map(|DerivedSecret(s)| PermDerivedSecret(s))
}

const CLIENT_AUTH_MSG_BYTES: usize
    = size_of::<NetworkId>()
    + size_of::<ServerPublicKey>()
    + size_of::<ShaDigest>();
struct ClientAuthMsg([u8; CLIENT_AUTH_MSG_BYTES]);

impl ClientAuthMsg {
    fn new(net_id: &NetworkId, pk: &ServerPublicKey, derived: &EphDerivedSecret) -> ClientAuthMsg {
        let digest = hash(&derived);
        Self::from_parts(net_id, pk, &digest)
    }
    fn from_parts(net_id: &NetworkId, pk: &ServerPublicKey, dig: &ShaDigest) -> ClientAuthMsg {
        const A: usize = size_of::<NetworkId>();
        const B: usize = A + size_of::<ServerPublicKey>();

        let mut buf = [0u8; CLIENT_AUTH_MSG_BYTES];
        buf[..A].copy_from_slice(&net_id);
        buf[A..B].copy_from_slice(&pk);
        buf[B..].copy_from_slice(&dig.0);
        ClientAuthMsg(buf)
    }

    fn sign(&self, sk: &ClientSecretKey) -> Signature {
        sign_detached(&self.0, &sk.0)
    }

    fn verify(&self, sig: &Signature, pk: &ClientPublicKey) -> bool {
        verify_detached(sig, &self.0, &pk.0)
    }

}

fn pub_key_to_curve(k: &PublicKey) -> Option<CurvePublicKey> {
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

fn sec_key_to_curve(k: &SecretKey) -> Option<CurveSecretKey> {
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
