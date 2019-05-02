//! Based on Duncan's fantastic
//! [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
//! ([repo](https://github.com/ssbc/scuttlebutt-protocol-guide)),
//! which he graciously released into the public domain.

#![feature(async_await, await_macro)]
extern crate futures;
#[macro_use] extern crate quick_error;
extern crate ssb_crypto;

use ssb_crypto::{
    NetworkKey,
    NonceGen,
    PublicKey,
    SecretKey,
};

use futures::io::{
    AsyncRead,
    AsyncReadExt,
    AsyncWrite,
    AsyncWriteExt,
};
use core::mem::size_of;

mod error;
mod utils;
pub use error::HandshakeError;
pub mod crypto;
use crypto::{
    ClientEphPublicKey,
    ClientPublicKey,
    ClientSecretKey,

    ServerEphPublicKey,
    ServerPublicKey,
    ServerSecretKey,

    gen_client_eph_keypair,
    gen_server_eph_keypair,

    message::{
        ClientAuth,
        ClientHello,
        ServerHello,
        ServerAccept,
    },
    shared_secret::{
        SharedA,
        SharedB,
        SharedC,
    },
    outcome::HandshakeOutcome
};

// TODO: memzero our secrets, if sodiumoxide doesn't do it for us.

/// Perform the client side of the handshake using the given `AsyncRead + AsyncWrite` stream.
pub async fn client<S>(
    mut stream: S,
    net_key: NetworkKey,
    pk: PublicKey,
    sk: SecretKey,
    server_pk: PublicKey)
    -> Result<HandshakeOutcome, HandshakeError>
where S: AsyncRead + AsyncWrite + Unpin
{
    let r = await!(try_client_side(&mut stream, net_key, pk, sk, server_pk));
    if r.is_err() {
        await!(stream.close()).unwrap_or(());
    }
    r
}

async fn try_client_side<S>(mut stream: S,
                            net_key: NetworkKey,
                            pk: PublicKey,
                            sk: SecretKey,
                            server_pk: PublicKey)
                            -> Result<HandshakeOutcome, HandshakeError>
where S: AsyncRead + AsyncWrite + Unpin
{

    let pk = ClientPublicKey(pk);
    let sk = ClientSecretKey(sk);
    let server_pk = ServerPublicKey(server_pk);

    let (eph_pk, eph_sk) = gen_client_eph_keypair();
    let hello = ClientHello::new(&eph_pk, &net_key);
    await!(stream.write_all(&hello.as_slice()))?;
    await!(stream.flush())?;

    let server_eph_pk = {
        let mut buf = [0u8; size_of::<ServerHello>()];
        await!(stream.read_exact(&mut buf))?;

        let server_hello = ServerHello::from_slice(&buf)?;
        server_hello.verify(&net_key)?
    };

    // Derive shared secrets
    let shared_a = SharedA::client_side(&eph_sk, &server_eph_pk)?;
    let shared_b = SharedB::client_side(&eph_sk, &server_pk)?;
    let shared_c = SharedC::client_side(&sk, &server_eph_pk)?;

    // Send client auth
    let client_auth = ClientAuth::new(&sk, &pk, &server_pk, &net_key, &shared_a, &shared_b);
    await!(stream.write_all(client_auth.as_slice()))?;
    await!(stream.flush())?;

    let mut buf = [0u8; 80];
    await!(stream.read_exact(&mut buf))?;

    let server_acc = ServerAccept::from_buffer(buf.to_vec())?;
    let v = server_acc.open_and_verify(&sk, &pk, &server_pk,
                                       &net_key, &shared_a,
                                       &shared_b, &shared_c)?;

    Ok(HandshakeOutcome::client_side(
        v,
        &pk,
        &server_pk,
        &eph_pk,
        &server_eph_pk,
        &net_key,
        &shared_a,
        &shared_b,
        &shared_c
    ))
}

/// Perform the server side of the handshake using the given `AsyncRead + AsyncWrite` stream.
pub async fn server<S>(mut stream: S,
                       net_key: NetworkKey,
                       pk: PublicKey,
                       sk: SecretKey)
                       -> Result<HandshakeOutcome, HandshakeError>
where S: AsyncRead + AsyncWrite + Unpin
{
    let r = await!(try_server_side(&mut stream, net_key, pk, sk));
    if r.is_err() {
        await!(stream.close()).unwrap_or(());
    }
    r
}

async fn try_server_side<S>(mut stream: S,
                            net_key: NetworkKey,
                            pk: PublicKey,
                            sk: SecretKey)
                            -> Result<HandshakeOutcome, HandshakeError>
where S: AsyncRead + AsyncWrite + Unpin
{

    let pk = ServerPublicKey(pk);
    let sk = ServerSecretKey(sk);

    let (eph_pk, eph_sk) = gen_server_eph_keypair();

    // Receive and verify client hello
    let client_eph_pk = {
        let mut buf = [0u8; 64];
        await!(stream.read_exact(&mut buf))?;
        let client_hello = ClientHello::from_slice(&buf)?;
        client_hello.verify(&net_key)?
    };

    // Send server hello
    let hello = ServerHello::new(&eph_pk, &net_key);
    await!(stream.write_all(hello.as_slice()))?;
    await!(stream.flush())?;

    // Derive shared secrets
    let shared_a = SharedA::server_side(&eph_sk, &client_eph_pk)?;
    let shared_b = SharedB::server_side(&sk, &client_eph_pk)?;

    // Receive and verify client auth
    let (client_sig, client_pk) = {
        let mut buf = [0u8; 112];
        await!(stream.read_exact(&mut buf))?;

        let client_auth = ClientAuth::from_buffer(buf.to_vec())?;
        client_auth.open_and_verify(&pk, &net_key, &shared_a, &shared_b)?
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk)?;

    // Send server accept
    let server_acc = ServerAccept::new(&sk, &client_pk, &net_key, &client_sig,
                                       &shared_a, &shared_b, &shared_c);
    await!(stream.write_all(server_acc.as_slice()))?;
    await!(stream.flush())?;

    Ok(HandshakeOutcome::server_side(
        &pk,
        &client_pk,
        &eph_pk,
        &client_eph_pk,
        &net_key,
        &shared_a,
        &shared_b,
        &shared_c,
    ))
}

#[cfg(test)]
mod tests {
    extern crate futures_util;

    use super::*;
    use core::task::Context;
    use core::pin::Pin;
    use std::io::{self, ErrorKind};

    // For some reason, the futures::join macro is failing to resolve
    // (as of 2019-04-30 nightly).
    use futures::{future::join, Poll};
    use futures::executor::block_on;

    extern crate async_ringbuffer;
    extern crate pin_utils;
    use pin_utils::unsafe_pinned;
    use ssb_crypto::{generate_longterm_keypair, NetworkKey, PublicKey};

    struct Duplex<R, W> {
        r: R,
        w: W,
    }
    impl<R, W> Duplex<R, W> {
        unsafe_pinned!(r: R);
        unsafe_pinned!(w: W);
    }
    impl<R, W> AsyncRead for Duplex<R, W>
    where
        R: AsyncRead + Unpin,
    {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
            self.r().poll_read(cx, buf)
        }
    }
    impl<R, W> AsyncWrite for Duplex<R, W>
    where
        W: AsyncWrite + Unpin,
    {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
            self.w().poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
            self.w().poll_flush(cx)
        }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
            self.w().poll_close(cx)
        }
    }

    type DuplexRingbufStream = Duplex<async_ringbuffer::Reader, async_ringbuffer::Writer>;

    fn make_streams() -> (DuplexRingbufStream, DuplexRingbufStream) {
        let (c2s_w, c2s_r) = async_ringbuffer::ring_buffer(1024);
        let (s2c_w, s2c_r) = async_ringbuffer::ring_buffer(1024);

        (Duplex { r: s2c_r, w: c2s_w }, Duplex { r: c2s_r, w: s2c_w })
    }

    #[test]
    fn basic() {
        let (mut c_stream, mut s_stream) = make_streams();
        let (s_pk, s_sk) = generate_longterm_keypair();
        let (c_pk, c_sk) = generate_longterm_keypair();

        let net_key = NetworkKey::SSB_MAIN_NET;
        let client_side = client(&mut c_stream, net_key.clone(), c_pk, c_sk, s_pk.clone());
        let server_side = server(&mut s_stream, net_key.clone(), s_pk, s_sk);

        let (c_out, s_out) = block_on(async {
            await!(join(client_side, server_side))
        });

        let mut c_out = c_out.unwrap();
        let mut s_out = s_out.unwrap();

        assert_eq!(c_out.write_key, s_out.read_key);
        assert_eq!(c_out.read_key, s_out.write_key);

        assert_eq!(c_out.write_noncegen.next(),
                   s_out.read_noncegen.next());

        assert_eq!(c_out.read_noncegen.next(),
                   s_out.write_noncegen.next());
    }

    fn is_eof_err<T>(r: &Result<T, HandshakeError>) -> bool {
        match r {
            Err(HandshakeError::Io(e)) => e.kind() == ErrorKind::UnexpectedEof,
            _ => false,
        }
    }

    #[test]
    fn server_rejects_wrong_netkey() {
        let (mut c_stream, mut s_stream) = make_streams();
        let (s_pk, s_sk) = generate_longterm_keypair();
        let (c_pk, c_sk) = generate_longterm_keypair();

        let client_side = client(&mut c_stream, NetworkKey::random(), c_pk, c_sk, s_pk.clone());
        let server_side = server(&mut s_stream, NetworkKey::random(), s_pk, s_sk);

        let (c_out, s_out) = block_on(async {
            await!(join(client_side, server_side))
        });

        assert!(is_eof_err(&c_out));
        match s_out {
            Err(HandshakeError::ClientHelloVerifyFailed) => {},
            _ => panic!(),
        };
    }

    #[test]
    fn server_rejects_wrong_pk() {
        test_handshake_with_bad_server_pk(
            PublicKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap());

        let (pk, _sk) = generate_longterm_keypair();
        test_handshake_with_bad_server_pk(pk);
    }

    fn test_handshake_with_bad_server_pk(bad_pk: PublicKey) {
        let (mut c_stream, mut s_stream) = make_streams();
        let (s_pk, s_sk) = generate_longterm_keypair();
        let (c_pk, c_sk) = generate_longterm_keypair();

        let net_key = NetworkKey::SSB_MAIN_NET;

        let client_side = client(&mut c_stream, net_key.clone(), c_pk, c_sk, bad_pk);
        let server_side = server(&mut s_stream, net_key.clone(), s_pk, s_sk);

        let (c_out, s_out) = block_on(async {
            await!(join(client_side, server_side))
        });

        assert!(c_out.is_err());
        assert!(s_out.is_err());
    }

}
