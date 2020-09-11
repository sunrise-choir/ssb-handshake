use crate::bytes::{as_mut, as_ref};
use crate::crypto::{keys::*, message::*, outcome::*, shared_secret::*};
use crate::error::HandshakeError;
use crate::util::send;

use core::mem::size_of;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use ssb_crypto::{Keypair, NetworkKey};

/// Perform the server side of the handshake using the given `AsyncRead + AsyncWrite` stream.
/// Closes the stream on handshake failure.
pub async fn server_side<S>(
    mut stream: S,
    net_key: &NetworkKey,
    keypair: &Keypair,
) -> Result<HandshakeKeys, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let r = try_server_side(&mut stream, net_key, keypair).await;
    if r.is_err() {
        stream.close().await.unwrap_or(());
    }
    r
}

async fn try_server_side<S>(
    mut stream: S,
    net_key: &NetworkKey,
    keypair: &Keypair,
) -> Result<HandshakeKeys, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (eph_pk, eph_sk) = gen_server_eph_keypair();

    // Receive and verify client hello
    let client_eph_pk = {
        let mut buf = [0; size_of::<ClientHello>()];
        stream.read_exact(&mut buf).await?;
        as_ref::<ClientHello>(&buf).verify(&net_key)?
    };

    // Send server hello
    send(&mut stream, ServerHello::new(&eph_pk, &net_key)).await?;

    // Derive shared secrets
    let shared_a = SharedA::server_side(&eph_sk, &client_eph_pk)?;
    let shared_b = SharedB::server_side(&keypair, &client_eph_pk)?;

    // Receive and verify client auth
    let (client_sig, client_pk) = {
        let mut buf = [0u8; 112];
        stream.read_exact(&mut buf).await?;

        as_mut::<ClientAuth>(&mut buf).verify(&keypair, &net_key, &shared_a, &shared_b)?
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk)?;

    // Send server accept
    send(
        &mut stream,
        ServerAccept::new(
            &keypair,
            &client_pk,
            &net_key,
            &client_sig,
            &shared_a,
            &shared_b,
            &shared_c,
        ),
    )
    .await?;

    Ok(HandshakeKeys {
        read_key: client_to_server_key(
            &ServerPublicKey(keypair.public),
            &net_key,
            &shared_a,
            &shared_b,
            &shared_c,
        ),
        read_starting_nonce: starting_nonce(&net_key, &eph_pk.0),

        write_key: server_to_client_key(&client_pk, &net_key, &shared_a, &shared_b, &shared_c),
        write_starting_nonce: starting_nonce(&net_key, &client_eph_pk.0),

        peer_key: client_pk.0,
    })
}
