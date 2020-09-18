use crate::bytes::{as_mut, as_ref};
use crate::crypto::{keys::*, message::*, outcome::*, shared_secret::*};
use crate::error::HandshakeError;
use crate::sync::util::send;

use core::mem::size_of;
use genio::{Read, Write};
use ssb_crypto::ephemeral::{EphPublicKey, EphSecretKey};
use ssb_crypto::{Keypair, NetworkKey};

/// Perform the server side of the handshake using the given `AsyncRead + AsyncWrite` stream.
/// Closes the stream on handshake failure.
pub fn server_side<S, IoErr>(
    mut stream: S,
    net_key: &NetworkKey,
    keypair: &Keypair,
    eph_kp: (EphPublicKey, EphSecretKey),
) -> Result<HandshakeKeys, HandshakeError<IoErr>>
where
    S: Read<ReadError = IoErr> + Write<WriteError = IoErr, FlushError = IoErr>,
{
    use HandshakeError::*;

    let (eph_pk, eph_sk) = (ServerEphPublicKey(eph_kp.0), ServerEphSecretKey(eph_kp.1));

    // Receive and verify client hello
    let client_eph_pk = {
        let mut buf = [0; size_of::<ClientHello>()];
        stream.read_exact(&mut buf)?;
        as_ref::<ClientHello>(&buf)
            .verify(&net_key)
            .ok_or(ClientHelloVerifyFailed)?
    };

    // Send server hello
    send(&mut stream, ServerHello::new(&eph_pk, &net_key))?;

    // Derive shared secrets
    let shared_a = SharedA::server_side(&eph_sk, &client_eph_pk).ok_or(SharedAInvalid)?;
    let shared_b = SharedB::server_side(&keypair, &client_eph_pk).ok_or(SharedBInvalid)?;

    // Receive and verify client auth
    let (client_sig, client_pk) = {
        let mut buf = [0u8; 112];
        stream.read_exact(&mut buf)?;

        as_mut::<ClientAuth>(&mut buf)
            .verify(&keypair, &net_key, &shared_a, &shared_b)
            .ok_or(ClientAuthVerifyFailed)?
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk).ok_or(SharedCInvalid)?;

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
    )?;

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
