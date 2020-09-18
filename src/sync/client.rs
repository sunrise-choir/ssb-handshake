use crate::bytes::{as_mut, as_ref};
use crate::crypto::outcome::HandshakeKeys;
use crate::crypto::{keys::*, message::*, outcome::*, shared_secret::*};
use crate::error::HandshakeError;
use crate::sync::util::send;

use core::mem::size_of;
use genio::{Read, Write};
use ssb_crypto::ephemeral::{EphPublicKey, EphSecretKey};
use ssb_crypto::{Keypair, NetworkKey, PublicKey};

pub fn client_side<S, IoErr>(
    mut stream: S,
    net_key: &NetworkKey,
    keypair: &Keypair,
    server_pk: &PublicKey,
    eph_kp: (EphPublicKey, EphSecretKey),
) -> Result<HandshakeKeys, HandshakeError<IoErr>>
where
    S: Read<ReadError = IoErr> + Write<WriteError = IoErr, FlushError = IoErr>,
{
    use HandshakeError::*;

    let (eph_pk, eph_sk) = (ClientEphPublicKey(eph_kp.0), ClientEphSecretKey(eph_kp.1));
    let server_pk = ServerPublicKey(*server_pk);

    send(&mut stream, ClientHello::new(&eph_pk, &net_key))?;

    let server_eph_pk = {
        let mut buf = [0u8; size_of::<ServerHello>()];
        stream.read_exact(&mut buf)?;
        as_mut::<ServerHello>(&mut buf)
            .verify(&net_key)
            .ok_or(ServerHelloVerifyFailed)?
    };

    // Derive shared secrets
    let shared_a = SharedA::client_side(&eph_sk, &server_eph_pk).ok_or(SharedAInvalid)?;
    let shared_b = SharedB::client_side(&eph_sk, &server_pk).ok_or(SharedBInvalid)?;
    let shared_c = SharedC::client_side(&keypair, &server_eph_pk).ok_or(SharedCInvalid)?;

    // Send client auth
    send(
        &mut stream,
        ClientAuth::new(&keypair, &server_pk, &net_key, &shared_a, &shared_b),
    )?;

    let mut buf = [0u8; size_of::<ServerAccept>()];
    stream.read_exact(&mut buf)?;
    as_ref::<ServerAccept>(&buf)
        .verify(
            &keypair, &server_pk, &net_key, &shared_a, &shared_b, &shared_c,
        )
        .ok_or(ServerAcceptVerifyFailed)?;

    Ok(HandshakeKeys {
        read_key: server_to_client_key(
            &ClientPublicKey(keypair.public),
            &net_key,
            &shared_a,
            &shared_b,
            &shared_c,
        ),
        read_starting_nonce: starting_nonce(&net_key, &eph_pk.0),

        write_key: client_to_server_key(&server_pk, &net_key, &shared_a, &shared_b, &shared_c),
        write_starting_nonce: starting_nonce(&net_key, &server_eph_pk.0),

        peer_key: server_pk.0,
    })
}
