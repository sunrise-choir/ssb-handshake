use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;

use ssb_crypto::{NetworkKey, NonceGen, generate_longterm_keypair};

use shs_core::{
    *,
    messages::*,
    shared_secret::*,
    shared_key::*,
};

fn client(to_server: Sender<Vec<u8>>, from_server: Receiver<Vec<u8>>,
          server_pk: ServerPublicKey) -> Result<HandshakeOutcome, HandshakeError> {

    let net_id = NetworkKey::SSB_MAIN_NET;
    let (pk, sk) = generate_longterm_keypair();
    let (pk, sk) = (ClientPublicKey(pk), ClientSecretKey(sk));

    let (eph_pk, eph_sk) = client::generate_eph_keypair();

    // Send client hello
    let hello = ClientHello::new(&eph_pk, &net_id);
    to_server.send(hello.to_vec()).unwrap();

    let server_eph_pk = {
        let buf = from_server.recv().unwrap();
        let server_hello = ServerHello::from_slice(&buf)?;
        server_hello.verify(&net_id)?
    };

    // Derive shared secrets
    let shared_a = SharedA::client_side(&eph_sk, &server_eph_pk)?;
    let shared_b = SharedB::client_side(&eph_sk, &server_pk)?;

    // Send client auth
    let client_auth = ClientAuth::new(&sk, &pk, &server_pk, &net_id, &shared_a, &shared_b);
    to_server.send(client_auth.to_vec()).unwrap();

    // Derive shared secret
    let shared_c = SharedC::client_side(&sk, &server_eph_pk).unwrap();

    let v = from_server.recv().unwrap();
    let server_acc = ServerAccept::from_buffer(v).unwrap();
    server_acc.open_and_verify(&sk, &pk, &server_pk,
                               &net_id, &shared_a,
                               &shared_b, &shared_c)?;

    Ok(HandshakeOutcome {
        read_key: server_to_client_key(&pk, &net_id, &shared_a, &shared_b, &shared_c),
        read_noncegen: NonceGen::new(&eph_pk.0, &net_id),

        write_key: client_to_server_key(&server_pk, &net_id, &shared_a, &shared_b, &shared_c),
        write_noncegen: NonceGen::new(&server_eph_pk.0, &net_id),
    })
}

fn server(to_client: Sender<Vec<u8>>, from_client: Receiver<Vec<u8>>,
          pk: ServerPublicKey, sk: ServerSecretKey)
          -> Result<HandshakeOutcome, HandshakeError> {

    let net_id = NetworkKey::SSB_MAIN_NET;
    let (eph_pk, eph_sk) = server::generate_eph_keypair();

    // Receive and verify client hello
    let client_eph_pk = {
        let buf = from_client.recv().unwrap();
        let client_hello = ClientHello::from_slice(&buf)?;
        client_hello.verify(&net_id)?
    };

    // Send server hello
    let hello = ServerHello::new(&eph_pk, &net_id);
    to_client.send(hello.to_vec()).unwrap();

    // Derive shared secrets
    let shared_a = SharedA::server_side(&eph_sk, &client_eph_pk)?;
    let shared_b = SharedB::server_side(&sk, &client_eph_pk)?;

    // Receive and verify client auth
    let (client_sig, client_pk) = {
        let v = from_client.recv().unwrap();
        let client_auth = ClientAuth::from_buffer(v)?;
        client_auth.open_and_verify(&pk, &net_id, &shared_a, &shared_b)?
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk)?;

    // Send server accept
    let server_acc = ServerAccept::new(&sk, &client_pk, &net_id, &client_sig,
                                      &shared_a, &shared_b, &shared_c);
    to_client.send(server_acc.to_vec()).unwrap();

    Ok(HandshakeOutcome {
        read_key: client_to_server_key(&pk, &net_id, &shared_a, &shared_b, &shared_c),
        read_noncegen: NonceGen::new(&eph_pk.0, &net_id),

        write_key: server_to_client_key(&client_pk, &net_id, &shared_a, &shared_b, &shared_c),
        write_noncegen: NonceGen::new(&client_eph_pk.0, &net_id),
    })
}


#[test]
fn ok() -> Result<(), HandshakeError> {

    let (c2s_sender, c2s_receiver) = channel();
    let (s2c_sender, s2c_receiver) = channel();

    let (pk, sk) = generate_longterm_keypair();
    let (server_pk, server_sk) = (ServerPublicKey(pk), ServerSecretKey(sk));

    // The client needs to know the server's long-term pk before the handshake.
    let server_pk_copy = server_pk.clone();

    let client_thread = thread::spawn(move|| client(c2s_sender, s2c_receiver, server_pk_copy));
    let server_thread = thread::spawn(move|| server(s2c_sender, c2s_receiver, server_pk, server_sk));

    let mut cout = client_thread.join().unwrap()?;
    let mut sout = server_thread.join().unwrap()?;

    assert_eq!(cout.write_key, sout.read_key);
    assert_eq!(cout.read_key, sout.write_key);

    assert_eq!(cout.write_noncegen.next(),
               sout.read_noncegen.next());

    assert_eq!(cout.read_noncegen.next(),
               sout.write_noncegen.next());

    Ok(())
}
