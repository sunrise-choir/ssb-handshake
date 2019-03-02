use std::env;
use std::io::{stdin, stdout, Read, Write};
use shs_core::*;

extern crate hex;
use hex::FromHex;

// For use with https://github.com/AljoschaMeyer/shs1-testsuite
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Usage: test_server net_id_hex server_sk_hex server_pk_hex");
        std::process::exit(1);
    }

    let net_id = NetworkId::from_slice(&Vec::from_hex(&args[1]).unwrap()).unwrap();
    let sk = ServerSecretKey::from_slice(&Vec::from_hex(&args[2]).unwrap()).unwrap();
    let pk = ServerPublicKey::from_slice(&Vec::from_hex(&args[3]).unwrap()).unwrap();

    let (eph_pk, eph_sk) = server::generate_eph_keypair();

    // Receive and verify client hello
    let client_eph_pk = {
        let mut buf = [0u8; 64];
        stdin().read_exact(&mut buf).unwrap();
        let client_hello = ClientHello::from_slice(&buf).unwrap();
        client_hello.verify(&net_id).unwrap()
    };

    // Send server hello
    let hello = ServerHello::new(&eph_pk, &net_id);
    stdout().write(hello.as_slice()).unwrap();
    stdout().flush().unwrap();

    // Derive shared secrets
    let shared_a = SharedA::server_side(&eph_sk, &client_eph_pk).unwrap();
    let shared_b = SharedB::server_side(&sk, &client_eph_pk).unwrap();

    // Receive and verify client auth
    let (client_sig, client_pk) = {
        let mut buf = [0u8; 112];
        stdin().read_exact(&mut buf).unwrap();

        let client_auth = ClientAuth::from_buffer(buf.to_vec()).unwrap();
        client_auth.open_and_verify(&pk, &net_id, &shared_a, &shared_b).unwrap()
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk).unwrap();

    // Send server accept
    let server_acc = ServerAccept::new(&sk, &client_pk, &net_id, &client_sig,
                                       &shared_a, &shared_b, &shared_c);
    stdout().write(server_acc.as_slice()).unwrap();
    stdout().flush().unwrap();

    // Derive shared keys for box streams
    let c2s_key = ClientToServerKey::new(&pk, &net_id, &shared_a, &shared_b, &shared_c);
    let s2c_key = ServerToClientKey::new(&client_pk, &net_id, &shared_a, &shared_b, &shared_c);

    let mut c2s_nonces = ClientToServerNonceGen::new(&eph_pk, &net_id);
    let mut s2c_nonces = ServerToClientNonceGen::new(&client_eph_pk, &net_id);

    let mut v = s2c_key.as_slice().to_vec();
    v.extend_from_slice(s2c_nonces.next().as_slice());
    v.extend_from_slice(c2s_key.as_slice());
    v.extend_from_slice(c2s_nonces.next().as_slice());
    assert_eq!(v.len(), 112);

    stdout().write(&v).unwrap();
    stdout().flush().unwrap();
}

// read 64 bytes msg1 from stdin
// write 64 bytes msg2 to stdout
// read 112 bytes msg3 from stdin
// write 80 bytes msg4 to stdout
// write 32 + 24 +32 + 24 = 112 bytes outcome to stdout
