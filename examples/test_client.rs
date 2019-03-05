use std::env;
use std::io::{stdin, stdout, Read, Write};
use shs_core::*;

extern crate hex;
use hex::FromHex;

// For use with https://github.com/AljoschaMeyer/shs1-testsuite
// cargo run --example test_client d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb 4fe84c0c552740abc0efa893916a56f7cb7f42d8c8f606f4c41d8125613f8cc6
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: test_client net_id_as_hex server_pk_as_hex");
        std::process::exit(1);
    }

    let net_id = NetworkId::from_slice(&Vec::from_hex(&args[1]).unwrap()).unwrap();
    let server_pk = ServerPublicKey::from_slice(&Vec::from_hex(&args[2]).unwrap()).unwrap();

    let (pk, sk) = client::generate_longterm_keypair();
    let (eph_pk, eph_sk) = client::generate_eph_keypair();

    // Send client hello
    let hello = ClientHello::new(&eph_pk, &net_id);
    stdout().write(hello.as_slice()).unwrap();
    stdout().flush().unwrap();

    let server_eph_pk = {
        let mut buf = [0u8; ServerHello::size()];
        stdin().read_exact(&mut buf).unwrap();
        let server_hello = ServerHello::from_slice(&buf).unwrap();
        server_hello.verify(&net_id).unwrap()
    };

    // Derive shared secrets
    let shared_a = SharedA::client_side(&eph_sk, &server_eph_pk).unwrap();
    let shared_b = SharedB::client_side(&eph_sk, &server_pk).unwrap();

    // Send client auth
    let client_auth = ClientAuth::new(&sk, &pk, &server_pk, &net_id, &shared_a, &shared_b);
    stdout().write(client_auth.as_slice()).unwrap();
    stdout().flush().unwrap();

    // Derive shared secret
    let shared_c = SharedC::client_side(&sk, &server_eph_pk).unwrap();

    let ok = {
        let mut buf = [0u8; ServerAccept::size()];
        stdin().read_exact(&mut buf).unwrap();
        let server_acc = ServerAccept::from_buffer(buf.to_vec()).unwrap();
        server_acc.open_and_verify(&sk, &pk, &server_pk,
                                   &net_id, &shared_a,
                                   &shared_b, &shared_c)
    };
    assert!(ok);

    // encryption_key, encryption_nonce, decryption_key and decryption_nonce
    // // Derive shared keys for box streams
    let c2s_key = ClientToServerKey::new(&server_pk, &net_id, &shared_a, &shared_b, &shared_c);
    let s2c_key = ServerToClientKey::new(&pk, &net_id, &shared_a, &shared_b, &shared_c);

    let mut c2s_nonces = ClientToServerNonceGen::new(&server_eph_pk, &net_id);
    let mut s2c_nonces = ServerToClientNonceGen::new(&eph_pk, &net_id);

    let mut v = c2s_key.as_slice().to_vec();
    v.extend_from_slice(c2s_nonces.next().as_slice());
    v.extend_from_slice(s2c_key.as_slice());
    v.extend_from_slice(s2c_nonces.next().as_slice());
    assert_eq!(v.len(), 112);

    stdout().write(&v).unwrap();
    stdout().flush().unwrap();
}
