use futures::executor::block_on;
use futures::io::AllowStdIo;
use std::env;
use std::io::{self, stdin, stdout, Write};

use ssb_crypto::{Keypair, NetworkKey, PublicKey};
use ssb_handshake::*;

extern crate readwrite;
use readwrite::ReadWrite;

extern crate hex;
use hex::FromHex;

// For use with https://github.com/AljoschaMeyer/shs1-testsuite
//
// cargo build --example test_server --release
// node ../shs1-testsuite/test-server.js target/release/examples/test_server
fn main() -> Result<(), HandshakeError<io::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Usage: test_server net_id_hex server_sk_hex server_pk_hex");
        std::process::exit(1);
    }

    let net_key = NetworkKey::from_slice(&Vec::from_hex(&args[1]).unwrap()).unwrap();
    let key = Keypair::from_slice(&Vec::from_hex(&args[2]).unwrap()).unwrap();
    let pk = PublicKey::from_slice(&Vec::from_hex(&args[3]).unwrap()).unwrap();
    assert_eq!(key.public, pk);

    let mut stream = AllowStdIo::new(ReadWrite::new(stdin(), stdout()));
    let o = block_on(server_side(&mut stream, &net_key, &key))?;

    let mut v = o.write_key.0.to_vec();
    v.extend_from_slice(&o.write_starting_nonce.0);
    v.extend_from_slice(&o.read_key.0);
    v.extend_from_slice(&o.read_starting_nonce.0);
    assert_eq!(v.len(), 112);

    stdout().write_all(&v).unwrap();
    stdout().flush().unwrap();

    Ok(())
}
