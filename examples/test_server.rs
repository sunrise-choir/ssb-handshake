use futures::executor::block_on;
use futures::io::AllowStdIo;
use std::env;
use std::io::{stdin, stdout, Write};

use ssb_crypto::{NetworkKey, PublicKey, SecretKey};
use ssb_handshake::*;

extern crate readwrite;
use readwrite::ReadWrite;

extern crate hex;
use hex::FromHex;

// For use with https://github.com/AljoschaMeyer/shs1-testsuite
//
// cargo build --example test_server --release
// node ../shs1-testsuite/test-server.js target/release/examples/test_server
fn main() -> Result<(), HandshakeError> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Usage: test_server net_id_hex server_sk_hex server_pk_hex");
        std::process::exit(1);
    }

    let net_key = NetworkKey::from_slice(&Vec::from_hex(&args[1]).unwrap()).unwrap();
    let sk = SecretKey::from_slice(&Vec::from_hex(&args[2]).unwrap()).unwrap();
    let pk = PublicKey::from_slice(&Vec::from_hex(&args[3]).unwrap()).unwrap();

    let mut stream = AllowStdIo::new(ReadWrite::new(stdin(), stdout()));
    let mut o = block_on(server(&mut stream, net_key, pk, sk))?;

    let mut v = o.write_key[..].to_vec();
    v.extend_from_slice(&o.write_noncegen.next()[..]);
    v.extend_from_slice(&o.read_key[..]);
    v.extend_from_slice(&o.read_noncegen.next()[..]);
    assert_eq!(v.len(), 112);

    stdout().write_all(&v).unwrap();
    stdout().flush().unwrap();

    Ok(())
}
