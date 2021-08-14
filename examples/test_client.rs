use futures::executor::block_on;
use futures::io::AllowStdIo;
use ssb_handshake::*;
use std::env;
use std::io::{self, stdin, stdout, Write};

extern crate readwrite;
use readwrite::ReadWrite;

extern crate hex;
use hex::FromHex;

extern crate ssb_crypto;
use ssb_crypto::{Keypair, NetworkKey, PublicKey};

// For use with https://github.com/AljoschaMeyer/shs1-testsuite
fn main() -> Result<(), HandshakeError<io::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: test_client net_id_as_hex server_pk_as_hex");
        std::process::exit(1);
    }

    let net_key = NetworkKey::from_slice(&Vec::from_hex(&args[1]).unwrap()).unwrap();
    let server_pk = PublicKey::from_slice(&Vec::from_hex(&args[2]).unwrap()).unwrap();

    let key = Keypair::generate();

    let mut stream = AllowStdIo::new(ReadWrite::new(stdin(), stdout()));
    let o = block_on(client_side(&mut stream, &net_key, &key, &server_pk))?;

    let mut v = o.write_key.0.to_vec();
    v.extend_from_slice(&o.write_starting_nonce.0);
    v.extend_from_slice(&o.read_key.0);
    v.extend_from_slice(&o.read_starting_nonce.0);
    assert_eq!(v.len(), 112);

    stdout().write_all(&v).unwrap();
    stdout().flush().unwrap();

    Ok(())
}
