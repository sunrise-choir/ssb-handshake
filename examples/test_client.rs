use futures::executor::block_on;
use futures::io::AllowStdIo;
use ssb_handshake::*;
use std::env;
use std::io::{stdin, stdout, Write};

extern crate readwrite;
use readwrite::ReadWrite;

extern crate hex;
use hex::FromHex;

extern crate ssb_crypto;
use ssb_crypto::{generate_longterm_keypair, NetworkKey, PublicKey};

// For use with https://github.com/AljoschaMeyer/shs1-testsuite
fn main() -> Result<(), HandshakeError> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: test_client net_id_as_hex server_pk_as_hex");
        std::process::exit(1);
    }

    let net_key = NetworkKey::from_slice(&Vec::from_hex(&args[1]).unwrap()).unwrap();
    let server_pk = PublicKey::from_slice(&Vec::from_hex(&args[2]).unwrap()).unwrap();

    let (pk, sk) = generate_longterm_keypair();

    let mut stream = AllowStdIo::new(ReadWrite::new(stdin(), stdout()));
    let mut o = block_on(client(&mut stream, net_key, pk, sk, server_pk))?;

    let mut v = o.write_key[..].to_vec();
    v.extend_from_slice(&o.write_noncegen.next()[..]);
    v.extend_from_slice(&o.read_key[..]);
    v.extend_from_slice(&o.read_noncegen.next()[..]);
    assert_eq!(v.len(), 112);

    stdout().write_all(&v).unwrap();
    stdout().flush().unwrap();

    Ok(())
}
