use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("IO error")]
    Io(#[from] io::Error),
    #[error("Failed to read client hello message")]
    ClientHelloDeserializeFailed,
    #[error("Failed to verify client hello message")]
    ClientHelloVerifyFailed,
    #[error("Failed to read server hello message")]
    ServerHelloDeserializeFailed,
    #[error("Failed to verify server hello message")]
    ServerHelloVerifyFailed,
    #[error("Failed to read client auth message")]
    ClientAuthDeserializeFailed,
    #[error("Failed to decrypt client auth message")]
    ClientAuthOpenFailed,
    #[error("Failed to verify client auth message")]
    ClientAuthVerifyFailed,
    #[error("Failed to read server accept message")]
    ServerAcceptDeserializeFailed,
    #[error("Failed to decrypt server accept message")]
    ServerAcceptOpenFailed,
    #[error("Failed to verify server accept message")]
    ServerAcceptVerifyFailed,
    #[error("Shared secret A is invalid")]
    SharedAInvalid,
    #[error("Shared secret B is invalid")]
    SharedBInvalid,
    #[error("Shared secret C is invalid")]
    SharedCInvalid,
}
