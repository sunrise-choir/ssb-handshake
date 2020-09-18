use genio::error::ReadExactError;

#[derive(Debug)]
pub enum HandshakeError<IoErr> {
    Io(IoErr),
    UnexpectedEnd,
    ClientHelloDeserializeFailed,
    ClientHelloVerifyFailed,
    ServerHelloDeserializeFailed,
    ServerHelloVerifyFailed,
    ClientAuthDeserializeFailed,
    ClientAuthVerifyFailed,
    ServerAcceptDeserializeFailed,
    ServerAcceptVerifyFailed,
    SharedAInvalid,
    SharedBInvalid,
    SharedCInvalid,
}

impl<IoErr> From<IoErr> for HandshakeError<IoErr> {
    fn from(err: IoErr) -> Self {
        HandshakeError::Io(err)
    }
}

impl<IoErr> From<ReadExactError<IoErr>> for HandshakeError<IoErr> {
    fn from(err: ReadExactError<IoErr>) -> Self {
        match err {
            ReadExactError::UnexpectedEnd => HandshakeError::UnexpectedEnd,
            ReadExactError::Other(e) => HandshakeError::Io(e),
        }
    }
}

#[cfg(feature = "std")]
impl<IoErr> std::fmt::Display for HandshakeError<IoErr>
where
    IoErr: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use HandshakeError::*;
        match self {
            Io(e) => write!(f, "IO error: {}", e),
            UnexpectedEnd => write!(f, "Unexpected end when reading from stream"),
            ClientHelloDeserializeFailed => write!(f, "Failed to read client hello message"),
            ClientHelloVerifyFailed => write!(f, "Failed to verify client hello message"),
            ServerHelloDeserializeFailed => write!(f, "Failed to read server hello message"),
            ServerHelloVerifyFailed => write!(f, "Failed to verify server hello message"),
            ClientAuthDeserializeFailed => write!(f, "Failed to read client auth message"),
            ClientAuthVerifyFailed => write!(f, "Failed to verify client auth message"),
            ServerAcceptDeserializeFailed => write!(f, "Failed to read server accept message"),
            ServerAcceptVerifyFailed => write!(f, "Failed to verify server accept message"),
            SharedAInvalid => write!(f, "Shared secret A is invalid"),
            SharedBInvalid => write!(f, "Shared secret B is invalid"),
            SharedCInvalid => write!(f, "Shared secret C is invalid"),
        }
    }
}

#[cfg(feature = "std")]
impl<IoErr> std::error::Error for HandshakeError<IoErr>
where
    IoErr: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandshakeError::Io(e) => Some(e),
            _ => None,
        }
    }
}
