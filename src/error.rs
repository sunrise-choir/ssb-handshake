use std::io;

quick_error! {
    #[derive(Debug)]
    pub enum HandshakeError {
        Io(err: io::Error) {
            description(err.description())
        }

        ClientHelloDeserializeFailed {
            description("Failed to read client hello message")
        }
        ClientHelloVerifyFailed {
            description("Failed to verify client hello message")
        }

        ServerHelloDeserializeFailed {
            description("Failed to read server hello message")
        }
        ServerHelloVerifyFailed {
            description("Failed to verify server hello message")
        }

        ClientAuthDeserializeFailed {
            description("Failed to read client auth message")
        }
        ClientAuthOpenFailed {
            description("Failed to decrypt client auth message")
        }
        ClientAuthVerifyFailed {
            description("Failed to verify client auth message")
        }

        ServerAcceptDeserializeFailed {
            description("Failed to read server accept message")
        }
        ServerAcceptOpenFailed {
            description("Failed to decrypt server accept message")
        }
        ServerAcceptVerifyFailed {
            description("Failed to verify server accept message")
        }

        SharedAInvalid {}
        SharedBInvalid {}
        SharedCInvalid {}
    }
}
impl From<io::Error> for HandshakeError {
    fn from(err: io::Error) -> HandshakeError {
        HandshakeError::Io(err)
    }
}
impl From<HandshakeError> for io::Error {
    fn from(err: HandshakeError) -> io::Error {
        match err {
            HandshakeError::Io(err) => err,
            err => io::Error::new(io::ErrorKind::InvalidData, err)
        }
    }
}
