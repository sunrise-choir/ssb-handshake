use crate::bytes::AsBytes;
use genio::Write;

pub fn send<S, M, IoErr>(stream: &mut S, msg: M) -> Result<(), IoErr>
where
    S: Write<WriteError = IoErr, FlushError = IoErr>,
    M: AsBytes,
{
    stream.write_all(msg.as_bytes())?;
    stream.flush()
}
