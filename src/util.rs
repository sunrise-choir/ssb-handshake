use crate::bytes::AsBytes;
use futures_io::AsyncWrite;
use futures_util::AsyncWriteExt;

pub async fn send<S, M>(stream: &mut S, msg: M) -> Result<(), futures_io::Error>
where
    S: AsyncWrite + Unpin,
    M: AsBytes,
{
    stream.write_all(msg.as_bytes()).await?;
    stream.flush().await
}
