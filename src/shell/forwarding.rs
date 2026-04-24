use anyhow::{Context, Result};
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub(super) async fn bridge_ssh_channel_with_tcp_stream<S>(
    channel: Channel<S>,
    tcp_stream: TcpStream,
) -> Result<()>
where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    let (mut channel_reader, channel_writer) = channel.split();
    let mut ssh_reader = channel_reader.make_reader();
    let mut ssh_writer = channel_writer.make_writer();
    let (mut tcp_reader, mut tcp_writer) = tcp_stream.into_split();

    let client_to_remote = async {
        tokio::io::copy(&mut tcp_reader, &mut ssh_writer)
            .await
            .context("failed to copy local TCP data into SSH channel")?;
        channel_writer
            .eof()
            .await
            .context("failed to send EOF to SSH channel")?;
        Result::<(), anyhow::Error>::Ok(())
    };
    let remote_to_client = async {
        tokio::io::copy(&mut ssh_reader, &mut tcp_writer)
            .await
            .context("failed to copy SSH channel data into local TCP stream")?;
        tcp_writer
            .shutdown()
            .await
            .context("failed to shut down local TCP writer")?;
        Result::<(), anyhow::Error>::Ok(())
    };

    let (upload_result, download_result) = tokio::join!(client_to_remote, remote_to_client);
    let _ = channel_writer.close().await;
    upload_result?;
    download_result?;
    Ok(())
}
