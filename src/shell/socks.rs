use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use russh::client;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use crate::debug::debug_log;
use crate::socks::{
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCESS, SocksAuthentication,
    negotiate_socks5_connect, write_socks5_response,
};

use super::common::NoopClientHandler;
use super::forwarding::bridge_ssh_channel_with_tcp_stream;

pub(super) struct DynamicForwardListener {
    listen_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DynamicForwardListener {
    pub(super) fn local_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

impl Drop for DynamicForwardListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) async fn start_dynamic_forward_listener(
    session: Arc<AsyncMutex<client::Handle<NoopClientHandler>>>,
    listen_addr: SocketAddr,
) -> Result<DynamicForwardListener> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind dynamic forward listener to {listen_addr}"))?;
    let bound_addr = listener
        .local_addr()
        .context("failed to read dynamic forward listener address")?;
    let task = tokio::spawn(async move {
        loop {
            let accept_result = listener.accept().await;
            let (stream, remote_addr) = match accept_result {
                Ok(parts) => parts,
                Err(error) => {
                    debug_log(format!("dynamic forward accept failed: {error}"));
                    break;
                }
            };
            debug_log(format!("accepted SOCKS client from {remote_addr}"));
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                if let Err(error) = handle_dynamic_forward_connection(stream, session).await {
                    debug_log(format!("SOCKS client handling failed: {error:#}"));
                }
            });
        }
    });
    Ok(DynamicForwardListener {
        listen_addr: bound_addr,
        task,
    })
}

async fn handle_dynamic_forward_connection(
    mut stream: TcpStream,
    session: Arc<AsyncMutex<client::Handle<NoopClientHandler>>>,
) -> Result<()> {
    let target = negotiate_socks5_connect(&mut stream, &SocksAuthentication::None).await?;
    let originator_addr = stream
        .peer_addr()
        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    debug_log(format!(
        "opening direct-tcpip channel to {}:{} for {}",
        target.host, target.port, originator_addr
    ));
    let channel_result = {
        let session_guard = session.lock().await;
        session_guard
            .channel_open_direct_tcpip(
                target.host.clone(),
                u32::from(target.port),
                originator_addr.ip().to_string(),
                u32::from(originator_addr.port()),
            )
            .await
    };
    let channel = match channel_result {
        Ok(channel) => channel,
        Err(error) => {
            write_socks5_response(&mut stream, SOCKS_REPLY_GENERAL_FAILURE, None)
                .await
                .context("failed to send SOCKS connect failure")?;
            return Err(error).context(format!(
                "failed to open direct-tcpip channel to {}:{}",
                target.host, target.port
            ));
        }
    };
    write_socks5_response(&mut stream, SOCKS_REPLY_SUCCESS, None)
        .await
        .context("failed to send SOCKS connect success")?;
    bridge_ssh_channel_with_tcp_stream(channel, stream)
        .await
        .context("SOCKS tunnel failed")
}
