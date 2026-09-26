use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::client;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};

use crate::debug::debug_log;
use crate::socks::{
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCESS, negotiate_socks5_connect,
    write_socks5_response,
};

use super::common::NoopClientHandler;
use super::forwarding::bridge_ssh_channel_with_tcp_stream;

const MAX_DYNAMIC_FORWARD_CONNECTIONS: usize = 256;
const SOCKS_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(test)]
mod tests;

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
        // The listener owns accepted connections, including incomplete negotiations.
        // Dropping its JoinSet aborts them when the session tears down the listener.
        let mut connections = JoinSet::new();
        loop {
            let accept_result = tokio::select! {
                accepted = listener.accept(), if connections.len() < MAX_DYNAMIC_FORWARD_CONNECTIONS => accepted,
                completed = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = completed {
                        debug_log(format!("dynamic forward connection failed to join: {error}"));
                    }
                    continue;
                }
            };
            let (stream, remote_addr) = match accept_result {
                Ok(parts) => parts,
                Err(error) => {
                    debug_log(format!("dynamic forward accept failed: {error}"));
                    break;
                }
            };
            debug_log(format!("accepted SOCKS client from {remote_addr}"));
            let session = Arc::clone(&session);
            connections.spawn(async move {
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
    let target = tokio::time::timeout(
        SOCKS_NEGOTIATION_TIMEOUT,
        negotiate_socks5_connect(&mut stream),
    )
    .await
    .context("SOCKS negotiation timed out")??;
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
