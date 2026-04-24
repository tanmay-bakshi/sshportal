use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use russh::client;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use super::common::{NoopClientHandler, debug_log};
use super::forwarding::bridge_ssh_channel_with_tcp_stream;

pub(super) struct DynamicForwardListener {
    listen_addr: SocketAddr,
    task: JoinHandle<()>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct SocksConnectTarget {
    pub(super) host: String,
    pub(super) port: u16,
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

pub(super) const SOCKS_VERSION: u8 = 0x05;
pub(super) const SOCKS_AUTH_NONE: u8 = 0x00;
pub(super) const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;
pub(super) const SOCKS_CMD_CONNECT: u8 = 0x01;
pub(super) const SOCKS_REPLY_SUCCESS: u8 = 0x00;
pub(super) const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
pub(super) const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub(super) const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
pub(super) const SOCKS_ATYP_IPV4: u8 = 0x01;
pub(super) const SOCKS_ATYP_DOMAIN_NAME: u8 = 0x03;
pub(super) const SOCKS_ATYP_IPV6: u8 = 0x04;

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
    let target = negotiate_socks5(&mut stream).await?;
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
            write_socks5_response(&mut stream, SOCKS_REPLY_GENERAL_FAILURE)
                .await
                .context("failed to send SOCKS connect failure")?;
            return Err(error).context(format!(
                "failed to open direct-tcpip channel to {}:{}",
                target.host, target.port
            ));
        }
    };
    write_socks5_response(&mut stream, SOCKS_REPLY_SUCCESS)
        .await
        .context("failed to send SOCKS connect success")?;
    bridge_ssh_channel_with_tcp_stream(channel, stream)
        .await
        .context("SOCKS tunnel failed")
}

pub(super) async fn negotiate_socks5<S>(stream: &mut S) -> Result<SocksConnectTarget>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .context("failed to read SOCKS greeting header")?;
    if greeting[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version {}", greeting[0]);
    }

    let method_count = usize::from(greeting[1]);
    let mut methods = vec![0_u8; method_count];
    stream
        .read_exact(&mut methods)
        .await
        .context("failed to read SOCKS methods")?;
    if !methods.contains(&SOCKS_AUTH_NONE) {
        stream
            .write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE_METHODS])
            .await
            .context("failed to reject SOCKS authentication methods")?;
        stream
            .flush()
            .await
            .context("failed to flush SOCKS authentication rejection")?;
        bail!("SOCKS client did not offer no-authentication mode");
    }

    stream
        .write_all(&[SOCKS_VERSION, SOCKS_AUTH_NONE])
        .await
        .context("failed to accept SOCKS authentication method")?;
    stream
        .flush()
        .await
        .context("failed to flush SOCKS authentication response")?;

    let mut request_header = [0_u8; 4];
    stream
        .read_exact(&mut request_header)
        .await
        .context("failed to read SOCKS connect request header")?;
    if request_header[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS request version {}", request_header[0]);
    }
    if request_header[1] != SOCKS_CMD_CONNECT {
        write_socks5_response(stream, SOCKS_REPLY_COMMAND_NOT_SUPPORTED)
            .await
            .context("failed to reject unsupported SOCKS command")?;
        bail!("unsupported SOCKS command {}", request_header[1]);
    }
    if request_header[2] != 0 {
        bail!("invalid SOCKS reserved byte {}", request_header[2]);
    }

    let host = match request_header[3] {
        SOCKS_ATYP_IPV4 => {
            let mut address_bytes = [0_u8; 4];
            stream
                .read_exact(&mut address_bytes)
                .await
                .context("failed to read SOCKS IPv4 destination")?;
            Ipv4Addr::from(address_bytes).to_string()
        }
        SOCKS_ATYP_DOMAIN_NAME => {
            let mut name_length = [0_u8; 1];
            stream
                .read_exact(&mut name_length)
                .await
                .context("failed to read SOCKS domain length")?;
            let mut name_bytes = vec![0_u8; usize::from(name_length[0])];
            stream
                .read_exact(&mut name_bytes)
                .await
                .context("failed to read SOCKS domain name")?;
            String::from_utf8(name_bytes).context("SOCKS domain name is not valid UTF-8")?
        }
        SOCKS_ATYP_IPV6 => {
            let mut address_bytes = [0_u8; 16];
            stream
                .read_exact(&mut address_bytes)
                .await
                .context("failed to read SOCKS IPv6 destination")?;
            std::net::Ipv6Addr::from(address_bytes).to_string()
        }
        address_type => {
            write_socks5_response(stream, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
                .await
                .context("failed to reject unsupported SOCKS address type")?;
            bail!("unsupported SOCKS address type {address_type}");
        }
    };

    let mut port_bytes = [0_u8; 2];
    stream
        .read_exact(&mut port_bytes)
        .await
        .context("failed to read SOCKS destination port")?;
    Ok(SocksConnectTarget {
        host,
        port: u16::from_be_bytes(port_bytes),
    })
}

async fn write_socks5_response<S>(stream: &mut S, reply: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[SOCKS_VERSION, reply, 0, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
        .context("failed to write SOCKS response")?;
    stream
        .flush()
        .await
        .context("failed to flush SOCKS response")
}
