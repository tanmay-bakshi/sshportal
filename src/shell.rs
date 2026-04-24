use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child as StdChild, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use portable_pty::{ChildKiller, MasterPty, PtyPair, PtySize, native_pty_system};
use russh::client;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, ssh_key};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, mpsc as tokio_mpsc};
use tokio::task::JoinHandle;

use crate::platform::ShellLaunch;

struct DynamicForwardListener {
    listen_addr: SocketAddr,
    task: JoinHandle<()>,
}

struct SshProxyListener {
    listen_addr: SocketAddr,
    task: JoinHandle<()>,
}

#[derive(Debug, Eq, PartialEq)]
struct SocksConnectTarget {
    host: String,
    port: u16,
}

impl DynamicForwardListener {
    fn local_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

impl Drop for DynamicForwardListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SshProxyListener {
    fn local_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

impl Drop for SshProxyListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct NoopClientHandler;

impl client::Handler for NoopClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn debug_enabled() -> bool {
    env::var_os("SSHPORTAL_DEBUG").is_some()
}

fn debug_log(message: impl AsRef<str>) {
    if debug_enabled() {
        eprintln!("[sshportal-debug] {}", message.as_ref());
    }
}

fn debug_public_key(label: &str, public_key: &PublicKey) {
    if !debug_enabled() {
        return;
    }
    let rendered_key = public_key
        .to_openssh()
        .unwrap_or_else(|_| "<failed to render public key>".to_string());
    eprintln!("[sshportal-debug] {label}: {rendered_key}");
}

fn same_public_key(left: &PublicKey, right: &PublicKey) -> bool {
    left.algorithm() == right.algorithm() && left.key_data() == right.key_data()
}

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_AUTH_NONE: u8 = 0x00;
const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_REPLY_SUCCESS: u8 = 0x00;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN_NAME: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;
const SSH_EXTENDED_DATA_STDERR: u32 = 1;
const SESSION_INPUT_CHANNEL_CAPACITY: usize = 32;
const SESSION_OUTPUT_CHANNEL_CAPACITY: usize = 32;

async fn start_dynamic_forward_listener(
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

async fn negotiate_socks5<S>(stream: &mut S) -> Result<SocksConnectTarget>
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

async fn bridge_ssh_channel_with_tcp_stream<S>(
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

async fn connect_authenticated_client_transport<S>(
    io: S,
    username: &str,
    private_key: Arc<PrivateKey>,
) -> Result<client::Handle<NoopClientHandler>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug_log("starting SSH client session");
    let client_config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 12,
        nodelay: true,
        ..client::Config::default()
    });
    let mut session = client::connect_stream(client_config, io, NoopClientHandler)
        .await
        .context("failed to start SSH client transport")?;
    debug_log("SSH client transport established");

    let negotiated_hash: Option<HashAlg> = session
        .best_supported_rsa_hash()
        .await
        .context("failed to determine RSA hash preference")?
        .flatten();
    debug_public_key("SSH client auth key", private_key.public_key());
    let auth_result = session
        .authenticate_publickey(
            username.to_string(),
            PrivateKeyWithHashAlg::new(private_key, negotiated_hash),
        )
        .await
        .context("SSH public-key authentication failed")?;
    if !auth_result.success() {
        bail!("SSH authentication was rejected by the remote shell");
    }
    debug_log("SSH client authenticated");
    Ok(session)
}

async fn wait_for_client_transport_close(
    session: &Arc<AsyncMutex<client::Handle<NoopClientHandler>>>,
) {
    loop {
        let is_closed = {
            let session_guard = session.lock().await;
            session_guard.is_closed()
        };
        if is_closed {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn build_ssh_proxy_server_config() -> Result<Arc<server::Config>> {
    let host_key = PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::OsRng,
        ssh_key::Algorithm::Ed25519,
    )
    .context("failed to generate SSH proxy host key")?;
    let config = server::Config {
        auth_rejection_time: Duration::from_secs(2),
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 12,
        nodelay: true,
        keys: vec![host_key],
        ..Default::default()
    };
    Ok(Arc::new(config))
}

async fn run_local_ssh_proxy_connection<S>(
    io: S,
    config: Arc<server::Config>,
    handler: LocalSshProxyHandler,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let running_session = server::run_stream(config, io, handler)
        .await
        .context("failed to start local SSH proxy transport")?;
    running_session
        .await
        .context("local SSH proxy connection failed")
}

async fn start_ssh_proxy_listener(
    upstream_session: Arc<AsyncMutex<client::Handle<NoopClientHandler>>>,
    listen_addr: SocketAddr,
    allowed_username: String,
    allowed_public_key: PublicKey,
) -> Result<SshProxyListener> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind local SSH proxy listener to {listen_addr}"))?;
    let bound_addr = listener
        .local_addr()
        .context("failed to read local SSH proxy listener address")?;
    let config = build_ssh_proxy_server_config()?;
    let task = tokio::spawn(async move {
        loop {
            let accept_result = listener.accept().await;
            let (stream, remote_addr) = match accept_result {
                Ok(parts) => parts,
                Err(error) => {
                    debug_log(format!("local SSH proxy accept failed: {error}"));
                    break;
                }
            };
            debug_log(format!(
                "accepted local SSH proxy client from {remote_addr}"
            ));
            let config = Arc::clone(&config);
            let handler = LocalSshProxyHandler {
                allowed_username: allowed_username.clone(),
                allowed_public_key: allowed_public_key.clone(),
                upstream_session: Arc::clone(&upstream_session),
                channels: Arc::new(AsyncMutex::new(HashMap::new())),
            };
            tokio::spawn(async move {
                if let Err(error) = run_local_ssh_proxy_connection(stream, config, handler).await {
                    debug_log(format!("local SSH proxy connection failed: {error:#}"));
                }
            });
        }
    });
    Ok(SshProxyListener {
        listen_addr: bound_addr,
        task,
    })
}

fn print_ssh_proxy_usage(listen_addr: SocketAddr, username: &str) {
    println!("SSH proxy listening on {listen_addr}");
    if listen_addr.ip().is_loopback() {
        println!(
            "open support shells with: ssh -p {} {}@{}",
            listen_addr.port(),
            username,
            listen_addr.ip()
        );
        return;
    }
    println!("use SSH username `{username}` when opening proxied sessions");
}

pub async fn run_client_session_proxy<S>(
    io: S,
    username: &str,
    private_key: Arc<PrivateKey>,
    ssh_listen: SocketAddr,
    dynamic_forward_listen: Option<SocketAddr>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let allowed_public_key = private_key.public_key().clone();
    let session = connect_authenticated_client_transport(io, username, private_key).await?;
    let session = Arc::new(AsyncMutex::new(session));
    let ssh_proxy_listener = start_ssh_proxy_listener(
        Arc::clone(&session),
        ssh_listen,
        username.to_string(),
        allowed_public_key,
    )
    .await?;
    print_ssh_proxy_usage(ssh_proxy_listener.local_addr(), username);

    let dynamic_forward_listener = match dynamic_forward_listen {
        Some(listen_addr) => {
            let listener =
                start_dynamic_forward_listener(Arc::clone(&session), listen_addr).await?;
            println!("SOCKS5 proxy listening on {}", listener.local_addr());
            Some(listener)
        }
        None => None,
    };

    wait_for_client_transport_close(&session).await;
    drop(dynamic_forward_listener);
    drop(ssh_proxy_listener);
    Ok(())
}

struct ProxiedSessionChannel {
    upstream_writer: Arc<ChannelWriteHalf<client::Msg>>,
}

struct LocalSshProxyHandler {
    allowed_username: String,
    allowed_public_key: PublicKey,
    upstream_session: Arc<AsyncMutex<client::Handle<NoopClientHandler>>>,
    channels: Arc<AsyncMutex<HashMap<ChannelId, ProxiedSessionChannel>>>,
}

impl LocalSshProxyHandler {
    async fn upstream_writer(
        &self,
        channel: ChannelId,
    ) -> Option<Arc<ChannelWriteHalf<client::Msg>>> {
        let guard = self.channels.lock().await;
        guard
            .get(&channel)
            .map(|state| Arc::clone(&state.upstream_writer))
    }
}

async fn relay_ssh_session_to_local_client(
    local_channel: ChannelId,
    mut upstream_reader: ChannelReadHalf,
    local_handle: server::Handle,
    channels: Arc<AsyncMutex<HashMap<ChannelId, ProxiedSessionChannel>>>,
) {
    loop {
        let message = upstream_reader.wait().await;
        let Some(message) = message else {
            break;
        };
        match message {
            ChannelMsg::Data { data } => match local_handle.data(local_channel, data).await {
                Ok(()) => {}
                Err(_) => break,
            },
            ChannelMsg::ExtendedData { data, ext } => {
                match local_handle.extended_data(local_channel, ext, data).await {
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
            ChannelMsg::Eof => {
                let _ = local_handle.eof(local_channel).await;
            }
            ChannelMsg::Close => {
                let _ = local_handle.close(local_channel).await;
                break;
            }
            ChannelMsg::ExitStatus { exit_status } => {
                let _ = local_handle
                    .exit_status_request(local_channel, exit_status)
                    .await;
            }
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                let _ = local_handle
                    .exit_signal_request(
                        local_channel,
                        signal_name,
                        core_dumped,
                        error_message,
                        lang_tag,
                    )
                    .await;
            }
            _ => {}
        }
    }
    let mut guard = channels.lock().await;
    guard.remove(&local_channel);
}

impl server::Handler for LocalSshProxyHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, username: &str) -> Result<Auth, Self::Error> {
        debug_log(format!("rejected local SSH proxy none auth for {username}"));
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        username: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if username == self.allowed_username
            && same_public_key(public_key, &self.allowed_public_key)
        {
            return Ok(Auth::Accept);
        }
        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        username: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if username == self.allowed_username
            && same_public_key(public_key, &self.allowed_public_key)
        {
            return Ok(Auth::Accept);
        }
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let local_channel = channel.id();
        let upstream_channel = {
            let session_guard = self.upstream_session.lock().await;
            session_guard.channel_open_session().await
        };
        let upstream_channel = match upstream_channel {
            Ok(channel) => channel,
            Err(error) => {
                debug_log(format!(
                    "failed to open upstream session channel for {local_channel:?}: {error}"
                ));
                return Ok(false);
            }
        };
        let (upstream_reader, upstream_writer) = upstream_channel.split();
        let upstream_writer = Arc::new(upstream_writer);
        {
            let mut guard = self.channels.lock().await;
            guard.insert(
                local_channel,
                ProxiedSessionChannel {
                    upstream_writer: Arc::clone(&upstream_writer),
                },
            );
        }
        let local_handle = session.handle();
        let channels = Arc::clone(&self.channels);
        tokio::spawn(async move {
            relay_ssh_session_to_local_client(
                local_channel,
                upstream_reader,
                local_handle,
                channels,
            )
            .await;
        });
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(upstream_writer) = self.upstream_writer(channel).await else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if let Err(error) = upstream_writer
            .request_pty(
                true, term, col_width, row_height, pix_width, pix_height, modes,
            )
            .await
        {
            debug_log(format!(
                "failed to forward PTY request for {channel:?}: {error}"
            ));
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(upstream_writer) = self.upstream_writer(channel).await else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if let Err(error) = upstream_writer
            .set_env(true, variable_name, variable_value)
            .await
        {
            debug_log(format!(
                "failed to forward env request for {channel:?}: {variable_name}={variable_value}: {error}"
            ));
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(upstream_writer) = self.upstream_writer(channel).await else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if let Err(error) = upstream_writer.request_shell(true).await {
            debug_log(format!(
                "failed to forward shell request for {channel:?}: {error}"
            ));
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(upstream_writer) = self.upstream_writer(channel).await else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if let Err(error) = upstream_writer.exec(true, data.to_vec()).await {
            debug_log(format!(
                "failed to forward exec request for {channel:?}: {error}"
            ));
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(upstream_writer) = self.upstream_writer(channel).await else {
            return Ok(());
        };
        upstream_writer
            .data(data)
            .await
            .context("failed to forward channel data upstream")
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(upstream_writer) = self.upstream_writer(channel).await else {
            return Ok(());
        };
        let _ = upstream_writer.eof().await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let removed = {
            let mut guard = self.channels.lock().await;
            guard.remove(&channel)
        };
        if let Some(state) = removed {
            let _ = state.upstream_writer.close().await;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(upstream_writer) = self.upstream_writer(channel).await else {
            return Ok(());
        };
        upstream_writer
            .window_change(col_width, row_height, pix_width, pix_height)
            .await
            .context("failed to forward terminal resize upstream")
    }
}

pub async fn run_remote_shell_server<S>(
    io: S,
    allowed_username: String,
    allowed_public_key: PublicKey,
    working_directory: PathBuf,
    shell: ShellLaunch,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host_key = PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::OsRng,
        ssh_key::Algorithm::Ed25519,
    )
    .context("failed to generate SSH host key")?;
    debug_log("starting SSH server session");
    let config = server::Config {
        auth_rejection_time: Duration::from_secs(2),
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 12,
        nodelay: true,
        keys: vec![host_key],
        ..Default::default()
    };
    let config = Arc::new(config);

    let shell_states: Arc<AsyncMutex<HashMap<ChannelId, SessionChannelState>>> =
        Arc::new(AsyncMutex::new(HashMap::new()));
    let handler = RemoteShellHandler {
        allowed_username,
        allowed_public_key,
        working_directory,
        shell,
        shell_states: Arc::clone(&shell_states),
    };

    let running_session = server::run_stream(config, io, handler)
        .await
        .context("failed to start SSH server transport")?;
    debug_log("SSH server transport established");
    running_session.await.context("SSH server session failed")
}

struct PendingSessionChannel {
    env_vars: Vec<(String, String)>,
}

enum SessionChannelState {
    Pending(PendingSessionChannel),
    PtyAllocated {
        pair: PtyPair,
        term: String,
        env_vars: Vec<(String, String)>,
    },
    RunningPty {
        master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
        input_sender: Option<tokio_mpsc::Sender<Vec<u8>>>,
        killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    },
    RunningExec {
        child: Arc<Mutex<StdChild>>,
        input_sender: Option<tokio_mpsc::Sender<Vec<u8>>>,
    },
}

struct RemoteShellHandler {
    allowed_username: String,
    allowed_public_key: PublicKey,
    working_directory: PathBuf,
    shell: ShellLaunch,
    shell_states: Arc<AsyncMutex<HashMap<ChannelId, SessionChannelState>>>,
}

impl RemoteShellHandler {
    fn shell_size(cols: u32, rows: u32, pix_width: u32, pix_height: u32) -> PtySize {
        PtySize {
            rows: rows.max(1) as u16,
            cols: cols.max(1) as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        }
    }

    fn exit_status_code(status: ExitStatus) -> u32 {
        match status.code() {
            Some(code) => u32::try_from(code).unwrap_or(1),
            None => 1,
        }
    }

    fn read_process_output<R>(mut reader: R, sender: tokio_mpsc::Sender<Vec<u8>>)
    where
        R: Read + Send + 'static,
    {
        std::mem::drop(tokio::task::spawn_blocking(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes_read) => {
                        if sender.blocking_send(buffer[..bytes_read].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    async fn start_pty_session(
        &self,
        channel: ChannelId,
        handle: server::Handle,
        pair: PtyPair,
        term: String,
        env_vars: Vec<(String, String)>,
        command_text: Option<String>,
    ) -> Result<()> {
        let mut command = match command_text {
            Some(command_text) => self.shell.build_exec_pty_command(&command_text),
            None => self.shell.build_command(),
        };
        command.cwd(&self.working_directory);
        command.env("TERM", &term);
        for (name, value) in &env_vars {
            command.env(name, value);
        }
        let mut child = pair
            .slave
            .spawn_command(command)
            .context("failed to spawn PTY process")?;

        let killer = Arc::new(Mutex::new(child.clone_killer()));
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let mut writer = pair
            .master
            .take_writer()
            .context("failed to take PTY writer")?;
        let master = Arc::new(Mutex::new(pair.master));

        let (input_sender, mut input_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_INPUT_CHANNEL_CAPACITY);
        std::mem::drop(tokio::task::spawn_blocking(move || {
            while let Some(data) = input_receiver.blocking_recv() {
                if writer.write_all(&data).is_err() {
                    break;
                }
                if writer.flush().is_err() {
                    break;
                }
            }
        }));

        let (output_sender, mut output_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_OUTPUT_CHANNEL_CAPACITY);
        tokio::task::spawn_blocking(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes_read) => {
                        if output_sender
                            .blocking_send(buffer[..bytes_read].to_vec())
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let output_handle = handle.clone();
        tokio::spawn(async move {
            while let Some(bytes) = output_receiver.recv().await {
                if output_handle.data(channel, bytes).await.is_err() {
                    break;
                }
            }
        });

        let exit_handle = handle.clone();
        let shell_states = Arc::clone(&self.shell_states);
        tokio::spawn(async move {
            let wait_result = tokio::task::spawn_blocking(move || child.wait()).await;
            let exit_code: u32 = match wait_result {
                Ok(Ok(status)) => status.exit_code(),
                _ => 1,
            };
            debug_log(format!("PTY process exited with status {exit_code}"));
            let _ = exit_handle.exit_status_request(channel, exit_code).await;
            let _ = exit_handle.eof(channel).await;
            let _ = exit_handle.close(channel).await;
            let mut guard = shell_states.lock().await;
            guard.remove(&channel);
        });

        let mut guard = self.shell_states.lock().await;
        guard.insert(
            channel,
            SessionChannelState::RunningPty {
                master,
                input_sender: Some(input_sender),
                killer,
            },
        );
        Ok(())
    }

    async fn start_exec_session(
        &self,
        channel: ChannelId,
        handle: server::Handle,
        env_vars: Vec<(String, String)>,
        command_text: String,
    ) -> Result<()> {
        let mut command = self.shell.build_exec_command(&command_text);
        command.current_dir(&self.working_directory);
        for (name, value) in &env_vars {
            command.env(name, value);
        }
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command.spawn().context("failed to spawn exec process")?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to take exec stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("failed to take exec stderr"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to take exec stdin"))?;

        let child = Arc::new(Mutex::new(child));

        let (input_sender, mut input_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_INPUT_CHANNEL_CAPACITY);
        std::mem::drop(tokio::task::spawn_blocking(move || {
            while let Some(data) = input_receiver.blocking_recv() {
                if stdin.write_all(&data).is_err() {
                    break;
                }
                if stdin.flush().is_err() {
                    break;
                }
            }
        }));

        let (stdout_sender, mut stdout_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_OUTPUT_CHANNEL_CAPACITY);
        let (stderr_sender, mut stderr_receiver) =
            tokio_mpsc::channel::<Vec<u8>>(SESSION_OUTPUT_CHANNEL_CAPACITY);
        Self::read_process_output(stdout, stdout_sender);
        Self::read_process_output(stderr, stderr_sender);

        let stdout_handle = handle.clone();
        tokio::spawn(async move {
            while let Some(bytes) = stdout_receiver.recv().await {
                if stdout_handle.data(channel, bytes).await.is_err() {
                    break;
                }
            }
        });

        let stderr_handle = handle.clone();
        tokio::spawn(async move {
            while let Some(bytes) = stderr_receiver.recv().await {
                if stderr_handle
                    .extended_data(channel, SSH_EXTENDED_DATA_STDERR, bytes)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let wait_child = Arc::clone(&child);
        let exit_handle = handle.clone();
        let shell_states = Arc::clone(&self.shell_states);
        tokio::spawn(async move {
            let exit_code = tokio::task::spawn_blocking(move || -> u32 {
                loop {
                    let maybe_status = {
                        let mut child_guard = match wait_child.lock() {
                            Ok(child_guard) => child_guard,
                            Err(_) => return 1,
                        };
                        match child_guard.try_wait() {
                            Ok(status) => status,
                            Err(error) => {
                                debug_log(format!("failed to poll exec process status: {error:#}"));
                                return 1;
                            }
                        }
                    };
                    if let Some(status) = maybe_status {
                        return Self::exit_status_code(status);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            })
            .await
            .unwrap_or(1);
            debug_log(format!("exec process exited with status {exit_code}"));
            let _ = exit_handle.exit_status_request(channel, exit_code).await;
            let _ = exit_handle.eof(channel).await;
            let _ = exit_handle.close(channel).await;
            let mut guard = shell_states.lock().await;
            guard.remove(&channel);
        });

        let mut guard = self.shell_states.lock().await;
        guard.insert(
            channel,
            SessionChannelState::RunningExec {
                child,
                input_sender: Some(input_sender),
            },
        );
        Ok(())
    }
}

impl server::Handler for RemoteShellHandler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        username: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        debug_log(format!("auth publickey offered for {username}"));
        debug_public_key("offered auth key", public_key);
        debug_public_key("allowed auth key", &self.allowed_public_key);
        if username == self.allowed_username
            && same_public_key(public_key, &self.allowed_public_key)
        {
            return Ok(Auth::Accept);
        }
        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        username: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        debug_log(format!("auth publickey verify for {username}"));
        if username == self.allowed_username
            && same_public_key(public_key, &self.allowed_public_key)
        {
            return Ok(Auth::Accept);
        }
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug_log(format!(
            "channel_open_session received for {:?}",
            channel.id()
        ));
        let mut guard = self.shell_states.lock().await;
        guard.insert(
            channel.id(),
            SessionChannelState::Pending(PendingSessionChannel {
                env_vars: Vec::new(),
            }),
        );
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let port = match u16::try_from(port_to_connect) {
            Ok(port) => port,
            Err(_) => {
                debug_log(format!(
                    "rejecting direct-tcpip request with invalid port {port_to_connect}"
                ));
                return Ok(false);
            }
        };
        let outbound = match TcpStream::connect((host_to_connect, port)).await {
            Ok(stream) => stream,
            Err(error) => {
                debug_log(format!(
                    "failed to connect direct-tcpip target {host_to_connect}:{port} from \
                     {originator_address}:{originator_port}: {error}"
                ));
                return Ok(false);
            }
        };
        debug_log(format!(
            "accepted direct-tcpip request {host_to_connect}:{port} from \
             {originator_address}:{originator_port}"
        ));
        tokio::spawn(async move {
            if let Err(error) = bridge_ssh_channel_with_tcp_stream(channel, outbound).await {
                debug_log(format!("direct-tcpip bridge failed: {error:#}"));
            }
        });
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug_log(format!(
            "pty_request term={term} cols={col_width} rows={row_height} pix_width={pix_width} pix_height={pix_height}"
        ));
        let pty_system = native_pty_system();
        let size = Self::shell_size(col_width, row_height, pix_width, pix_height);
        let pair = match pty_system.openpty(size) {
            Ok(pair) => pair,
            Err(error) => {
                debug_log(format!("failed to allocate PTY for {channel:?}: {error:#}"));
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let mut guard = self.shell_states.lock().await;
        let Some(SessionChannelState::Pending(pending_state)) = guard.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        guard.insert(
            channel,
            SessionChannelState::PtyAllocated {
                pair,
                term: term.to_string(),
                env_vars: pending_state.env_vars,
            },
        );
        session.channel_success(channel)?;
        debug_log("pty_request accepted");
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut guard = self.shell_states.lock().await;
        let success = match guard.get_mut(&channel) {
            Some(SessionChannelState::Pending(pending_state)) => {
                pending_state
                    .env_vars
                    .push((variable_name.to_string(), variable_value.to_string()));
                true
            }
            Some(SessionChannelState::PtyAllocated { env_vars, .. }) => {
                env_vars.push((variable_name.to_string(), variable_value.to_string()));
                true
            }
            _ => false,
        };
        if success {
            session.channel_success(channel)?;
            return Ok(());
        }
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug_log("shell_request received");
        let pending_state = {
            let mut guard = self.shell_states.lock().await;
            guard.remove(&channel)
        };
        let Some(SessionChannelState::PtyAllocated {
            pair,
            term,
            env_vars,
        }) = pending_state
        else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if let Err(error) = self
            .start_pty_session(channel, session.handle(), pair, term, env_vars, None)
            .await
        {
            debug_log(format!("failed to spawn shell for {channel:?}: {error:#}"));
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        debug_log("shell_request accepted");
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command_text = String::from_utf8_lossy(data).into_owned();
        debug_log(format!(
            "exec_request received for {channel:?}: {command_text}"
        ));
        let pending_state = {
            let mut guard = self.shell_states.lock().await;
            guard.remove(&channel)
        };
        let start_result = match pending_state {
            Some(SessionChannelState::Pending(pending_state)) => {
                self.start_exec_session(
                    channel,
                    session.handle(),
                    pending_state.env_vars,
                    command_text,
                )
                .await
            }
            Some(SessionChannelState::PtyAllocated {
                pair,
                term,
                env_vars,
            }) => {
                self.start_pty_session(
                    channel,
                    session.handle(),
                    pair,
                    term,
                    env_vars,
                    Some(command_text),
                )
                .await
            }
            _ => Err(anyhow!("channel was not ready for exec request")),
        };
        if let Err(error) = start_result {
            debug_log(format!(
                "failed to start exec request for {channel:?}: {error:#}"
            ));
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let input_sender = {
            let guard = self.shell_states.lock().await;
            match guard.get(&channel) {
                Some(SessionChannelState::RunningPty {
                    input_sender: Some(input_sender),
                    ..
                })
                | Some(SessionChannelState::RunningExec {
                    input_sender: Some(input_sender),
                    ..
                }) => input_sender.clone(),
                _ => return Ok(()),
            }
        };
        if data.is_empty() {
            return Ok(());
        }
        debug_log(format!(
            "forwarding {} bytes into session input",
            data.len()
        ));
        input_sender
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow!("failed to send data to session input writer"))?;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut guard = self.shell_states.lock().await;
        match guard.get_mut(&channel) {
            Some(SessionChannelState::RunningPty { input_sender, .. })
            | Some(SessionChannelState::RunningExec { input_sender, .. }) => {
                debug_log("received SSH channel EOF");
                let _ = input_sender.take();
            }
            _ => {}
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let removed_state = {
            let mut guard = self.shell_states.lock().await;
            guard.remove(&channel)
        };
        match removed_state {
            Some(SessionChannelState::RunningPty { killer, .. }) => {
                debug_log("received SSH channel close");
                if let Ok(mut killer_guard) = killer.lock() {
                    let _ = killer_guard.kill();
                }
            }
            Some(SessionChannelState::RunningExec { child, .. }) => {
                debug_log("received SSH channel close");
                if let Ok(mut child_guard) = child.lock() {
                    let _ = child_guard.kill();
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let size = Self::shell_size(col_width, row_height, pix_width, pix_height);
        let guard = self.shell_states.lock().await;
        match guard.get(&channel) {
            Some(SessionChannelState::PtyAllocated { pair, .. }) => {
                pair.master
                    .resize(size)
                    .context("failed to resize pending PTY")?;
            }
            Some(SessionChannelState::RunningPty { master, .. }) => {
                let master_guard = master
                    .lock()
                    .map_err(|_| anyhow!("failed to lock PTY master"))?;
                master_guard
                    .resize(size)
                    .context("failed to resize running PTY")?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::platform::{ShellFamily, ShellLaunch};

    use super::*;

    use russh::Disconnect;
    use tempfile::tempdir;
    use tokio::io::duplex;

    async fn none_authentication_succeeds<S>(io: S, username: &str) -> bool
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let client_config = Arc::new(client::Config {
            inactivity_timeout: None,
            ..client::Config::default()
        });
        let mut session = client::connect_stream(client_config, io, NoopClientHandler)
            .await
            .unwrap();
        let auth_result = session
            .authenticate_none(username.to_string())
            .await
            .unwrap();
        let success = auth_result.success();
        let _ = session
            .disconnect(
                russh::Disconnect::ByApplication,
                "none authentication check complete",
                "en-US",
            )
            .await;
        success
    }

    async fn collect_interactive_shell_output(
        channel: &mut Channel<client::Msg>,
        shell: &ShellLaunch,
        marker: &str,
    ) -> String {
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        let command = match shell.family() {
            ShellFamily::Posix => format!("printf '{marker}\\n'; exit\n"),
            ShellFamily::PowerShell => format!("Write-Output '{marker}'\r\nexit\r\n"),
        };
        channel.data(command.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        let mut terminal_pending = Vec::new();
        loop {
            let maybe_message = channel.wait().await;
            let Some(message) = maybe_message else {
                break;
            };
            match message {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    let rendered =
                        emulate_terminal_responses(channel, &mut terminal_pending, data.as_ref())
                            .await;
                    response.extend_from_slice(&rendered);
                }
                ChannelMsg::ExitStatus { .. } => break,
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        response.extend_from_slice(&terminal_pending);
        String::from_utf8_lossy(&response).into_owned()
    }

    fn marker_exec_command(shell: &ShellLaunch, marker: &str) -> String {
        match shell.family() {
            ShellFamily::Posix => format!("printf '{marker}\\n'"),
            ShellFamily::PowerShell => format!("Write-Output '{marker}'"),
        }
    }

    fn large_output_exec_command(shell: &ShellLaunch, byte_count: usize) -> String {
        match shell.family() {
            ShellFamily::Posix => format!("head -c {byte_count} /dev/zero | tr '\\0' 'x'"),
            ShellFamily::PowerShell => {
                format!("[Console]::Out.Write(('x' * {byte_count}))")
            }
        }
    }

    async fn collect_exec_output(
        channel: &mut Channel<client::Msg>,
        command: &str,
    ) -> (String, String, u32) {
        channel.exec(true, command).await.unwrap();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        let mut saw_eof = false;
        loop {
            let maybe_message = channel.wait().await;
            let Some(message) = maybe_message else {
                break;
            };
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(data.as_ref()),
                ChannelMsg::ExtendedData {
                    data,
                    ext: SSH_EXTENDED_DATA_STDERR,
                } => {
                    stderr.extend_from_slice(data.as_ref());
                }
                ChannelMsg::Eof => {
                    saw_eof = true;
                    if exit_status.is_some() {
                        break;
                    }
                }
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => {
                    exit_status = Some(status);
                    if saw_eof {
                        break;
                    }
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }

        (
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
            exit_status.unwrap(),
        )
    }

    async fn close_completed_session_channel(channel: &mut Channel<client::Msg>) {
        channel.close().await.unwrap();
        loop {
            let maybe_message = channel.wait().await;
            let Some(message) = maybe_message else {
                break;
            };
            if matches!(message, ChannelMsg::Close) {
                break;
            }
        }
    }

    async fn emulate_terminal_responses(
        channel: &mut Channel<client::Msg>,
        pending: &mut Vec<u8>,
        bytes: &[u8],
    ) -> Vec<u8> {
        const DEVICE_STATUS_REPORT: &[u8] = b"\x1b[6n";
        const CURSOR_POSITION_RESPONSE: &[u8] = b"\x1b[1;1R";

        pending.extend_from_slice(bytes);
        let mut rendered = Vec::new();

        while let Some(index) = find_subslice(pending, DEVICE_STATUS_REPORT) {
            rendered.extend_from_slice(&pending[..index]);
            channel.data(CURSOR_POSITION_RESPONSE).await.unwrap();
            pending.drain(..index + DEVICE_STATUS_REPORT.len());
        }

        let retained_suffix_length = longest_prefix_suffix_match(pending, DEVICE_STATUS_REPORT);
        let rendered_length = pending.len().saturating_sub(retained_suffix_length);
        rendered.extend_from_slice(&pending[..rendered_length]);
        pending.drain(..rendered_length);

        rendered
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn longest_prefix_suffix_match(buffer: &[u8], needle: &[u8]) -> usize {
        for prefix_length in (1..needle.len()).rev() {
            if buffer.ends_with(&needle[..prefix_length]) {
                return prefix_length;
            }
        }
        0
    }

    #[tokio::test]
    async fn negotiates_socks5_domain_connect_request() {
        let (mut client_side, mut server_side) = duplex(1024);
        let server_task = tokio::spawn(async move { negotiate_socks5(&mut server_side).await });

        client_side
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_NONE])
            .await
            .unwrap();
        let mut method_response = [0_u8; 2];
        client_side.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [SOCKS_VERSION, SOCKS_AUTH_NONE]);

        client_side
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_CMD_CONNECT,
                0,
                SOCKS_ATYP_DOMAIN_NAME,
                11,
                b'e',
                b'x',
                b'a',
                b'm',
                b'p',
                b'l',
                b'e',
                b'.',
                b'c',
                b'o',
                b'm',
                0x04,
                0x38,
            ])
            .await
            .unwrap();

        let target = server_task.await.unwrap().unwrap();
        assert_eq!(
            target,
            SocksConnectTarget {
                host: "example.com".to_string(),
                port: 1080,
            }
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_socks5_command() {
        let (mut client_side, mut server_side) = duplex(1024);
        let server_task = tokio::spawn(async move { negotiate_socks5(&mut server_side).await });

        client_side
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_NONE])
            .await
            .unwrap();
        let mut method_response = [0_u8; 2];
        client_side.read_exact(&mut method_response).await.unwrap();
        assert_eq!(method_response, [SOCKS_VERSION, SOCKS_AUTH_NONE]);

        client_side
            .write_all(&[
                SOCKS_VERSION,
                0x02,
                0,
                SOCKS_ATYP_IPV4,
                127,
                0,
                0,
                1,
                0x1f,
                0x90,
            ])
            .await
            .unwrap();

        let mut failure_response = [0_u8; 10];
        client_side.read_exact(&mut failure_response).await.unwrap();
        assert_eq!(
            failure_response,
            [
                SOCKS_VERSION,
                SOCKS_REPLY_COMMAND_NOT_SUPPORTED,
                0,
                SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );

        let error = server_task.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("unsupported SOCKS command"));
    }

    #[tokio::test]
    async fn forwards_direct_tcpip_channels_to_client_network() {
        let temp_dir = tempdir().unwrap();
        let allowed_private_key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let allowed_public_key = allowed_private_key.public_key().clone();
        let (client_io, server_io) = duplex(64 * 1024);
        let shell = ShellLaunch::detect_for_current_platform().unwrap();

        let server_task = tokio::spawn(run_remote_shell_server(
            server_io,
            "support-user".to_string(),
            allowed_public_key,
            temp_dir.path().to_path_buf(),
            shell,
        ));

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            socket.write_all(&request).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let client_config = Arc::new(client::Config {
            inactivity_timeout: None,
            ..client::Config::default()
        });
        let mut session = client::connect_stream(client_config, client_io, NoopClientHandler)
            .await
            .unwrap();
        let negotiated_hash = session.best_supported_rsa_hash().await.unwrap().flatten();
        let auth_result = session
            .authenticate_publickey(
                "support-user".to_string(),
                PrivateKeyWithHashAlg::new(Arc::new(allowed_private_key), negotiated_hash),
            )
            .await
            .unwrap();
        assert!(auth_result.success());

        let mut channel = session
            .channel_open_direct_tcpip("127.0.0.1", u32::from(echo_addr.port()), "127.0.0.1", 43123)
            .await
            .unwrap();
        channel.data(&b"ping through tunnel"[..]).await.unwrap();
        channel.eof().await.unwrap();

        let mut response = Vec::new();
        loop {
            let maybe_message = channel.wait().await;
            let Some(message) = maybe_message else {
                break;
            };
            match message {
                ChannelMsg::Data { data } => response.extend_from_slice(data.as_ref()),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }

        assert_eq!(response, b"ping through tunnel");

        session
            .disconnect(Disconnect::ByApplication, "test complete", "en-US")
            .await
            .unwrap();
        echo_task.await.unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn executes_noninteractive_commands_over_authenticated_transport() {
        let temp_dir = tempdir().unwrap();
        let allowed_private_key = Arc::new(
            PrivateKey::random(
                &mut russh::keys::ssh_key::rand_core::OsRng,
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let allowed_public_key = allowed_private_key.public_key().clone();
        let (client_io, server_io) = duplex(64 * 1024);
        let shell = ShellLaunch::detect_for_current_platform().unwrap();

        let server_task = tokio::spawn(run_remote_shell_server(
            server_io,
            "support-user".to_string(),
            allowed_public_key,
            temp_dir.path().to_path_buf(),
            shell.clone(),
        ));

        let session =
            connect_authenticated_client_transport(client_io, "support-user", allowed_private_key)
                .await
                .unwrap();
        let mut channel = session.channel_open_session().await.unwrap();
        let command = marker_exec_command(&shell, "direct-exec");
        let (stdout, stderr, exit_status) = collect_exec_output(&mut channel, &command).await;

        assert_eq!(stderr, "");
        assert_eq!(exit_status, 0);
        assert!(stdout.contains("direct-exec"));

        session
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
            .await
            .unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn transfers_large_exec_output_through_bounded_channels() {
        let temp_dir = tempdir().unwrap();
        let allowed_private_key = Arc::new(
            PrivateKey::random(
                &mut russh::keys::ssh_key::rand_core::OsRng,
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let allowed_public_key = allowed_private_key.public_key().clone();
        let (client_io, server_io) = duplex(64 * 1024);
        let shell = ShellLaunch::detect_for_current_platform().unwrap();

        let server_task = tokio::spawn(run_remote_shell_server(
            server_io,
            "support-user".to_string(),
            allowed_public_key,
            temp_dir.path().to_path_buf(),
            shell.clone(),
        ));

        let session =
            connect_authenticated_client_transport(client_io, "support-user", allowed_private_key)
                .await
                .unwrap();
        let mut channel = session.channel_open_session().await.unwrap();
        let command = large_output_exec_command(&shell, 200_000);
        let (stdout, stderr, exit_status) = collect_exec_output(&mut channel, &command).await;

        assert_eq!(stderr, "");
        assert_eq!(exit_status, 0);
        assert_eq!(stdout.len(), 200_000);
        assert!(stdout.chars().all(|character| character == 'x'));

        session
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
            .await
            .unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn reuses_authenticated_transport_for_multiple_shell_sessions() {
        let temp_dir = tempdir().unwrap();
        let allowed_private_key = Arc::new(
            PrivateKey::random(
                &mut russh::keys::ssh_key::rand_core::OsRng,
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let allowed_public_key = allowed_private_key.public_key().clone();
        let (client_io, server_io) = duplex(64 * 1024);
        let shell = ShellLaunch::detect_for_current_platform().unwrap();

        let server_task = tokio::spawn(run_remote_shell_server(
            server_io,
            "support-user".to_string(),
            allowed_public_key,
            temp_dir.path().to_path_buf(),
            shell.clone(),
        ));

        let session =
            connect_authenticated_client_transport(client_io, "support-user", allowed_private_key)
                .await
                .unwrap();

        let mut first_channel = session.channel_open_session().await.unwrap();
        let first_output =
            collect_interactive_shell_output(&mut first_channel, &shell, "first-session").await;
        assert!(first_output.contains("first-session"));
        close_completed_session_channel(&mut first_channel).await;

        let mut second_channel = session.channel_open_session().await.unwrap();
        let second_output =
            collect_interactive_shell_output(&mut second_channel, &shell, "second-session").await;
        assert!(second_output.contains("second-session"));
        close_completed_session_channel(&mut second_channel).await;

        session
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
            .await
            .unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn local_ssh_proxy_accepts_repeated_sessions_over_one_client_transport() {
        let temp_dir = tempdir().unwrap();
        let allowed_private_key = Arc::new(
            PrivateKey::random(
                &mut russh::keys::ssh_key::rand_core::OsRng,
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let allowed_public_key = allowed_private_key.public_key().clone();
        let (client_io, server_io) = duplex(64 * 1024);
        let shell = ShellLaunch::detect_for_current_platform().unwrap();

        let server_task = tokio::spawn(run_remote_shell_server(
            server_io,
            "support-user".to_string(),
            allowed_public_key.clone(),
            temp_dir.path().to_path_buf(),
            shell.clone(),
        ));

        let upstream_session = Arc::new(AsyncMutex::new(
            connect_authenticated_client_transport(
                client_io,
                "support-user",
                Arc::clone(&allowed_private_key),
            )
            .await
            .unwrap(),
        ));
        let proxy_listener = start_ssh_proxy_listener(
            Arc::clone(&upstream_session),
            "127.0.0.1:0".parse().unwrap(),
            "support-user".to_string(),
            allowed_public_key,
        )
        .await
        .unwrap();

        let none_auth_stream = TcpStream::connect(proxy_listener.local_addr())
            .await
            .unwrap();
        assert!(
            !none_authentication_succeeds(none_auth_stream, "support-user").await,
            "local SSH proxy accepted none authentication"
        );

        let first_proxy_stream = TcpStream::connect(proxy_listener.local_addr())
            .await
            .unwrap();
        let first_local_client = connect_authenticated_client_transport(
            first_proxy_stream,
            "support-user",
            Arc::clone(&allowed_private_key),
        )
        .await
        .unwrap();
        let mut first_channel = first_local_client.channel_open_session().await.unwrap();
        let first_output =
            collect_interactive_shell_output(&mut first_channel, &shell, "proxy-first").await;
        assert!(first_output.contains("proxy-first"));
        first_local_client
            .disconnect(
                russh::Disconnect::ByApplication,
                "first proxy session complete",
                "en-US",
            )
            .await
            .unwrap();

        let second_proxy_stream = TcpStream::connect(proxy_listener.local_addr())
            .await
            .unwrap();
        let second_local_client = connect_authenticated_client_transport(
            second_proxy_stream,
            "support-user",
            Arc::clone(&allowed_private_key),
        )
        .await
        .unwrap();
        let mut second_channel = second_local_client.channel_open_session().await.unwrap();
        let second_output =
            collect_interactive_shell_output(&mut second_channel, &shell, "proxy-second").await;
        assert!(second_output.contains("proxy-second"));
        second_local_client
            .disconnect(
                russh::Disconnect::ByApplication,
                "second proxy session complete",
                "en-US",
            )
            .await
            .unwrap();

        drop(proxy_listener);
        {
            let session_guard = upstream_session.lock().await;
            session_guard
                .disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
                .await
                .unwrap();
        }
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn local_ssh_proxy_executes_noninteractive_commands() {
        let temp_dir = tempdir().unwrap();
        let allowed_private_key = Arc::new(
            PrivateKey::random(
                &mut russh::keys::ssh_key::rand_core::OsRng,
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let allowed_public_key = allowed_private_key.public_key().clone();
        let (client_io, server_io) = duplex(64 * 1024);
        let shell = ShellLaunch::detect_for_current_platform().unwrap();

        let server_task = tokio::spawn(run_remote_shell_server(
            server_io,
            "support-user".to_string(),
            allowed_public_key.clone(),
            temp_dir.path().to_path_buf(),
            shell.clone(),
        ));

        let upstream_session = Arc::new(AsyncMutex::new(
            connect_authenticated_client_transport(
                client_io,
                "support-user",
                Arc::clone(&allowed_private_key),
            )
            .await
            .unwrap(),
        ));
        let proxy_listener = start_ssh_proxy_listener(
            Arc::clone(&upstream_session),
            "127.0.0.1:0".parse().unwrap(),
            "support-user".to_string(),
            allowed_public_key,
        )
        .await
        .unwrap();

        let proxy_stream = TcpStream::connect(proxy_listener.local_addr())
            .await
            .unwrap();
        let local_client = connect_authenticated_client_transport(
            proxy_stream,
            "support-user",
            Arc::clone(&allowed_private_key),
        )
        .await
        .unwrap();
        let mut channel = local_client.channel_open_session().await.unwrap();
        let command = marker_exec_command(&shell, "proxy-exec");
        let (stdout, stderr, exit_status) = collect_exec_output(&mut channel, &command).await;

        assert_eq!(stderr, "");
        assert_eq!(exit_status, 0);
        assert!(stdout.contains("proxy-exec"));

        local_client
            .disconnect(
                russh::Disconnect::ByApplication,
                "proxy exec complete",
                "en-US",
            )
            .await
            .unwrap();

        drop(proxy_listener);
        {
            let session_guard = upstream_session.lock().await;
            session_guard
                .disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
                .await
                .unwrap();
        }
        server_task.await.unwrap().unwrap();
    }
}
