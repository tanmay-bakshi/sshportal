use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::client;
use russh::keys::{PrivateKey, PublicKey, ssh_key};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use super::common::{NoopClientHandler, debug_log, same_public_key};

pub(super) struct SshProxyListener {
    listen_addr: SocketAddr,
    task: JoinHandle<()>,
}
impl SshProxyListener {
    pub(super) fn local_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

impl Drop for SshProxyListener {
    fn drop(&mut self) {
        self.task.abort();
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

pub(super) async fn start_ssh_proxy_listener(
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
                allow_unauthenticated: remote_addr.ip().is_loopback(),
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

struct ProxiedSessionChannel {
    upstream_writer: Arc<ChannelWriteHalf<client::Msg>>,
}

struct LocalSshProxyHandler {
    allowed_username: String,
    allow_unauthenticated: bool,
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
        if self.allow_unauthenticated && username == self.allowed_username {
            debug_log(format!("accepted local SSH proxy none auth for {username}"));
            return Ok(Auth::Accept);
        }
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
