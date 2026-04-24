use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use russh::client;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;

use super::common::{NoopClientHandler, debug_log, debug_public_key};
use super::local_proxy::start_ssh_proxy_listener;
use super::socks::start_dynamic_forward_listener;

pub(super) async fn connect_authenticated_client_transport<S>(
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
