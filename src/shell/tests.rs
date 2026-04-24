use std::sync::Arc;
use std::time::Duration;

use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, ssh_key};
use russh::{Channel, ChannelMsg};
use russh::{Disconnect, client};
use tempfile::tempdir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio_tungstenite::accept_async;

use crate::platform::{ShellFamily, ShellLaunch};
use crate::websocket_to_io;

use super::client::connect_authenticated_client_transport;
use super::common::{NoopClientHandler, SSH_EXTENDED_DATA_STDERR};
use super::local_proxy::start_ssh_proxy_listener;
use super::remote::run_remote_shell_server;
use super::socks::{
    SOCKS_ATYP_DOMAIN_NAME, SOCKS_ATYP_IPV4, SOCKS_AUTH_NONE, SOCKS_CMD_CONNECT,
    SOCKS_REPLY_COMMAND_NOT_SUPPORTED, SOCKS_REPLY_SUCCESS, SOCKS_VERSION, SocksConnectTarget,
    negotiate_socks5, start_dynamic_forward_listener,
};

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
                    emulate_terminal_responses(channel, &mut terminal_pending, data.as_ref()).await;
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
async fn runs_authenticated_transport_over_websocket_io() {
    let temp_dir = tempdir().unwrap();
    let allowed_private_key = Arc::new(
        PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap(),
    );
    let allowed_public_key = allowed_private_key.public_key().clone();
    let shell = ShellLaunch::detect_for_current_platform().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let websocket = accept_async(socket).await.unwrap();
        run_remote_shell_server(
            websocket_to_io(websocket),
            "support-user".to_string(),
            allowed_public_key,
            temp_dir.path().to_path_buf(),
            shell,
        )
        .await
    });

    let (websocket, _) = tokio_tungstenite::connect_async(format!("ws://{listener_addr}"))
        .await
        .unwrap();
    let session = tokio::time::timeout(
        Duration::from_secs(5),
        connect_authenticated_client_transport(
            websocket_to_io(websocket),
            "support-user",
            Arc::clone(&allowed_private_key),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let shell = ShellLaunch::detect_for_current_platform().unwrap();
    let mut channel = session.channel_open_session().await.unwrap();
    let command = marker_exec_command(&shell, "websocket-exec");
    let (stdout, stderr, exit_status) = collect_exec_output(&mut channel, &command).await;

    assert_eq!(stderr, "");
    assert_eq!(exit_status, 0);
    assert!(stdout.contains("websocket-exec"));

    session
        .disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
        .await
        .unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dynamic_forward_listener_routes_socks_connections_through_client_network() {
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
        shell,
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
    let dynamic_forward_listener = start_dynamic_forward_listener(
        Arc::clone(&upstream_session),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut socket, _) = echo_listener.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        socket.write_all(&request).await.unwrap();
        socket.shutdown().await.unwrap();
    });

    let mut socks_stream = TcpStream::connect(dynamic_forward_listener.local_addr())
        .await
        .unwrap();
    socks_stream
        .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_NONE])
        .await
        .unwrap();
    let mut method_response = [0_u8; 2];
    socks_stream.read_exact(&mut method_response).await.unwrap();
    assert_eq!(method_response, [SOCKS_VERSION, SOCKS_AUTH_NONE]);

    let port_bytes = echo_addr.port().to_be_bytes();
    socks_stream
        .write_all(&[
            SOCKS_VERSION,
            SOCKS_CMD_CONNECT,
            0,
            SOCKS_ATYP_DOMAIN_NAME,
            9,
            b'l',
            b'o',
            b'c',
            b'a',
            b'l',
            b'h',
            b'o',
            b's',
            b't',
            port_bytes[0],
            port_bytes[1],
        ])
        .await
        .unwrap();

    let mut connect_response = [0_u8; 10];
    socks_stream
        .read_exact(&mut connect_response)
        .await
        .unwrap();
    assert_eq!(connect_response[0], SOCKS_VERSION);
    assert_eq!(connect_response[1], SOCKS_REPLY_SUCCESS);

    socks_stream
        .write_all(b"hello through socks")
        .await
        .unwrap();
    socks_stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    socks_stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"hello through socks");

    drop(dynamic_forward_listener);
    {
        let session_guard = upstream_session.lock().await;
        session_guard
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
            .await
            .unwrap();
    }
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
