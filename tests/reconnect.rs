use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

const DEADLINE: Duration = Duration::from_secs(30);

struct Process {
    child: Child,
    output: Arc<Mutex<String>>,
    changed: Arc<Notify>,
    _readers: [AbortOnDropHandle<()>; 2],
}

impl Process {
    fn spawn(binary: &str, args: &[&str]) -> Self {
        let mut child = Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let output = Arc::new(Mutex::new(String::new()));
        let changed = Arc::new(Notify::new());
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let read = |stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>| {
            let output = Arc::clone(&output);
            let changed = Arc::clone(&changed);
            AbortOnDropHandle::new(tokio::spawn(async move {
                let mut lines = BufReader::new(stream).lines();
                while let Some(line) = lines.next_line().await.unwrap() {
                    let mut output = output.lock().unwrap();
                    output.push_str(&line);
                    output.push('\n');
                    drop(output);
                    changed.notify_waiters();
                }
            }))
        };
        Self {
            child,
            _readers: [read(Box::new(stdout)), read(Box::new(stderr))],
            output,
            changed,
        }
    }

    async fn wait_for(&self, text: &str, count: usize) -> String {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let notification = self.changed.notified();
                let output = self.output.lock().unwrap().clone();
                if output.matches(text).count() >= count {
                    return output;
                }
                notification.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing {text:?}: {}", self.output.lock().unwrap()))
    }

    async fn exit(&mut self) -> std::process::ExitStatus {
        tokio::time::timeout(DEADLINE, self.child.wait())
            .await
            .unwrap()
            .unwrap()
    }
}

struct FaultProxy {
    address: SocketAddr,
    forwarding: Arc<std::sync::atomic::AtomicBool>,
    connections: Arc<Mutex<Vec<CancellationToken>>>,
    _task: AbortOnDropHandle<()>,
}

impl FaultProxy {
    async fn start(destination: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let forwarding = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let enabled = Arc::clone(&forwarding);
        let connections = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::clone(&connections);
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                let (mut client, _) = tokio::select! {
                    accepted = listener.accept() => accepted.unwrap(),
                    _ = tasks.join_next(), if !tasks.is_empty() => continue,
                };
                if !enabled.load(std::sync::atomic::Ordering::SeqCst) {
                    drop(client);
                    continue;
                }
                let cancellation = CancellationToken::new();
                active.lock().unwrap().push(cancellation.clone());
                tasks.spawn(async move {
                    let mut server = TcpStream::connect(destination).await.unwrap();
                    tokio::select! {
                        _ = cancellation.cancelled() => {}
                        _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                    }
                });
            }
        }));
        Self {
            address,
            forwarding,
            connections,
            _task: task,
        }
    }

    fn disconnect(&self) {
        self.forwarding
            .store(false, std::sync::atomic::Ordering::SeqCst);
        for connection in self.connections.lock().unwrap().drain(..) {
            connection.cancel();
        }
    }

    fn restore(&self) {
        self.forwarding
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn printed_address(output: &str, prefix: &str) -> SocketAddr {
    output
        .lines()
        .rev()
        .find_map(|line| {
            line.strip_prefix(prefix)
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(|address| address.parse().ok())
        })
        .unwrap_or_else(|| panic!("missing address {prefix:?}: {output}"))
}

async fn socks_echo(proxy: SocketAddr, destination: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend_from_slice(&destination.port().to_be_bytes());
        stream.write_all(&connect).await.unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        stream.write_all(b"recovered-egress").await.unwrap();
        let mut echoed = [0; 16];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"recovered-egress");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn real_processes_recover_transport_loss_and_reject_a_different_client() {
    tokio::time::timeout(DEADLINE, async {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let _echo_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (mut stream, _) = tokio::select! {
                    accepted = echo.accept() => accepted.unwrap(),
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                };
                connections.spawn(async move {
                    let mut data = [0; 128];
                    loop {
                        let size = stream.read(&mut data).await.unwrap();
                        if size == 0 {
                            return;
                        }
                        stream.write_all(&data[..size]).await.unwrap();
                    }
                });
            }
        }));
        let mut server = Process::spawn(
            env!("CARGO_BIN_EXE_sshportal-server"),
            &[
                "--listen",
                "127.0.0.1:0",
                "--socks-only",
                "127.0.0.1:0",
                "--join-token",
                "recovery-test",
                "--reconnect",
                "--reconnect-interval-seconds",
                "1",
                "--reconnect-timeout-seconds",
                "6",
            ],
        );
        let output = server
            .wait_for("sshportal server listening on http://", 1)
            .await;
        let server_address = printed_address(&output, "sshportal server listening on http://");
        let proxy = FaultProxy::start(server_address).await;
        let url = format!("ws://{}/connect?token=recovery-test", proxy.address);
        let mut client = Process::spawn(
            env!("CARGO_BIN_EXE_sshportal-client"),
            &[
                "--server",
                &url,
                "--approve-session",
                "--reconnect",
                "--reconnect-interval-seconds",
                "1",
                "--reconnect-timeout-seconds",
                "6",
            ],
        );
        client.wait_for("connection attempt failed", 1).await;
        proxy.restore();
        let output = server.wait_for("SOCKS5 proxy listening on", 1).await;
        let socks_address = printed_address(&output, "SOCKS5 proxy listening on ");
        socks_echo(socks_address, echo_address).await;

        proxy.disconnect();
        server
            .wait_for("for the approved client to reconnect", 1)
            .await;
        let direct = format!("ws://{server_address}/connect?token=recovery-test");
        let mut other = Process::spawn(
            env!("CARGO_BIN_EXE_sshportal-client"),
            &["--server", &direct, "--approve-session", "--reconnect"],
        );
        assert!(!other.exit().await.success());
        other
            .wait_for("resume credentials do not identify the approved client", 1)
            .await;
        proxy.restore();
        let output = server.wait_for("SOCKS5 proxy listening on", 2).await;
        assert_eq!(
            printed_address(&output, "SOCKS5 proxy listening on "),
            socks_address
        );
        socks_echo(socks_address, echo_address).await;
        assert!(client.child.try_wait().unwrap().is_none());
        assert!(server.child.try_wait().unwrap().is_none());

        proxy.disconnect();
        assert!(!client.exit().await.success());
        assert!(!server.exit().await.success());
        client.wait_for("reconnection window expired", 1).await;
        server.wait_for("recovery window expired", 1).await;
    })
    .await
    .expect("reconnection processes did not complete within their bounds");
}

#[cfg(unix)]
#[tokio::test]
async fn ssh_recovery_preserves_listener_ports_and_host_key() {
    use russh::client;
    use russh::keys::PublicKey;

    struct HostKey(Arc<Mutex<Option<PublicKey>>>);

    impl client::Handler for HostKey {
        type Error = russh::Error;

        async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
            *self.0.lock().unwrap() = Some(key.clone());
            Ok(true)
        }
    }

    async fn execute(address: SocketAddr) -> (PublicKey, client::Handle<HostKey>) {
        let key = Arc::new(Mutex::new(None));
        let mut ssh = client::connect(
            Arc::new(client::Config::default()),
            address,
            HostKey(Arc::clone(&key)),
        )
        .await
        .unwrap();
        assert!(
            ssh.authenticate_none(whoami::username())
                .await
                .unwrap()
                .success()
        );
        let mut channel = ssh.channel_open_session().await.unwrap();
        channel.exec(true, "printf recovered-shell").await.unwrap();
        let mut output = Vec::new();
        let mut status = None;
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => output.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(output, b"recovered-shell");
        assert_eq!(status, Some(0));
        let key = key.lock().unwrap().clone().unwrap();
        (key, ssh)
    }

    tokio::time::timeout(DEADLINE, async {
        let server = Process::spawn(
            env!("CARGO_BIN_EXE_sshportal-server"),
            &[
                "--listen",
                "127.0.0.1:0",
                "--dynamic-forward",
                "127.0.0.1:0",
                "--join-token",
                "ssh-recovery-test",
                "--reconnect",
                "--reconnect-interval-seconds",
                "1",
                "--reconnect-timeout-seconds",
                "6",
            ],
        );
        let output = server
            .wait_for("sshportal server listening on http://", 1)
            .await;
        let address = printed_address(&output, "sshportal server listening on http://");
        let proxy = FaultProxy::start(address).await;
        proxy.restore();
        let url = format!("ws://{}/connect?token=ssh-recovery-test", proxy.address);
        let mut client = Process::spawn(
            env!("CARGO_BIN_EXE_sshportal-client"),
            &[
                "--server",
                &url,
                "--approve-session",
                "--reconnect",
                "--reconnect-interval-seconds",
                "1",
                "--reconnect-timeout-seconds",
                "6",
            ],
        );
        let output = server.wait_for("SOCKS5 proxy listening on ", 1).await;
        let ssh = printed_address(&output, "SSH proxy listening on ");
        let socks = printed_address(&output, "SOCKS5 proxy listening on ");
        let (host_key, old_local_transport) = execute(ssh).await;
        proxy.disconnect();
        server
            .wait_for("for the approved client to reconnect", 1)
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), old_local_transport)
            .await
            .expect("old local SSH transport survived epoch teardown");
        proxy.restore();
        let output = tokio::select! {
            output = server.wait_for("SOCKS5 proxy listening on ", 2) => output,
            status = client.child.wait() => panic!("SSH client exited during recovery: {status:?}: {}", client.output.lock().unwrap()),
        };
        assert_eq!(printed_address(&output, "SSH proxy listening on "), ssh);
        assert_eq!(
            printed_address(&output, "SOCKS5 proxy listening on "),
            socks
        );
        let (recovered_key, recovered_transport) = execute(ssh).await;
        assert_eq!(recovered_key, host_key);
        recovered_transport.disconnect(russh::Disconnect::ByApplication, "test complete", "en-US")
            .await.unwrap();
    })
    .await
    .expect("SSH recovery did not restore command access");
}

#[cfg(unix)]
#[tokio::test]
async fn termination_interrupts_connection_retries_and_rendezvous_waits() {
    let mut server = Process::spawn(
        env!("CARGO_BIN_EXE_sshportal-server"),
        &[
            "--listen",
            "127.0.0.1:0",
            "--socks-only",
            "127.0.0.1:0",
            "--reconnect",
        ],
    );
    let output = server
        .wait_for("sshportal server listening on http://", 1)
        .await;
    let address = printed_address(&output, "sshportal server listening on http://");
    let proxy = FaultProxy::start(address).await;
    let url = format!("ws://{}/connect?token=unused", proxy.address);
    let mut client = Process::spawn(
        env!("CARGO_BIN_EXE_sshportal-client"),
        &["--server", &url, "--reconnect", "--approve-session"],
    );
    client.wait_for("waiting before reconnecting", 1).await;
    for process in [&mut client, &mut server] {
        assert!(
            Command::new("/bin/kill")
                .arg("-TERM")
                .arg(process.child.id().unwrap().to_string())
                .status()
                .await
                .unwrap()
                .success()
        );
        let status = tokio::time::timeout(Duration::from_secs(2), process.child.wait())
            .await
            .expect("termination did not interrupt the recovery wait")
            .unwrap();
        assert!(status.success());
    }
}
