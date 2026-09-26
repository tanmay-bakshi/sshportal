use std::sync::Arc;
use std::time::Duration;

use russh::keys::{PrivateKey, ssh_key};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::task::AbortOnDropHandle;

use super::{
    DynamicForwardListener, MAX_DYNAMIC_FORWARD_CONNECTIONS, NoopClientHandler,
    SOCKS_NEGOTIATION_TIMEOUT, start_dynamic_forward_listener,
};
use crate::platform::ShellLaunch;
use crate::shell::client::connect_authenticated_client_transport;
use crate::shell::remote::run_remote_shell_server;

struct Harness {
    listener: DynamicForwardListener,
    session: Arc<Mutex<russh::client::Handle<NoopClientHandler>>>,
    _server: AbortOnDropHandle<anyhow::Result<()>>,
    _home: TempDir,
}

impl Harness {
    async fn start() -> Self {
        let home = tempdir().unwrap();
        let key =
            Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let (client_io, server_io) = duplex(64 * 1024);
        let server = AbortOnDropHandle::new(tokio::spawn(run_remote_shell_server(
            server_io,
            "support-user".to_string(),
            key.public_key().clone(),
            home.path().to_path_buf(),
            ShellLaunch::detect_for_current_platform().unwrap(),
        )));
        let session = Arc::new(Mutex::new(
            connect_authenticated_client_transport(client_io, "support-user", key)
                .await
                .unwrap(),
        ));
        let listener =
            start_dynamic_forward_listener(Arc::clone(&session), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
        Self {
            listener,
            session,
            _server: server,
            _home: home,
        }
    }

    async fn negotiate_method(&self) -> TcpStream {
        let mut socket = TcpStream::connect(self.listener.local_addr())
            .await
            .unwrap();
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        socket
    }
}

#[tokio::test]
async fn dropping_listener_closes_incomplete_negotiations_and_releases_session() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let harness = Harness::start().await;
        let mut socket = harness.negotiate_method().await;
        drop(harness.listener);

        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        while Arc::strong_count(&harness.session) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("accepted SOCKS connection outlived its listener");
}

#[tokio::test]
async fn connection_admission_resumes_after_an_accepted_socket_closes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let harness = Harness::start().await;
        let mut sockets = Vec::new();
        for _ in 0..MAX_DYNAMIC_FORWARD_CONNECTIONS {
            sockets.push(harness.negotiate_method().await);
        }
        let mut waiting = TcpStream::connect(harness.listener.local_addr())
            .await
            .unwrap();
        waiting.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), waiting.read_exact(&mut reply))
                .await
                .is_err()
        );

        drop(sockets.pop());
        waiting.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
    })
    .await
    .expect("SOCKS admission did not recover after a connection closed");
}

#[tokio::test]
async fn incomplete_negotiation_expires_without_closing_the_listener() {
    tokio::time::timeout(SOCKS_NEGOTIATION_TIMEOUT + Duration::from_secs(5), async {
        let harness = Harness::start().await;
        let mut socket = harness.negotiate_method().await;
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        let _next_connection = harness.negotiate_method().await;
    })
    .await
    .expect("incomplete SOCKS negotiation was not reclaimed");
}
