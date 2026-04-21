#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_tungstenite::{is_upgrade_request, upgrade};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, RwLock, oneshot};
use tokio_tungstenite::WebSocketStream;
use url::form_urlencoded;

use sshportal::{
    ClientDecision, ClientHello, ControlPacket, DEFAULT_CONNECT_PATH, DEFAULT_HEALTH_PATH,
    OperatorKeyMaterial, PROTOCOL_VERSION, ServerOffer, load_operator_key, recv_packet,
    run_client_session_proxy, send_packet, validate_protocol_version, websocket_to_io,
};

use russh::keys::ssh_key::rand_core::{OsRng, RngCore};

#[derive(Parser, Debug)]
#[command(
    name = "sshportal-server",
    about = "Accept one consent-gated support client and expose it as a local SSH proxy.",
    long_about = "Run the server side of an sshportal support session. The server prints a one-time join token, accepts the first client that proves possession of it, and exposes the approved session through a local SSH listener.",
    after_help = "Examples:\n  sshportal-server --listen 0.0.0.0:8080 --ssh-listen 127.0.0.1:2222\n  sshportal-server --operator-key ./operator_ed25519 --persist-operator-key"
)]
struct ServerCli {
    /// HTTP address for the one-time rendezvous endpoint.
    #[arg(long, default_value = "0.0.0.0:8080", value_name = "ADDR")]
    listen: SocketAddr,
    /// Operator identity shown to the client user during consent.
    #[arg(long, default_value = "support-operator")]
    operator_name: String,
    /// Explicit join token to require from the client.
    ///
    /// If omitted, the server generates a fresh random token for this run.
    #[arg(long, value_name = "TOKEN")]
    join_token: Option<String>,
    /// Seconds to wait for the client to finish the handshake before releasing the slot.
    #[arg(long, default_value_t = 30, value_name = "SECONDS")]
    handshake_timeout_seconds: u64,
    /// Existing private key to use for authenticating support sessions.
    #[arg(long, value_name = "PATH")]
    operator_key: Option<PathBuf>,
    /// Request separate client approval to install the operator key persistently on POSIX clients.
    #[arg(long)]
    persist_operator_key: bool,
    /// Local SSH proxy listener that the operator connects to after approval.
    #[arg(long, default_value = "127.0.0.1:0", value_name = "LISTEN_ADDR")]
    ssh_listen: SocketAddr,
    /// Optional local SOCKS5 listener to expose for the lifetime of the session.
    #[arg(long, value_name = "LISTEN_ADDR")]
    dynamic_forward: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
struct SessionSummary {
    phase: &'static str,
    detail: &'static str,
}

impl Default for SessionSummary {
    fn default() -> Self {
        Self::waiting()
    }
}

impl SessionSummary {
    fn waiting() -> Self {
        Self {
            phase: "waiting",
            detail: "listening for a single support client",
        }
    }

    fn negotiating() -> Self {
        Self {
            phase: "negotiating",
            detail: "client connected; awaiting handshake completion",
        }
    }

    fn connected() -> Self {
        Self {
            phase: "connected",
            detail: "support session established",
        }
    }

    fn finished() -> Self {
        Self {
            phase: "finished",
            detail: "support session completed",
        }
    }

    fn failed() -> Self {
        Self {
            phase: "failed",
            detail: "support session failed",
        }
    }
}

struct AppState {
    session_claimed: AtomicBool,
    shutdown_notify: Notify,
    status: RwLock<SessionSummary>,
    session_sender: Mutex<Option<oneshot::Sender<EstablishedSession>>>,
    operator_name: String,
    join_token: String,
    handshake_timeout: Duration,
    operator_key: OperatorKeyMaterial,
    ssh_listen: SocketAddr,
    dynamic_forward: Option<SocketAddr>,
}

struct EstablishedSession {
    websocket: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    client_hello: ClientHello,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ServerCli::parse();
    let join_token = resolve_join_token(cli.join_token)?;
    let operator_key = load_operator_key(cli.operator_key.as_deref(), cli.persist_operator_key)?;

    let listener = TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("failed to bind HTTP server to {}", cli.listen))?;
    let (session_sender, session_receiver) = oneshot::channel();
    let state = Arc::new(AppState {
        session_claimed: AtomicBool::new(false),
        shutdown_notify: Notify::new(),
        status: RwLock::new(SessionSummary::default()),
        session_sender: Mutex::new(Some(session_sender)),
        operator_name: cli.operator_name.clone(),
        join_token: join_token.clone(),
        handshake_timeout: Duration::from_secs(cli.handshake_timeout_seconds),
        operator_key,
        ssh_listen: cli.ssh_listen,
        dynamic_forward: cli.dynamic_forward,
    });

    println!("sshportal server listening on http://{}", cli.listen);
    println!("status endpoint: http://{}", cli.listen);
    println!(
        "support websocket endpoint: ws://{}{}?token={}",
        cli.listen, DEFAULT_CONNECT_PATH, join_token
    );
    println!(
        "handshake timeout: {}",
        format_duration(Duration::from_secs(cli.handshake_timeout_seconds))
    );
    println!("local SSH proxy requested on {}", cli.ssh_listen);
    if let Some(listen_addr) = cli.dynamic_forward {
        println!("dynamic SOCKS5 proxy requested on {listen_addr}");
    }

    let http_task = tokio::spawn(run_http_server(listener, Arc::clone(&state)));
    let established_session = session_receiver
        .await
        .context("server shut down before any client session started")?;
    http_task
        .await
        .context("HTTP server task failed to join")??;
    {
        let mut status = state.status.write().await;
        *status = SessionSummary::connected();
    }
    let transport = websocket_to_io(established_session.websocket);
    let session_result = run_client_session_proxy(
        transport,
        &established_session.client_hello.metadata.username,
        Arc::clone(state.operator_key.private_key()),
        state.ssh_listen,
        state.dynamic_forward,
    )
    .await;
    {
        let mut status = state.status.write().await;
        match &session_result {
            Ok(()) => *status = SessionSummary::finished(),
            Err(_error) => *status = SessionSummary::failed(),
        }
    }
    session_result?;
    Ok(())
}

async fn run_http_server(listener: TcpListener, state: Arc<AppState>) -> Result<()> {
    let builder = http1::Builder::new();
    loop {
        tokio::select! {
            _ = state.shutdown_notify.notified() => {
                break;
            }
            accept_result = listener.accept() => {
                let (stream, _) = accept_result.context("failed to accept HTTP connection")?;
                stream
                    .set_nodelay(true)
                    .context("failed to enable TCP_NODELAY on the accepted HTTP socket")?;
                let state_for_connection = Arc::clone(&state);
                let connection_builder = builder.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| handle_request(request, Arc::clone(&state_for_connection)));
                    let connection = connection_builder
                        .serve_connection(TokioIo::new(stream), service)
                        .with_upgrades();
                    if let Err(error) = connection.await {
                        eprintln!("HTTP connection error: {error}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_request(
    mut request: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/") => status_response(&state).await,
        (&Method::GET, DEFAULT_HEALTH_PATH) => health_response(&state).await,
        (&Method::GET, DEFAULT_CONNECT_PATH) => websocket_response(&mut request, state).await,
        _ => plain_response(StatusCode::NOT_FOUND, "not found"),
    };
    Ok(response)
}

async fn status_response(state: &Arc<AppState>) -> Response<Full<Bytes>> {
    let summary = state.status.read().await.clone();
    plain_response(StatusCode::OK, render_status_body(&summary))
}

async fn health_response(state: &Arc<AppState>) -> Response<Full<Bytes>> {
    let summary = state.status.read().await.clone();
    let body = serde_json::json!({
        "phase": summary.phase,
        "detail": summary.detail,
    })
    .to_string();
    let mut response = Response::new(Full::from(Bytes::from(body)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

async fn websocket_response(
    request: &mut Request<Incoming>,
    state: Arc<AppState>,
) -> Response<Full<Bytes>> {
    if !is_upgrade_request(request) {
        return plain_response(StatusCode::BAD_REQUEST, "websocket upgrade required");
    }
    if !request_matches_join_token(request, &state.join_token) {
        return plain_response(StatusCode::NOT_FOUND, "not found");
    }
    if state.session_claimed.swap(true, Ordering::SeqCst) {
        return plain_response(
            StatusCode::CONFLICT,
            "server is already negotiating another client",
        );
    }

    let (response, websocket) = match upgrade(request, None) {
        Ok(parts) => parts,
        Err(error) => {
            state.session_claimed.store(false, Ordering::SeqCst);
            return plain_response(
                StatusCode::BAD_REQUEST,
                format!("failed to upgrade websocket: {error}"),
            );
        }
    };

    {
        let mut status = state.status.write().await;
        *status = SessionSummary::negotiating();
    }

    let state_for_task = Arc::clone(&state);
    tokio::spawn(async move {
        let negotiation_result = match websocket.await {
            Ok(websocket_stream) => {
                let timeout_result = tokio::time::timeout(
                    state_for_task.handshake_timeout,
                    handle_support_session(websocket_stream, Arc::clone(&state_for_task)),
                )
                .await;
                match timeout_result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow!(
                        "support client did not finish the handshake within {}",
                        format_duration(state_for_task.handshake_timeout)
                    )),
                }
            }
            Err(error) => Err(anyhow!("failed to finalize websocket upgrade: {error}")),
        };
        match negotiation_result {
            Ok(established_session) => {
                let mut sender_guard = state_for_task.session_sender.lock().await;
                if let Some(sender) = sender_guard.take() {
                    let _ = sender.send(established_session);
                    state_for_task.shutdown_notify.notify_waiters();
                }
            }
            Err(error) => {
                eprintln!("support negotiation failed: {error:#}");
                release_negotiation_claim(&state_for_task).await;
            }
        }
    });
    response
}

async fn handle_support_session(
    mut websocket: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    state: Arc<AppState>,
) -> Result<EstablishedSession> {
    let client_hello = match recv_packet(&mut websocket).await? {
        ControlPacket::ClientHello(hello) => hello,
        unexpected => bail!("expected client_hello packet, received {unexpected:?}"),
    };
    validate_protocol_version(client_hello.protocol_version)?;

    let offer = ServerOffer {
        protocol_version: PROTOCOL_VERSION,
        operator_name: state.operator_name.clone(),
        ssh_public_key: state.operator_key.public_key_openssh().to_string(),
        persist_key_requested: state.operator_key.persistent(),
    };
    send_packet(&mut websocket, &ControlPacket::ServerOffer(offer)).await?;

    let decision = match recv_packet(&mut websocket).await? {
        ControlPacket::ClientDecision(decision) => decision,
        unexpected => bail!("expected client_decision packet, received {unexpected:?}"),
    };
    handle_client_decision(&decision)?;
    if let Some(note) = &decision.note {
        eprintln!("client note: {note}");
    }

    Ok(EstablishedSession {
        websocket,
        client_hello,
    })
}

fn handle_client_decision(decision: &ClientDecision) -> Result<()> {
    if !decision.session_allowed {
        let note = decision
            .note
            .clone()
            .unwrap_or_else(|| "the client declined the session".to_string());
        bail!("{note}");
    }
    Ok(())
}

fn plain_response(status: StatusCode, body: impl Into<String>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::from(Bytes::from(body.into())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn resolve_join_token(join_token: Option<String>) -> Result<String> {
    if let Some(join_token) = join_token {
        let trimmed = join_token.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        bail!("--join-token must not be empty");
    }

    let mut token_bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut token_bytes);
    Ok(hex_encode(&token_bytes))
}

fn request_matches_join_token<B>(request: &Request<B>, expected_join_token: &str) -> bool {
    let Some(query) = request.uri().query() else {
        return false;
    };
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        if name == "token" && value == expected_join_token {
            return true;
        }
    }
    false
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;

        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn format_duration(duration: Duration) -> String {
    if duration.subsec_nanos() == 0 {
        let seconds = duration.as_secs();
        if seconds == 1 {
            return "1 second".to_string();
        }
        return format!("{seconds} seconds");
    }

    format!("{} ms", duration.as_millis())
}

async fn release_negotiation_claim(state: &Arc<AppState>) {
    state.session_claimed.store(false, Ordering::SeqCst);
    let mut status = state.status.write().await;
    *status = SessionSummary::waiting();
}

fn render_status_body(summary: &SessionSummary) -> String {
    format!(
        "sshportal server\nphase: {}\ndetail: {}\n",
        summary.phase, summary.detail
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use hyper::{Request, StatusCode};
    use russh::keys::ssh_key::rand_core::OsRng as KeyOsRng;
    use russh::keys::{PrivateKey, ssh_key};
    use tokio::net::TcpListener;
    use tokio::sync::{Mutex, Notify, RwLock, oneshot};
    use tokio_tungstenite::{connect_async, tungstenite::Error as WebSocketError};

    use super::{
        AppState, SessionSummary, render_status_body, request_matches_join_token,
        resolve_join_token, run_http_server,
    };
    use sshportal::{DEFAULT_CONNECT_PATH, OperatorKeyMaterial};

    #[test]
    fn explicit_join_token_is_preserved() {
        let token = resolve_join_token(Some("  shared-secret  ".to_string())).unwrap();

        assert_eq!(token, "shared-secret");
    }

    #[test]
    fn generated_join_token_is_hex_encoded() {
        let token = resolve_join_token(None).unwrap();

        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn request_join_token_must_match_query_parameter() {
        let request = Request::builder()
            .uri("http://127.0.0.1/connect?token=expected&token=ignored")
            .body(())
            .unwrap();

        assert!(request_matches_join_token(&request, "expected"));
        assert!(!request_matches_join_token(&request, "missing"));
    }

    #[test]
    fn rendered_status_body_is_generic_plain_text() {
        let body = render_status_body(&SessionSummary::connected());

        assert_eq!(
            body,
            "sshportal server\nphase: connected\ndetail: support session established\n"
        );
        assert!(!body.contains("Client:"));
        assert!(!body.contains(DEFAULT_CONNECT_PATH));
    }

    #[tokio::test]
    async fn provisional_claim_is_released_after_handshake_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (session_sender, _session_receiver) = oneshot::channel();
        let state = Arc::new(AppState {
            session_claimed: AtomicBool::new(false),
            shutdown_notify: Notify::new(),
            status: RwLock::new(SessionSummary::default()),
            session_sender: Mutex::new(Some(session_sender)),
            operator_name: "support".to_string(),
            join_token: "join-token".to_string(),
            handshake_timeout: Duration::from_millis(150),
            operator_key: test_operator_key_material(),
            ssh_listen: "127.0.0.1:0".parse().unwrap(),
            dynamic_forward: None,
        });

        let server_task = tokio::spawn(run_http_server(listener, Arc::clone(&state)));
        let first_url = format!("ws://{listen_addr}{DEFAULT_CONNECT_PATH}?token=join-token");
        let second_url = first_url.clone();

        let first_socket = connect_async(first_url).await.unwrap().0;
        tokio::time::sleep(Duration::from_millis(250)).await;
        let second_socket = connect_async(second_url).await.unwrap().0;

        drop(first_socket);
        drop(second_socket);
        tokio::time::sleep(Duration::from_millis(50)).await;

        state.shutdown_notify.notify_waiters();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn websocket_upgrade_requires_join_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (session_sender, _session_receiver) = oneshot::channel();
        let state = Arc::new(AppState {
            session_claimed: AtomicBool::new(false),
            shutdown_notify: Notify::new(),
            status: RwLock::new(SessionSummary::default()),
            session_sender: Mutex::new(Some(session_sender)),
            operator_name: "support".to_string(),
            join_token: "join-token".to_string(),
            handshake_timeout: Duration::from_secs(1),
            operator_key: test_operator_key_material(),
            ssh_listen: "127.0.0.1:0".parse().unwrap(),
            dynamic_forward: None,
        });

        let server_task = tokio::spawn(run_http_server(listener, Arc::clone(&state)));
        let missing_token_url = format!("ws://{listen_addr}{DEFAULT_CONNECT_PATH}");
        let error = connect_async(missing_token_url).await.unwrap_err();

        match error {
            WebSocketError::Http(response) => {
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }
            unexpected => panic!("expected HTTP websocket rejection, received {unexpected:?}"),
        }

        state.shutdown_notify.notify_waiters();
        server_task.await.unwrap().unwrap();
    }

    fn test_operator_key_material() -> OperatorKeyMaterial {
        let private_key = PrivateKey::random(&mut KeyOsRng, ssh_key::Algorithm::Ed25519).unwrap();
        OperatorKeyMaterial::from_private_key(private_key, false).unwrap()
    }
}
