#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_tungstenite::{HyperWebsocket, is_upgrade_request, upgrade};
use hyper_util::rt::{TokioIo, TokioTimer};
use ipnet::IpNet;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_tungstenite::WebSocketStream;
use url::form_urlencoded;

#[cfg(target_os = "macos")]
use sshportal::MacosPerAppVpn;
use sshportal::{
    ClientDecision, ClientHello, ControlPacket, DEFAULT_CONNECT_PATH, DEFAULT_HEALTH_PATH,
    OfferedSession, OperatorKeyMaterial, PROTOCOL_VERSION, ServerOffer, SystemVpnPolicy, VpnScope,
    harden_dynamic_library_search, load_operator_key, recv_packet, run_client_session_proxy,
    run_operator_socks_proxy, run_operator_vpn, send_packet, websocket_config, websocket_to_io,
};

#[derive(Parser, Debug)]
#[command(
    name = "sshportal-server",
    about = "Accept one consent-gated support client and expose SSH, SOCKS, or VPN access.",
    long_about = "Run the server side of an sshportal support session. The server prints a one-time join token, accepts the first client that proves possession of it, and starts exactly one client-approved SSH, SOCKS, or VPN session.",
    after_help = "Examples:\n  sshportal-server --listen 0.0.0.0:8080 --ssh-listen 127.0.0.1:2222\n  sshportal-server --operator-key ./operator_ed25519 --persist-operator-key\n  sshportal-server --socks-only 127.0.0.1:1080\n  sudo sshportal-server --vpn\n  sudo sshportal-server --vpn --vpn-include-cidr 10.20.0.0/16 --vpn-include-domain anthem.com\n  sshportal-server --vpn-app /Applications/Firefox.app"
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
    #[arg(
        long,
        default_value = "127.0.0.1:0",
        value_name = "LISTEN_ADDR",
        conflicts_with_all = ["socks_only", "vpn", "vpn_app"]
    )]
    ssh_listen: SocketAddr,
    /// Optional local SOCKS5 listener to expose for the lifetime of the session.
    #[arg(
        long,
        value_name = "LISTEN_ADDR",
        conflicts_with_all = ["socks_only", "vpn", "vpn_app"]
    )]
    dynamic_forward: Option<SocketAddr>,
    /// Run without SSH and expose only this local SOCKS5 listener.
    #[arg(
        long,
        value_name = "LISTEN_ADDR",
        conflicts_with_all = ["operator_key", "persist_operator_key", "vpn", "vpn_app"]
    )]
    socks_only: Option<SocketAddr>,
    /// Open a system VPN through the client.
    ///
    /// With no include selectors, all internet-bound IPv4, IPv6, TCP, UDP, and DNS traffic is
    /// routed through the client. This mode requires administrator/root privileges and WSS.
    #[arg(
        long,
        conflicts_with_all = [
            "operator_key",
            "persist_operator_key",
            "ssh_listen",
            "dynamic_forward",
            "socks_only",
            "vpn_app"
        ]
    )]
    vpn: bool,
    /// Route only this IP network through a system VPN session.
    ///
    /// Repeat the option to include multiple IPv4 or IPv6 networks. Supplying any VPN include
    /// option changes --vpn from full-tunnel to allowlist split-tunnel mode.
    #[arg(long, value_name = "CIDR", requires = "vpn")]
    vpn_include_cidr: Vec<IpNet>,
    /// Route this domain suffix through a system VPN session.
    ///
    /// The value includes both its apex and every subdomain. Repeat the option for multiple
    /// suffixes; wildcard syntax is neither needed nor accepted.
    #[arg(long, value_name = "DOMAIN", requires = "vpn")]
    vpn_include_domain: Vec<String>,
    /// On macOS, route only new connections from this signed application through the client.
    ///
    /// The server remains unprivileged. macOS may require administrator approval when the native
    /// SSHPortal system extension is installed for the first time.
    #[arg(
        long,
        value_name = "APP_BUNDLE",
        conflicts_with_all = [
            "operator_key",
            "persist_operator_key",
            "ssh_listen",
            "dynamic_forward",
            "socks_only",
            "vpn"
        ]
    )]
    vpn_app: Option<PathBuf>,
    /// Explicit SSHPortal.app bundle to use for native per-app VPN support.
    #[arg(long, value_name = "APP_BUNDLE", requires = "vpn_app")]
    vpn_companion: Option<PathBuf>,
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
    rendezvous_state: watch::Sender<RendezvousState>,
    status: RwLock<SessionSummary>,
    session_sender: Mutex<Option<oneshot::Sender<EstablishedSession>>>,
    operator_name: String,
    join_token: String,
    handshake_timeout: Duration,
    session_mode: ServerSessionMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RendezvousState {
    Accepting,
    Negotiating,
    Established,
}

#[derive(Clone, Copy, Debug)]
struct RendezvousLimits {
    max_connections: usize,
    header_timeout: Duration,
}

const MAX_HTTP_HEADERS: usize = 64;
const MAX_HTTP_HEADER_BUFFER_BYTES: usize = 16 * 1024;

impl Default for RendezvousLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            header_timeout: Duration::from_secs(10),
        }
    }
}

struct NegotiationJob {
    websocket: HyperWebsocket,
    transport_local: SocketAddr,
    transport_peer: SocketAddr,
}

impl AppState {
    async fn try_begin_negotiation(&self) -> bool {
        let mut status = self.status.write().await;
        let claimed = self.rendezvous_state.send_if_modified(|rendezvous_state| {
            if *rendezvous_state != RendezvousState::Accepting {
                return false;
            }
            *rendezvous_state = RendezvousState::Negotiating;
            true
        });
        if claimed {
            *status = SessionSummary::negotiating();
        }
        claimed
    }

    async fn release_negotiation(&self) {
        let mut status = self.status.write().await;
        let released = self.rendezvous_state.send_if_modified(|rendezvous_state| {
            if *rendezvous_state != RendezvousState::Negotiating {
                return false;
            }
            *rendezvous_state = RendezvousState::Accepting;
            true
        });
        if released {
            *status = SessionSummary::waiting();
        }
    }

    async fn mark_established(&self) {
        let _status = self.status.write().await;
        self.rendezvous_state
            .send_replace(RendezvousState::Established);
    }
}

enum ServerSessionMode {
    Ssh {
        operator_key: OperatorKeyMaterial,
        ssh_listen: SocketAddr,
        dynamic_forward: Option<SocketAddr>,
    },
    Socks {
        listen_addr: SocketAddr,
    },
    VpnSystem {
        policy: SystemVpnPolicy,
    },
    #[cfg(target_os = "macos")]
    VpnApplication {
        configuration: MacosPerAppVpn,
    },
}

impl ServerSessionMode {
    fn offer(&self, operator_name: String) -> ServerOffer {
        let session = match self {
            Self::Ssh { operator_key, .. } => OfferedSession::Ssh {
                ssh_public_key: operator_key.public_key_openssh().to_string(),
                persist_key_requested: operator_key.persistent(),
            },
            Self::Socks { .. } => OfferedSession::Socks {},
            Self::VpnSystem { policy } => OfferedSession::Vpn {
                scope: VpnScope::System {
                    policy: policy.clone(),
                },
            },
            #[cfg(target_os = "macos")]
            Self::VpnApplication { configuration } => OfferedSession::Vpn {
                scope: VpnScope::Application {
                    application: configuration.application_name().to_string(),
                },
            },
        };
        ServerOffer {
            protocol_version: PROTOCOL_VERSION,
            operator_name,
            session,
        }
    }
}

struct EstablishedSession {
    websocket: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    client_hello: ClientHello,
    transport_local: SocketAddr,
    transport_peer: SocketAddr,
}

fn main() -> Result<()> {
    harden_dynamic_library_search()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize the asynchronous runtime")?
        .block_on(run())
}

async fn run() -> Result<()> {
    let cli = ServerCli::parse();
    let session_mode = resolve_session_mode(&cli)?;
    let join_token = resolve_join_token(cli.join_token)?;

    let listener = TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("failed to bind HTTP server to {}", cli.listen))?;
    let (session_sender, session_receiver) = oneshot::channel();
    let (rendezvous_state, _) = watch::channel(RendezvousState::Accepting);
    let state = Arc::new(AppState {
        rendezvous_state,
        status: RwLock::new(SessionSummary::default()),
        session_sender: Mutex::new(Some(session_sender)),
        operator_name: cli.operator_name.clone(),
        join_token: join_token.clone(),
        handshake_timeout: Duration::from_secs(cli.handshake_timeout_seconds),
        session_mode,
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
    match &state.session_mode {
        ServerSessionMode::Ssh {
            ssh_listen,
            dynamic_forward,
            ..
        } => {
            println!("local SSH proxy requested on {ssh_listen}");
            if let Some(listen_addr) = dynamic_forward {
                println!("SSH-backed dynamic SOCKS5 proxy requested on {listen_addr}");
            }
        }
        ServerSessionMode::Socks { listen_addr } => {
            println!("SOCKS-only proxy requested on {listen_addr} (SSH disabled)");
            println!("SOCKS-only traffic relies on WSS for transport encryption");
        }
        ServerSessionMode::VpnSystem { policy } => {
            if policy.is_full_tunnel() {
                println!("full-tunnel system VPN requested (SSH disabled)");
            } else {
                println!("selective system VPN requested (SSH disabled)");
                if !policy.include_cidrs().is_empty() {
                    println!(
                        "included IP networks: {}",
                        policy
                            .include_cidrs()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                if !policy.include_domains().is_empty() {
                    println!(
                        "included domain suffixes: {}",
                        policy.include_domains().join(", ")
                    );
                }
            }
            println!("VPN mode requires administrator/root privileges and WSS");
        }
        #[cfg(target_os = "macos")]
        ServerSessionMode::VpnApplication { configuration } => {
            println!(
                "native per-app VPN requested for {} ({})",
                configuration.application_name(),
                configuration.application_bundle().display()
            );
            println!(
                "macOS companion: {}",
                configuration.companion_bundle().display()
            );
            println!("per-app VPN requires WSS but does not require root privileges");
        }
    }

    let mut http_task = tokio::spawn(run_http_server(
        listener,
        Arc::clone(&state),
        RendezvousLimits::default(),
    ));
    let established_session =
        wait_for_established_session(session_receiver, &mut http_task).await?;
    http_task
        .await
        .context("HTTP server task failed to join")??;
    {
        let mut status = state.status.write().await;
        *status = SessionSummary::connected();
    }
    let session_result = match &state.session_mode {
        ServerSessionMode::Ssh {
            operator_key,
            ssh_listen,
            dynamic_forward,
        } => {
            let transport = websocket_to_io(established_session.websocket);
            run_client_session_proxy(
                transport,
                &established_session.client_hello.metadata.username,
                Arc::clone(operator_key.private_key()),
                *ssh_listen,
                *dynamic_forward,
            )
            .await
        }
        ServerSessionMode::Socks { listen_addr } => {
            run_operator_socks_proxy(established_session.websocket, *listen_addr).await
        }
        ServerSessionMode::VpnSystem { policy } => {
            run_operator_vpn(
                established_session.websocket,
                established_session.transport_local,
                established_session.transport_peer,
                policy.clone(),
            )
            .await
        }
        #[cfg(target_os = "macos")]
        ServerSessionMode::VpnApplication { configuration } => {
            configuration.run(established_session.websocket).await
        }
    };
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

async fn wait_for_established_session(
    session_receiver: oneshot::Receiver<EstablishedSession>,
    http_task: &mut tokio::task::JoinHandle<Result<()>>,
) -> Result<EstablishedSession> {
    tokio::select! {
        biased;
        result = session_receiver => {
            result.context("server shut down before any client session started")
        }
        result = http_task => {
            result.context("HTTP server task failed to join")??;
            bail!("HTTP server stopped before any client session started");
        }
    }
}

async fn run_http_server(
    listener: TcpListener,
    state: Arc<AppState>,
    limits: RendezvousLimits,
) -> Result<()> {
    if limits.max_connections == 0 {
        bail!("HTTP rendezvous connection limit must not be zero");
    }
    if limits.header_timeout.is_zero() {
        bail!("HTTP rendezvous header timeout must not be zero");
    }

    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout)
        .max_headers(MAX_HTTP_HEADERS)
        .max_buf_size(MAX_HTTP_HEADER_BUFFER_BYTES);
    let admission = Arc::new(Semaphore::new(limits.max_connections));
    let (negotiation_sender, mut negotiation_receiver) = mpsc::channel(1);
    let mut connections = JoinSet::new();
    let mut negotiations = JoinSet::new();
    let mut state_updates = state.rendezvous_state.subscribe();
    let mut rendezvous_state = *state_updates.borrow_and_update();

    let server_result = loop {
        if rendezvous_state == RendezvousState::Established {
            break Ok(());
        }
        tokio::select! {
            changed = state_updates.changed() => {
                if changed.is_err() {
                    break Err(anyhow!("HTTP rendezvous state channel closed unexpectedly"));
                }
                rendezvous_state = *state_updates.borrow_and_update();
            }
            accepted = async {
                let permit = Arc::clone(&admission)
                    .acquire_owned()
                    .await
                    .expect("HTTP admission semaphore remains open");
                let (stream, peer_addr) = listener.accept().await?;
                Ok::<_, std::io::Error>((stream, peer_addr, permit))
            }, if rendezvous_state == RendezvousState::Accepting => {
                let (stream, peer_addr, permit) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        break Err(error).context("failed to accept HTTP connection");
                    }
                };
                if *state_updates.borrow() != RendezvousState::Accepting {
                    drop(stream);
                    continue;
                }
                if stream.set_nodelay(true).is_err() {
                    continue;
                }
                let local_addr = match stream.local_addr() {
                    Ok(local_addr) => local_addr,
                    Err(error) => {
                        break Err(error).context(
                            "failed to read the accepted HTTP socket's local address",
                        );
                    }
                };
                let state_for_connection = Arc::clone(&state);
                let negotiation_sender = negotiation_sender.clone();
                let connection_builder = builder.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |request| {
                        handle_request(
                            request,
                            Arc::clone(&state_for_connection),
                            local_addr,
                            peer_addr,
                            negotiation_sender.clone(),
                        )
                    });
                    connection_builder
                        .serve_connection(TokioIo::new(stream), service)
                        .with_upgrades()
                        .await
                        .context("HTTP rendezvous connection failed")
                });
            }
            job = negotiation_receiver.recv() => {
                let Some(job) = job else {
                    break Err(anyhow!("HTTP rendezvous negotiation queue closed unexpectedly"));
                };
                let state_for_negotiation = Arc::clone(&state);
                negotiations.spawn(async move {
                    run_negotiation(job, state_for_negotiation).await
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(error) = observe_rendezvous_task("HTTP connection", result) {
                    break Err(error);
                }
            }
            result = negotiations.join_next(), if !negotiations.is_empty() => {
                match result {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(error))) => {
                        state.release_negotiation().await;
                        eprintln!("WebSocket negotiation failed: {error:#}");
                    }
                    Some(Err(error)) if error.is_cancelled() => {}
                    Some(Err(error)) => {
                        break Err(anyhow!(error).context("WebSocket negotiation task failed to join"));
                    }
                }
            }
        }
    };

    drop(listener);
    drop(negotiation_sender);
    let negotiation_shutdown =
        abort_and_join_tasks(&mut negotiations, "WebSocket negotiation").await;
    let connection_shutdown = abort_and_join_tasks(&mut connections, "HTTP connection").await;
    server_result
        .and(negotiation_shutdown)
        .and(connection_shutdown)
}

fn observe_rendezvous_task(
    label: &str,
    result: Option<Result<Result<()>, tokio::task::JoinError>>,
) -> Option<anyhow::Error> {
    match result {
        Some(Ok(Ok(()))) | None => None,
        Some(Ok(Err(_))) => None,
        Some(Err(error)) if error.is_cancelled() => None,
        Some(Err(error)) => Some(anyhow!(error).context(format!("{label} task failed to join"))),
    }
}

async fn abort_and_join_tasks(tasks: &mut JoinSet<Result<()>>, label: &str) -> Result<()> {
    tasks.abort_all();
    let mut join_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) if join_error.is_none() => {
                join_error = Some(anyhow!(error).context(format!("{label} task failed to join")));
            }
            Err(_) => {}
        }
    }
    match join_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn handle_request(
    mut request: Request<Incoming>,
    state: Arc<AppState>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    negotiation_sender: mpsc::Sender<NegotiationJob>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/") => status_response(&state).await,
        (&Method::GET, DEFAULT_HEALTH_PATH) => health_response(&state).await,
        (&Method::GET, DEFAULT_CONNECT_PATH) => {
            websocket_response(
                &mut request,
                state,
                local_addr,
                peer_addr,
                negotiation_sender,
            )
            .await
        }
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
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    negotiation_sender: mpsc::Sender<NegotiationJob>,
) -> Response<Full<Bytes>> {
    if !is_upgrade_request(request) {
        return plain_response(StatusCode::BAD_REQUEST, "websocket upgrade required");
    }
    if !request_matches_join_token(request, &state.join_token) {
        return plain_response(StatusCode::NOT_FOUND, "not found");
    }
    if !state.try_begin_negotiation().await {
        return plain_response(
            StatusCode::CONFLICT,
            "server is already negotiating another client",
        );
    }
    let (response, websocket) = match upgrade(request, Some(websocket_config())) {
        Ok(parts) => parts,
        Err(error) => {
            state.release_negotiation().await;
            return plain_response(
                StatusCode::BAD_REQUEST,
                format!("failed to upgrade websocket: {error}"),
            );
        }
    };

    if negotiation_sender
        .try_send(NegotiationJob {
            websocket,
            transport_local: local_addr,
            transport_peer: peer_addr,
        })
        .is_err()
    {
        state.release_negotiation().await;
        return plain_response(StatusCode::SERVICE_UNAVAILABLE, "server is shutting down");
    }
    response
}

async fn run_negotiation(job: NegotiationJob, state: Arc<AppState>) -> Result<()> {
    let handshake = async {
        let websocket = job
            .websocket
            .await
            .context("failed to finalize websocket upgrade")?;
        handle_support_session(
            websocket,
            Arc::clone(&state),
            job.transport_local,
            job.transport_peer,
        )
        .await
    };
    let established_session = match tokio::time::timeout(state.handshake_timeout, handshake).await {
        Ok(Ok(established_session)) => established_session,
        Ok(Err(error)) => return Err(error),
        Err(_) => bail!(
            "support client did not finish the handshake within {}",
            format_duration(state.handshake_timeout)
        ),
    };

    let sender = match state.session_sender.lock().await.take() {
        Some(sender) => sender,
        None => {
            state.mark_established().await;
            bail!("support session receiver is unavailable");
        }
    };
    if sender.send(established_session).is_err() {
        state.mark_established().await;
        bail!("support session receiver closed before accepting the established session");
    }
    state.mark_established().await;
    Ok(())
}

async fn handle_support_session(
    mut websocket: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    state: Arc<AppState>,
    transport_local: SocketAddr,
    transport_peer: SocketAddr,
) -> Result<EstablishedSession> {
    let client_hello = match recv_packet(&mut websocket).await? {
        ControlPacket::ClientHello(hello) => hello,
        unexpected => bail!("expected client_hello packet, received {unexpected:?}"),
    };
    let offer = state.session_mode.offer(state.operator_name.clone());
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
        transport_local,
        transport_peer,
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

fn resolve_session_mode(cli: &ServerCli) -> Result<ServerSessionMode> {
    if cli.vpn {
        let policy =
            SystemVpnPolicy::new(cli.vpn_include_cidr.clone(), cli.vpn_include_domain.clone())?;
        return Ok(ServerSessionMode::VpnSystem { policy });
    }
    if let Some(application_bundle) = &cli.vpn_app {
        #[cfg(target_os = "macos")]
        {
            let configuration =
                MacosPerAppVpn::resolve(application_bundle, cli.vpn_companion.as_deref())?;
            return Ok(ServerSessionMode::VpnApplication { configuration });
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = application_bundle;
            bail!("--vpn-app is supported only on macOS");
        }
    }
    if let Some(listen_addr) = cli.socks_only {
        return Ok(ServerSessionMode::Socks { listen_addr });
    }
    let operator_key = load_operator_key(cli.operator_key.as_deref(), cli.persist_operator_key)?;
    Ok(ServerSessionMode::Ssh {
        operator_key,
        ssh_listen: cli.ssh_listen,
        dynamic_forward: cli.dynamic_forward,
    })
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
    rand::fill(&mut token_bytes);
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

fn render_status_body(summary: &SessionSummary) -> String {
    format!(
        "sshportal server\nphase: {}\ndetail: {}\n",
        summary.phase, summary.detail
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use clap::Parser;
    use futures_util::{SinkExt, StreamExt};
    use hyper::{Request, StatusCode};
    use russh::keys::{PrivateKey, ssh_key};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Mutex, RwLock, oneshot, watch};
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{Error as WebSocketError, Message},
    };

    use super::{
        AppState, EstablishedSession, RendezvousLimits, RendezvousState, ServerCli,
        ServerSessionMode, SessionSummary, render_status_body, request_matches_join_token,
        resolve_join_token, resolve_session_mode, run_http_server, wait_for_established_session,
    };
    use sshportal::{
        ClientDecision, ClientHello, ClientMetadata, ControlPacket, DEFAULT_CONNECT_PATH,
        OperatorKeyMaterial, PROTOCOL_VERSION, Platform, recv_packet, send_packet,
    };

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
    fn socks_only_mode_does_not_require_ssh_configuration() {
        let cli = ServerCli::try_parse_from(["sshportal-server", "--socks-only", "127.0.0.1:1080"])
            .unwrap();

        let mode = resolve_session_mode(&cli).unwrap();
        assert!(matches!(
            mode,
            ServerSessionMode::Socks { listen_addr }
                if listen_addr == "127.0.0.1:1080".parse().unwrap()
        ));
    }

    #[test]
    fn socks_only_mode_rejects_ssh_listener_configuration() {
        let result = ServerCli::try_parse_from([
            "sshportal-server",
            "--socks-only",
            "127.0.0.1:1080",
            "--ssh-listen",
            "127.0.0.1:2222",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn vpn_mode_does_not_require_ssh_configuration() {
        let cli = ServerCli::try_parse_from(["sshportal-server", "--vpn"]).unwrap();

        let mode = resolve_session_mode(&cli).unwrap();

        assert!(matches!(
            mode,
            ServerSessionMode::VpnSystem { policy } if policy.is_full_tunnel()
        ));
    }

    #[test]
    fn vpn_selectors_require_system_vpn_mode() {
        for arguments in [
            vec!["sshportal-server", "--vpn-include-cidr", "10.20.0.0/16"],
            vec!["sshportal-server", "--vpn-include-domain", "anthem.com"],
        ] {
            assert!(ServerCli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn repeated_vpn_selectors_form_one_normalized_policy() {
        let cli = ServerCli::try_parse_from([
            "sshportal-server",
            "--vpn",
            "--vpn-include-cidr",
            "10.20.4.7/16",
            "--vpn-include-cidr",
            "2001:db8::/32",
            "--vpn-include-domain",
            "Login.ANTHEM.com",
            "--vpn-include-domain",
            "anthem.com",
        ])
        .unwrap();

        let mode = resolve_session_mode(&cli).unwrap();
        let ServerSessionMode::VpnSystem { policy } = mode else {
            panic!("expected a system VPN session");
        };

        assert_eq!(
            policy
                .include_cidrs()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.20.0.0/16", "2001:db8::/32"]
        );
        assert_eq!(policy.include_domains(), ["anthem.com"]);
    }

    #[test]
    fn malformed_vpn_domain_is_rejected_when_resolving_the_session() {
        let cli = ServerCli::try_parse_from([
            "sshportal-server",
            "--vpn",
            "--vpn-include-domain",
            "*.anthem.com",
        ])
        .unwrap();

        assert!(resolve_session_mode(&cli).is_err());
    }

    #[test]
    fn vpn_mode_rejects_every_other_session_mode_option() {
        for arguments in [
            vec![
                "sshportal-server",
                "--vpn",
                "--socks-only",
                "127.0.0.1:1080",
            ],
            vec![
                "sshportal-server",
                "--vpn",
                "--ssh-listen",
                "127.0.0.1:2222",
            ],
            vec![
                "sshportal-server",
                "--vpn",
                "--dynamic-forward",
                "127.0.0.1:1080",
            ],
            vec![
                "sshportal-server",
                "--vpn",
                "--operator-key",
                "operator-key",
            ],
            vec!["sshportal-server", "--vpn", "--persist-operator-key"],
        ] {
            assert!(ServerCli::try_parse_from(arguments).is_err());
        }
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
        let (state, _session_receiver) = test_state(Duration::from_millis(150));

        let server_task = tokio::spawn(run_http_server(
            listener,
            Arc::clone(&state),
            test_limits(8, Duration::from_secs(2)),
        ));
        let first_url = format!("ws://{listen_addr}{DEFAULT_CONNECT_PATH}?token=join-token");
        let second_url = first_url.clone();

        let first_socket = connect_async(first_url).await.unwrap().0;
        let mut queued_http = TcpStream::connect(listen_addr).await.unwrap();
        queued_http
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0_u8; 1024];
        assert!(
            tokio::time::timeout(Duration::from_millis(75), queued_http.read(&mut response))
                .await
                .is_err()
        );
        let response_bytes =
            tokio::time::timeout(Duration::from_secs(1), queued_http.read(&mut response))
                .await
                .expect("HTTP listener did not resume after the provisional claim expired")
                .unwrap();
        assert!(response_bytes > 0);
        let second_socket = connect_async(second_url).await.unwrap().0;

        drop(first_socket);
        drop(queued_http);
        drop(second_socket);
        stop_server(&state, server_task).await;
    }

    #[tokio::test]
    async fn websocket_upgrade_requires_join_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (state, _session_receiver) = test_state(Duration::from_secs(1));

        let server_task = tokio::spawn(run_http_server(
            listener,
            Arc::clone(&state),
            test_limits(8, Duration::from_secs(2)),
        ));
        let missing_token_url = format!("ws://{listen_addr}{DEFAULT_CONNECT_PATH}");
        let error = connect_async(missing_token_url).await.unwrap_err();

        match error {
            WebSocketError::Http(response) => {
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }
            unexpected => panic!("expected HTTP websocket rejection, received {unexpected:?}"),
        }

        stop_server(&state, server_task).await;
    }

    #[tokio::test]
    async fn partial_http_headers_are_closed_at_the_read_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (state, _session_receiver) = test_state(Duration::from_secs(1));
        let server_task = tokio::spawn(run_http_server(
            listener,
            Arc::clone(&state),
            test_limits(8, Duration::from_millis(100)),
        ));
        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Incomplete:")
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut Vec::new()))
            .await
            .expect("partial HTTP headers remained open after their deadline")
            .unwrap();

        stop_server(&state, server_task).await;
    }

    #[tokio::test]
    async fn connection_admission_waits_for_capacity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (state, _session_receiver) = test_state(Duration::from_secs(1));
        let server_task = tokio::spawn(run_http_server(
            listener,
            Arc::clone(&state),
            test_limits(1, Duration::from_secs(5)),
        ));

        let mut first = TcpStream::connect(listen_addr).await.unwrap();
        first
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0_u8; 1024];
        let first_bytes = tokio::time::timeout(Duration::from_secs(1), first.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(first_bytes > 0);

        let mut second = TcpStream::connect(listen_addr).await.unwrap();
        second
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), second.read(&mut response))
                .await
                .is_err()
        );

        drop(first);
        let second_bytes = tokio::time::timeout(Duration::from_secs(1), second.read(&mut response))
            .await
            .expect("queued HTTP connection was not admitted after capacity returned")
            .unwrap();
        assert!(second_bytes > 0);

        stop_server(&state, server_task).await;
    }

    #[tokio::test]
    async fn shutdown_aborts_and_joins_idle_http_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (state, _session_receiver) = test_state(Duration::from_secs(1));
        let server_task = tokio::spawn(run_http_server(
            listener,
            Arc::clone(&state),
            test_limits(4, Duration::from_secs(5)),
        ));
        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;

        stop_server(&state, server_task).await;

        let mut byte = [0_u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("idle HTTP connection survived rendezvous shutdown");
    }

    #[tokio::test]
    async fn upgraded_websocket_survives_http_task_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (state, session_receiver) = test_state(Duration::from_secs(1));
        let server_task = tokio::spawn(run_http_server(
            listener,
            Arc::clone(&state),
            test_limits(8, Duration::from_secs(2)),
        ));
        let url = format!("ws://{listen_addr}{DEFAULT_CONNECT_PATH}?token=join-token");
        let mut client = connect_async(url).await.unwrap().0;

        send_packet(
            &mut client,
            &ControlPacket::ClientHello(ClientHello {
                protocol_version: PROTOCOL_VERSION,
                metadata: ClientMetadata {
                    hostname: "test-client".to_string(),
                    username: "test-user".to_string(),
                    working_directory: "/test".to_string(),
                    platform: Platform::current().unwrap(),
                },
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            recv_packet(&mut client).await.unwrap(),
            ControlPacket::ServerOffer(_)
        ));
        send_packet(
            &mut client,
            &ControlPacket::ClientDecision(ClientDecision {
                session_allowed: true,
                key_installed: false,
                note: None,
            }),
        )
        .await
        .unwrap();

        let mut established = tokio::time::timeout(Duration::from_secs(1), session_receiver)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("HTTP task did not stop after the session was established")
            .unwrap()
            .unwrap();

        client
            .send(Message::Binary(b"still-open".to_vec().into()))
            .await
            .unwrap();
        let message = tokio::time::timeout(Duration::from_secs(1), established.websocket.next())
            .await
            .expect("upgraded WebSocket stopped with the HTTP rendezvous")
            .unwrap()
            .unwrap();
        assert_eq!(message.into_data(), b"still-open".as_slice());
    }

    #[tokio::test]
    async fn established_session_wait_fails_when_the_http_task_stops_first() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (state, session_receiver) = test_state(Duration::from_secs(1));
        let mut server_task = tokio::spawn(run_http_server(
            listener,
            Arc::clone(&state),
            test_limits(0, Duration::from_secs(1)),
        ));

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_established_session(session_receiver, &mut server_task),
        )
        .await
        .expect("session wait ignored the failed HTTP task");
        let Err(error) = result else {
            panic!("HTTP task failure unexpectedly produced a session");
        };
        assert!(
            error
                .to_string()
                .contains("connection limit must not be zero")
        );
    }

    fn test_state(
        handshake_timeout: Duration,
    ) -> (Arc<AppState>, oneshot::Receiver<EstablishedSession>) {
        let (session_sender, session_receiver) = oneshot::channel();
        let (rendezvous_state, _) = watch::channel(RendezvousState::Accepting);
        let state = Arc::new(AppState {
            rendezvous_state,
            status: RwLock::new(SessionSummary::default()),
            session_sender: Mutex::new(Some(session_sender)),
            operator_name: "support".to_string(),
            join_token: "join-token".to_string(),
            handshake_timeout,
            session_mode: ServerSessionMode::Ssh {
                operator_key: test_operator_key_material(),
                ssh_listen: "127.0.0.1:0".parse().unwrap(),
                dynamic_forward: None,
            },
        });
        (state, session_receiver)
    }

    fn test_limits(max_connections: usize, header_timeout: Duration) -> RendezvousLimits {
        RendezvousLimits {
            max_connections,
            header_timeout,
        }
    }

    async fn stop_server(
        state: &AppState,
        server_task: tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        state
            .rendezvous_state
            .send_replace(RendezvousState::Established);
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("HTTP rendezvous did not stop")
            .unwrap()
            .unwrap();
    }

    fn test_operator_key_material() -> OperatorKeyMaterial {
        let private_key =
            PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        OperatorKeyMaterial::from_private_key(private_key, false).unwrap()
    }
}
