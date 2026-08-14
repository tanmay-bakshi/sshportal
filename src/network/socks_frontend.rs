use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{AbortHandle, JoinSet};

use crate::NETWORK_SESSION_FLOW_LIMIT;
use crate::debug::debug_log;
use crate::network::protocol::{NetworkError, NetworkErrorKind};
use crate::network::session::{
    NetworkSessionRuntime, OperatorNetworkSession, ReceivedUdpDatagram, bridge_operator_tcp,
    start_operator_network_session,
};
use crate::socks::{
    SOCKS_REPLY_CONNECTION_NOT_ALLOWED, SOCKS_REPLY_CONNECTION_REFUSED,
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_HOST_UNREACHABLE, SOCKS_REPLY_NETWORK_UNREACHABLE,
    SOCKS_REPLY_SUCCESS, SOCKS_REPLY_TTL_EXPIRED, SocksAuthentication, SocksRequest,
    SocksUdpDatagram, decode_socks_udp_datagram, encode_socks_udp_datagram,
    negotiate_socks5_network, write_socks5_response,
};

const SOCKS_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SOCKS_UDP_PACKET_BYTES: usize = 65_535;
const MAX_SOCKS_UDP_TARGETS: usize = 64;
const MAX_SOCKS_UDP_QUEUED_DATAGRAMS_PER_TARGET: usize = 8;
const MAX_SOCKS_UDP_BUFFERED_BYTES: usize = 4 * 1024 * 1024;
const SOCKS_UDP_TARGET_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

struct SocksUdpTarget {
    generation: u64,
    requests: mpsc::Sender<BufferedSocksUdpDatagram>,
    connected_peer: Option<SocketAddr>,
    last_used: tokio::time::Instant,
    worker: AbortHandle,
}

impl Drop for SocksUdpTarget {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

struct BufferedSocksUdpDatagram {
    data: Bytes,
    _buffer_permit: OwnedSemaphorePermit,
}

enum SocksUdpEvent {
    Opened {
        target: crate::network::NetworkTarget,
        generation: u64,
        peer: SocketAddr,
    },
    Response {
        target: crate::network::NetworkTarget,
        generation: u64,
        peer: SocketAddr,
        datagram: ReceivedUdpDatagram,
        handled: oneshot::Sender<()>,
    },
}

struct SocksUdpWorkerCompletion {
    target: crate::network::NetworkTarget,
    generation: u64,
    result: Result<(), NetworkError>,
}

pub async fn run_operator_socks_proxy<S>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    listen_addr: SocketAddr,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind SOCKS5 proxy to {listen_addr}"))?;
    let bound_addr = listener
        .local_addr()
        .context("failed to read SOCKS5 proxy listener address")?;
    println!("SOCKS5 proxy listening on {bound_addr} (SSH disabled)");
    run_operator_network_proxy_with_listener(websocket, listener, SocksAuthentication::None).await
}

pub(crate) async fn run_operator_network_proxy_with_listener<S>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    listener: TcpListener,
    authentication: SocksAuthentication,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (session, runtime) = start_operator_network_session(websocket).await?;
    run_socks_listener(session, runtime, listener, authentication).await
}

async fn run_socks_listener(
    session: OperatorNetworkSession,
    runtime: NetworkSessionRuntime,
    listener: TcpListener,
    authentication: SocksAuthentication,
) -> Result<()> {
    let mut flows = JoinSet::new();
    let session_result = {
        let runtime = runtime.wait();
        tokio::pin!(runtime);
        loop {
            tokio::select! {
                accepted = listener.accept(), if flows.len() < NETWORK_SESSION_FLOW_LIMIT => {
                    let (stream, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            break Err(error).context("failed to accept SOCKS5 connection");
                        }
                    };
                    let flow_session = session.clone();
                    let flow_authentication = authentication.clone();
                    debug_log(format!("accepted SOCKS client {peer}"));
                    flows.spawn(async move {
                        if let Err(error) = run_socks_flow(stream, flow_session, flow_authentication).await {
                            debug_log(format!("SOCKS client {peer} ended with an error: {error:#}"));
                        }
                    });
                }
                result = &mut runtime => break result,
                result = flows.join_next(), if !flows.is_empty() => {
                    if let Some(Err(error)) = result {
                        break Err(error).context("SOCKS flow task failed to join");
                    }
                }
            }
        }
    };

    flows.abort_all();
    while flows.join_next().await.is_some() {}
    session_result
}

async fn run_socks_flow(
    mut stream: TcpStream,
    session: OperatorNetworkSession,
    authentication: SocksAuthentication,
) -> Result<()> {
    let request = match tokio::time::timeout(
        SOCKS_NEGOTIATION_TIMEOUT,
        negotiate_socks5_network(&mut stream, &authentication),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            let _ = write_socks5_response(&mut stream, SOCKS_REPLY_TTL_EXPIRED, None).await;
            return Err(anyhow!("SOCKS negotiation timed out"));
        }
    };
    match request {
        SocksRequest::Connect(target) => run_socks_tcp(stream, session, target).await,
        SocksRequest::UdpAssociate => run_socks_udp(stream, session).await,
    }
}

async fn run_socks_tcp(
    mut stream: TcpStream,
    session: OperatorNetworkSession,
    target: crate::network::NetworkTarget,
) -> Result<()> {
    let tunnel = match session.connect_tcp(target).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            write_socks5_response(&mut stream, socks_reply_for_error(&error), None).await?;
            return Err(error.into());
        }
    };
    write_socks5_response(&mut stream, SOCKS_REPLY_SUCCESS, None).await?;
    bridge_operator_tcp(stream, tunnel).await
}

async fn run_socks_udp(mut control: TcpStream, session: OperatorNetworkSession) -> Result<()> {
    let bind_address = match control.local_addr()?.ip() {
        IpAddr::V4(address) if address.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(address) if address.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        address => address,
    };
    let relay = UdpSocket::bind(SocketAddr::new(bind_address, 0))
        .await
        .context("failed to bind SOCKS UDP relay")?;
    let relay_address = relay
        .local_addr()
        .context("failed to read SOCKS UDP relay address")?;
    let control_peer = control.peer_addr()?;
    write_socks5_response(&mut control, SOCKS_REPLY_SUCCESS, Some(relay_address)).await?;

    let mut packet = vec![0_u8; MAX_SOCKS_UDP_PACKET_BYTES];
    let mut associated_udp_peer = None;
    let mut targets = HashMap::<crate::network::NetworkTarget, SocksUdpTarget>::new();
    let buffered_bytes = Arc::new(Semaphore::new(MAX_SOCKS_UDP_BUFFERED_BYTES));
    let (events, mut event_receiver) = mpsc::channel(MAX_SOCKS_UDP_TARGETS);
    let mut workers = JoinSet::<SocksUdpWorkerCompletion>::new();
    let mut next_generation = 0_u64;
    let mut control_byte = [0_u8; 1];
    let association_result: Result<()> = async {
        loop {
            let next_target_expiry = next_udp_target_expiry(
                targets.values().map(|target| target.last_used),
                SOCKS_UDP_TARGET_IDLE_TIMEOUT,
            );
            tokio::select! {
                () = wait_for_udp_target_expiry(next_target_expiry) => {
                    let now = tokio::time::Instant::now();
                    targets.retain(|_, target| {
                        target.last_used + SOCKS_UDP_TARGET_IDLE_TIMEOUT > now
                    });
                }
                control_result = control.read(&mut control_byte) => {
                    match control_result {
                        Ok(0) => return Ok(()),
                        Ok(_) => return Err(anyhow!("SOCKS UDP control connection sent unexpected data")),
                        Err(error) => return Err(error).context("SOCKS UDP control connection failed"),
                    }
                }
                datagram = relay.recv_from(&mut packet) => {
                    let (size, source) = datagram.context("failed to receive SOCKS UDP datagram")?;
                    if source.ip() != control_peer.ip() {
                        debug_log(format!("ignored SOCKS UDP datagram from unrelated peer {source}"));
                        continue;
                    }
                    if let Some(expected) = associated_udp_peer {
                        if source != expected {
                            debug_log(format!("ignored SOCKS UDP datagram from unexpected source {source}"));
                            continue;
                        }
                    } else {
                        associated_udp_peer = Some(source);
                    }
                    let datagram = match decode_socks_udp_datagram(&packet[..size]) {
                        Ok(datagram) => datagram,
                        Err(error) => {
                            debug_log(format!("ignored invalid SOCKS UDP datagram: {error:#}"));
                            continue;
                        }
                    };
                    queue_socks_udp_datagram(
                        datagram,
                        &session,
                        &mut targets,
                        &mut workers,
                        &events,
                        &buffered_bytes,
                        &mut next_generation,
                    )?;
                }
                event = event_receiver.recv() => {
                    let event = event.context("SOCKS UDP destination event channel closed unexpectedly")?;
                    handle_socks_udp_event(
                        event,
                        &mut targets,
                        &relay,
                        associated_udp_peer,
                    ).await?;
                }
                completion = workers.join_next(), if !workers.is_empty() => {
                    match completion {
                        Some(Ok(completion)) => {
                            let is_current = targets
                                .get(&completion.target)
                                .is_some_and(|target| target.generation == completion.generation);
                            if is_current {
                                targets.remove(&completion.target);
                                if let Err(error) = completion.result {
                                    debug_log(format!(
                                        "UDP destination {}:{} ended with an error: {error}",
                                        completion.target.host, completion.target.port
                                    ));
                                }
                            }
                        }
                        Some(Err(error)) if error.is_cancelled() => {}
                        Some(Err(error)) => {
                            return Err(anyhow!(error)).context("SOCKS UDP destination worker failed");
                        }
                        None => {}
                    }
                }
            }
        }
    }
    .await;

    targets.clear();
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    association_result
}

fn queue_socks_udp_datagram(
    datagram: SocksUdpDatagram,
    session: &OperatorNetworkSession,
    targets: &mut HashMap<crate::network::NetworkTarget, SocksUdpTarget>,
    workers: &mut JoinSet<SocksUdpWorkerCompletion>,
    events: &mpsc::Sender<SocksUdpEvent>,
    buffered_bytes: &Arc<Semaphore>,
    next_generation: &mut u64,
) -> Result<()> {
    if !targets.contains_key(&datagram.target) && targets.len() == MAX_SOCKS_UDP_TARGETS {
        debug_log(format!(
            "discarded UDP datagram to {}:{} because the association target limit was reached",
            datagram.target.host, datagram.target.port
        ));
        return Ok(());
    }
    let permit_count = u32::try_from(datagram.data.len())
        .context("SOCKS UDP datagram length does not fit the buffer accounting range")?;
    let buffer_permit = match Arc::clone(buffered_bytes).try_acquire_many_owned(permit_count) {
        Ok(permit) => permit,
        Err(_) => {
            debug_log(format!(
                "discarded UDP datagram to {}:{} because the association buffer is full",
                datagram.target.host, datagram.target.port
            ));
            return Ok(());
        }
    };

    if !targets.contains_key(&datagram.target) {
        *next_generation = next_generation
            .checked_add(1)
            .context("SOCKS UDP target generation exhausted")?;
        let generation = *next_generation;
        let (requests, request_receiver) = mpsc::channel(MAX_SOCKS_UDP_QUEUED_DATAGRAMS_PER_TARGET);
        let worker = workers.spawn(run_socks_udp_target(
            session.clone(),
            datagram.target.clone(),
            generation,
            request_receiver,
            events.clone(),
        ));
        targets.insert(
            datagram.target.clone(),
            SocksUdpTarget {
                generation,
                requests,
                connected_peer: None,
                last_used: tokio::time::Instant::now(),
                worker,
            },
        );
    }

    let target = targets
        .get_mut(&datagram.target)
        .expect("a SOCKS UDP target is present after admission");
    match target.requests.try_send(BufferedSocksUdpDatagram {
        data: datagram.data,
        _buffer_permit: buffer_permit,
    }) {
        Ok(()) => target.last_used = tokio::time::Instant::now(),
        Err(mpsc::error::TrySendError::Full(_)) => {
            debug_log(format!(
                "discarded UDP datagram to {}:{} because its destination queue is full",
                datagram.target.host, datagram.target.port
            ));
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            debug_log(format!(
                "discarded UDP datagram to {}:{} because its destination closed",
                datagram.target.host, datagram.target.port
            ));
        }
    }
    Ok(())
}

async fn run_socks_udp_target(
    session: OperatorNetworkSession,
    target: crate::network::NetworkTarget,
    generation: u64,
    requests: mpsc::Receiver<BufferedSocksUdpDatagram>,
    events: mpsc::Sender<SocksUdpEvent>,
) -> SocksUdpWorkerCompletion {
    let result = run_socks_udp_target_inner(&session, &target, generation, requests, &events).await;
    SocksUdpWorkerCompletion {
        target,
        generation,
        result,
    }
}

async fn run_socks_udp_target_inner(
    session: &OperatorNetworkSession,
    target: &crate::network::NetworkTarget,
    generation: u64,
    requests: mpsc::Receiver<BufferedSocksUdpDatagram>,
    events: &mpsc::Sender<SocksUdpEvent>,
) -> Result<(), NetworkError> {
    let tunnel = session.open_udp(target.clone()).await?;
    let peer = tunnel.peer_addr();
    events
        .send(SocksUdpEvent::Opened {
            target: target.clone(),
            generation,
            peer,
        })
        .await
        .map_err(|_| socks_udp_association_closed())?;
    let (sender, receiver) = tunnel.split();
    tokio::select! {
        result = forward_socks_udp_requests(sender, requests) => result,
        result = forward_socks_udp_responses(
            receiver,
            target.clone(),
            generation,
            peer,
            events.clone(),
        ) => result,
    }
}

async fn forward_socks_udp_requests(
    mut sender: crate::network::session::UdpTunnelSender,
    mut requests: mpsc::Receiver<BufferedSocksUdpDatagram>,
) -> Result<(), NetworkError> {
    while let Some(datagram) = requests.recv().await {
        sender.send_datagram(datagram.data).await?;
    }
    Ok(())
}

async fn forward_socks_udp_responses(
    mut receiver: crate::network::session::UdpTunnelReceiver,
    target: crate::network::NetworkTarget,
    generation: u64,
    peer: SocketAddr,
    events: mpsc::Sender<SocksUdpEvent>,
) -> Result<(), NetworkError> {
    loop {
        let Some(datagram) = receiver.receive_datagram().await? else {
            return Ok(());
        };
        let wire_bytes = datagram.wire_bytes;
        let (handled, handled_receiver) = oneshot::channel();
        if events
            .send(SocksUdpEvent::Response {
                target: target.clone(),
                generation,
                peer,
                datagram,
                handled,
            })
            .await
            .is_err()
        {
            receiver.release_receive_capacity(wire_bytes)?;
            return Err(socks_udp_association_closed());
        }

        // The HTTP/2 window continues to account for this capsule until the
        // local relay has either admitted or deliberately discarded it.
        let association_open = handled_receiver.await.is_ok();
        receiver.release_receive_capacity(wire_bytes)?;
        if !association_open {
            return Err(socks_udp_association_closed());
        }
    }
}

async fn handle_socks_udp_event(
    event: SocksUdpEvent,
    targets: &mut HashMap<crate::network::NetworkTarget, SocksUdpTarget>,
    relay: &UdpSocket,
    associated_udp_peer: Option<SocketAddr>,
) -> Result<()> {
    match event {
        SocksUdpEvent::Opened {
            target,
            generation,
            peer,
        } => {
            let Some(state) = targets.get_mut(&target) else {
                return Ok(());
            };
            if state.generation != generation {
                return Ok(());
            }
            if state.connected_peer.replace(peer).is_some() {
                return Err(anyhow!(
                    "SOCKS UDP destination {}:{} opened more than once",
                    target.host,
                    target.port
                ));
            }
        }
        SocksUdpEvent::Response {
            target,
            generation,
            peer,
            datagram,
            handled,
        } => {
            let is_current = targets.get_mut(&target).is_some_and(|state| {
                if state.generation != generation || state.connected_peer != Some(peer) {
                    return false;
                }
                state.last_used = tokio::time::Instant::now();
                true
            });
            if is_current && let Some(local_peer) = associated_udp_peer {
                relay_socks_udp_response(relay, local_peer, peer, datagram.data).await;
            }
            let _ = handled.send(());
        }
    }
    Ok(())
}

async fn relay_socks_udp_response(
    relay: &UdpSocket,
    local_peer: SocketAddr,
    connected_peer: SocketAddr,
    data: Bytes,
) {
    let response_target = crate::network::NetworkTarget::from(connected_peer);
    let encoded = match encode_socks_udp_datagram(&SocksUdpDatagram {
        target: response_target.clone(),
        data,
    }) {
        Ok(encoded) => encoded,
        Err(error) => {
            debug_log(format!(
                "discarded UDP response from {}:{}: {error:#}",
                response_target.host, response_target.port
            ));
            return;
        }
    };
    match relay.send_to(&encoded, local_peer).await {
        Ok(sent) if sent == encoded.len() => {}
        Ok(sent) => {
            debug_log(format!(
                "discarded partial SOCKS UDP response from {}:{} ({sent} of {} bytes)",
                response_target.host,
                response_target.port,
                encoded.len()
            ));
        }
        Err(error) => {
            debug_log(format!(
                "discarded SOCKS UDP response from {}:{}: {error}",
                response_target.host, response_target.port
            ));
        }
    }
}

fn socks_udp_association_closed() -> NetworkError {
    NetworkError::new(
        NetworkErrorKind::SessionClosed,
        "SOCKS UDP association closed",
    )
}

fn next_udp_target_expiry(
    last_used: impl Iterator<Item = tokio::time::Instant>,
    idle_timeout: Duration,
) -> Option<tokio::time::Instant> {
    last_used.map(|instant| instant + idle_timeout).min()
}

async fn wait_for_udp_target_expiry(expiry: Option<tokio::time::Instant>) {
    match expiry {
        Some(expiry) => tokio::time::sleep_until(expiry).await,
        None => std::future::pending().await,
    }
}

fn socks_reply_for_error(error: &NetworkError) -> u8 {
    match error.kind {
        NetworkErrorKind::PermissionDenied => SOCKS_REPLY_CONNECTION_NOT_ALLOWED,
        NetworkErrorKind::NetworkUnreachable => SOCKS_REPLY_NETWORK_UNREACHABLE,
        NetworkErrorKind::HostUnreachable | NetworkErrorKind::NameNotFound => {
            SOCKS_REPLY_HOST_UNREACHABLE
        }
        NetworkErrorKind::ConnectionRefused => SOCKS_REPLY_CONNECTION_REFUSED,
        NetworkErrorKind::TimedOut => SOCKS_REPLY_TTL_EXPIRED,
        NetworkErrorKind::General
        | NetworkErrorKind::ResourceLimit
        | NetworkErrorKind::Protocol
        | NetworkErrorKind::SessionClosed => SOCKS_REPLY_GENERAL_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::task::JoinHandle;
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

    use crate::NETWORK_SESSION_FLOW_LIMIT;
    use crate::OfferedSession;
    use crate::network::NetworkTarget;
    use crate::network::session::run_client_network_session;
    use crate::socks::{
        SOCKS_ATYP_DOMAIN_NAME, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, SOCKS_AUTH_NONE,
        SOCKS_AUTH_USERNAME_PASSWORD, SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE,
        SOCKS_REPLY_SUCCESS, SOCKS_VERSION, SocksAuthentication, SocksUdpDatagram,
        decode_socks_target, decode_socks_udp_datagram, encode_socks_target,
        encode_socks_udp_datagram,
    };

    use super::{
        MAX_SOCKS_UDP_PACKET_BYTES, MAX_SOCKS_UDP_QUEUED_DATAGRAMS_PER_TARGET,
        next_udp_target_expiry, run_operator_network_proxy_with_listener,
        wait_for_udp_target_expiry,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const TASK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
    const WEBSOCKET_TRANSPORT_BYTES: usize = 512 * 1024;

    struct NetworkProxyHarness {
        socks_address: SocketAddr,
        operator_task: JoinHandle<anyhow::Result<()>>,
        client_task: JoinHandle<anyhow::Result<()>>,
    }

    impl Drop for NetworkProxyHarness {
        fn drop(&mut self) {
            self.operator_task.abort();
            self.client_task.abort();
        }
    }

    #[derive(Debug)]
    struct SocksReply {
        status: u8,
        bound_target: Option<NetworkTarget>,
    }

    async fn start_network_proxy(authentication: SocksAuthentication) -> NetworkProxyHarness {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socks_address = listener.local_addr().unwrap();
        let (operator_io, client_io) = duplex(WEBSOCKET_TRANSPORT_BYTES);
        let operator_websocket =
            WebSocketStream::from_raw_socket(operator_io, Role::Server, None).await;
        let client_websocket =
            WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
        let client_task = tokio::spawn(async move {
            run_client_network_session(client_websocket, OfferedSession::Socks {}).await
        });
        let operator_task = tokio::spawn(async move {
            run_operator_network_proxy_with_listener(operator_websocket, listener, authentication)
                .await
        });
        NetworkProxyHarness {
            socks_address,
            operator_task,
            client_task,
        }
    }

    async fn authenticate_username_password(
        stream: &mut TcpStream,
        username: &str,
        password: &str,
    ) -> bool {
        stream
            .write_all(&[
                SOCKS_VERSION,
                2,
                SOCKS_AUTH_NONE,
                SOCKS_AUTH_USERNAME_PASSWORD,
            ])
            .await
            .unwrap();
        let mut method = [0_u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, SOCKS_AUTH_USERNAME_PASSWORD]);

        let username_length = u8::try_from(username.len()).unwrap();
        let password_length = u8::try_from(password.len()).unwrap();
        let mut credentials = Vec::with_capacity(username.len() + password.len() + 3);
        credentials.extend_from_slice(&[1, username_length]);
        credentials.extend_from_slice(username.as_bytes());
        credentials.push(password_length);
        credentials.extend_from_slice(password.as_bytes());
        stream.write_all(&credentials).await.unwrap();

        let mut result = [0_u8; 2];
        stream.read_exact(&mut result).await.unwrap();
        assert_eq!(result[0], 1);
        result[1] == 0
    }

    async fn authenticate_without_credentials(stream: &mut TcpStream) {
        stream
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_NONE])
            .await
            .unwrap();
        let mut method = [0_u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, SOCKS_AUTH_NONE]);
    }

    async fn request_socks_command(
        stream: &mut TcpStream,
        command: u8,
        target: &NetworkTarget,
    ) -> SocksReply {
        let mut request = vec![SOCKS_VERSION, command, 0];
        encode_socks_target(target, &mut request).unwrap();
        stream.write_all(&request).await.unwrap();
        read_socks_reply(stream).await
    }

    async fn read_socks_reply(stream: &mut TcpStream) -> SocksReply {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], SOCKS_VERSION);
        assert_eq!(header[2], 0);

        let mut encoded_target = vec![header[3]];
        match header[3] {
            SOCKS_ATYP_IPV4 => {
                let mut tail = [0_u8; 6];
                stream.read_exact(&mut tail).await.unwrap();
                encoded_target.extend_from_slice(&tail);
            }
            SOCKS_ATYP_IPV6 => {
                let mut tail = [0_u8; 18];
                stream.read_exact(&mut tail).await.unwrap();
                encoded_target.extend_from_slice(&tail);
            }
            SOCKS_ATYP_DOMAIN_NAME => {
                let mut length = [0_u8; 1];
                stream.read_exact(&mut length).await.unwrap();
                encoded_target.push(length[0]);
                let mut tail = vec![0_u8; usize::from(length[0]) + 2];
                stream.read_exact(&mut tail).await.unwrap();
                encoded_target.extend_from_slice(&tail);
            }
            address_type => panic!("unexpected SOCKS reply address type {address_type}"),
        }
        let port = u16::from_be_bytes(
            encoded_target[encoded_target.len() - 2..]
                .try_into()
                .unwrap(),
        );
        let bound_target = if port == 0 {
            None
        } else {
            let (target, consumed) = decode_socks_target(&encoded_target).unwrap();
            assert_eq!(consumed, encoded_target.len());
            Some(target)
        };
        SocksReply {
            status: header[1],
            bound_target,
        }
    }

    async fn open_authenticated_tcp_flow(
        socks_address: SocketAddr,
        destination_port: u16,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(socks_address).await.unwrap();
        assert!(authenticate_username_password(&mut stream, "operator", "session-secret").await);
        let target = NetworkTarget::new("localhost", destination_port).unwrap();
        let reply = request_socks_command(&mut stream, SOCKS_CMD_CONNECT, &target).await;
        assert_eq!(reply.status, SOCKS_REPLY_SUCCESS);
        stream
    }

    async fn spawn_tcp_echo_endpoint(greeting: &'static [u8]) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(greeting).await.unwrap();
            let mut buffer = [0_u8; 4096];
            loop {
                let received = stream.read(&mut buffer).await.unwrap();
                if received == 0 {
                    return;
                }
                stream.write_all(&buffer[..received]).await.unwrap();
            }
        });
        (address, task)
    }

    async fn spawn_udp_echo_endpoint() -> (SocketAddr, JoinHandle<()>) {
        spawn_udp_echo_endpoint_for(1).await
    }

    async fn spawn_udp_echo_endpoint_for(
        expected_datagrams: usize,
    ) -> (SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut packet = [0_u8; 4096];
            for _ in 0..expected_datagrams {
                let (received, peer) = socket.recv_from(&mut packet).await.unwrap();
                let sent = socket.send_to(&packet[..received], peer).await.unwrap();
                assert_eq!(sent, received);
            }
        });
        (address, task)
    }

    async fn spawn_localhost_udp_echo_endpoint() -> (SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind(("localhost", 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut packet = [0_u8; 4096];
            let (received, peer) = socket.recv_from(&mut packet).await.unwrap();
            let sent = socket.send_to(&packet[..received], peer).await.unwrap();
            assert_eq!(sent, received);
        });
        (address, task)
    }

    async fn send_and_receive_udp(
        socket: &UdpSocket,
        relay_address: SocketAddr,
        request_target: NetworkTarget,
        response_peer: SocketAddr,
        payload: &'static [u8],
    ) {
        let request = encode_socks_udp_datagram(&SocksUdpDatagram {
            target: request_target,
            data: Bytes::from_static(payload),
        })
        .unwrap();
        let sent = socket.send_to(&request, relay_address).await.unwrap();
        assert_eq!(sent, request.len());

        let mut response = vec![0_u8; 65_535];
        let (received, source) = socket.recv_from(&mut response).await.unwrap();
        assert_eq!(source, relay_address);
        let response = decode_socks_udp_datagram(&response[..received]).unwrap();
        assert_eq!(response.target, NetworkTarget::from(response_peer));
        assert_eq!(response.data, Bytes::from_static(payload));
    }

    async fn wait_for_udp_relay_release(address: SocketAddr) -> UdpSocket {
        tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, async {
            loop {
                match UdpSocket::bind(address).await {
                    Ok(socket) => return socket,
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("failed while waiting for UDP relay release: {error}"),
                }
            }
        })
        .await
        .expect("SOCKS UDP relay remained bound after its control connection closed")
    }

    async fn join_endpoint(task: JoinHandle<()>) {
        tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, task)
            .await
            .expect("egress endpoint did not finish")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_target_expiry_tracks_the_earliest_idle_deadline() {
        let now = tokio::time::Instant::now();
        let idle_timeout = Duration::from_millis(50);
        let expiry = next_udp_target_expiry(
            [now + Duration::from_millis(20), now].into_iter(),
            idle_timeout,
        )
        .unwrap();
        assert_eq!(expiry, now + idle_timeout);
        tokio::time::timeout(
            Duration::from_millis(250),
            wait_for_udp_target_expiry(Some(expiry)),
        )
        .await
        .expect("earliest SOCKS UDP idle deadline did not wake the target tracker");
        assert!(next_udp_target_expiry(std::iter::empty(), idle_timeout).is_none());
    }

    #[tokio::test]
    async fn socks_listener_bounds_connections_before_network_flow_admission() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let proxy = start_network_proxy(SocksAuthentication::None).await;
            let mut active_connections = Vec::with_capacity(NETWORK_SESSION_FLOW_LIMIT);
            for _ in 0..NETWORK_SESSION_FLOW_LIMIT {
                let mut stream = TcpStream::connect(proxy.socks_address).await.unwrap();
                authenticate_without_credentials(&mut stream).await;
                active_connections.push(stream);
            }

            let mut waiting_connection = TcpStream::connect(proxy.socks_address).await.unwrap();
            waiting_connection
                .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_NONE])
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(250), waiting_connection.readable(),)
                    .await
                    .is_err(),
                "SOCKS listener admitted a connection beyond its task limit"
            );

            drop(active_connections.pop());
            let mut method = [0_u8; 2];
            tokio::time::timeout(
                TASK_SHUTDOWN_TIMEOUT,
                waiting_connection.read_exact(&mut method),
            )
            .await
            .expect("SOCKS listener did not admit a waiting connection after capacity returned")
            .unwrap();
            assert_eq!(method, [SOCKS_VERSION, SOCKS_AUTH_NONE]);
            drop(active_connections);
            drop(waiting_connection);
            drop(proxy);
        })
        .await
        .expect("bounded SOCKS listener integration test timed out");
    }

    #[tokio::test]
    async fn authenticated_domain_connects_are_isolated_over_one_websocket_session() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (first_endpoint, first_endpoint_task) =
                spawn_tcp_echo_endpoint(b"first-egress").await;
            let (second_endpoint, second_endpoint_task) =
                spawn_tcp_echo_endpoint(b"second-egress").await;
            let proxy = start_network_proxy(SocksAuthentication::UsernamePassword {
                username: "operator".to_string(),
                password: "session-secret".to_string(),
            })
            .await;

            let (mut first_flow, mut second_flow) = tokio::join!(
                open_authenticated_tcp_flow(proxy.socks_address, first_endpoint.port()),
                open_authenticated_tcp_flow(proxy.socks_address, second_endpoint.port()),
            );

            let mut rejected_flow = TcpStream::connect(proxy.socks_address).await.unwrap();
            assert!(
                !authenticate_username_password(&mut rejected_flow, "operator", "wrong-secret")
                    .await
            );
            let mut rejected_byte = [0_u8; 1];
            assert_eq!(rejected_flow.read(&mut rejected_byte).await.unwrap(), 0);

            let mut first_greeting = [0_u8; 12];
            let mut second_greeting = [0_u8; 13];
            first_flow.read_exact(&mut first_greeting).await.unwrap();
            second_flow.read_exact(&mut second_greeting).await.unwrap();
            assert_eq!(&first_greeting, b"first-egress");
            assert_eq!(&second_greeting, b"second-egress");

            first_flow.write_all(b"first-payload").await.unwrap();
            second_flow.write_all(b"second-payload").await.unwrap();
            let mut first_response = [0_u8; 13];
            let mut second_response = [0_u8; 14];
            first_flow.read_exact(&mut first_response).await.unwrap();
            second_flow.read_exact(&mut second_response).await.unwrap();
            assert_eq!(&first_response, b"first-payload");
            assert_eq!(&second_response, b"second-payload");

            drop(first_flow);
            drop(second_flow);
            join_endpoint(first_endpoint_task).await;
            join_endpoint(second_endpoint_task).await;
            drop(proxy);
        })
        .await
        .expect("authenticated SOCKS TCP integration test timed out");
    }

    #[tokio::test]
    async fn udp_associate_round_trips_each_target_and_ends_with_its_control_connection() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (first_endpoint, first_endpoint_task) = spawn_localhost_udp_echo_endpoint().await;
            let (second_endpoint, second_endpoint_task) = spawn_udp_echo_endpoint().await;
            let proxy = start_network_proxy(SocksAuthentication::None).await;
            let mut control = TcpStream::connect(proxy.socks_address).await.unwrap();
            authenticate_without_credentials(&mut control).await;
            let unspecified_target =
                NetworkTarget::new(Ipv4Addr::UNSPECIFIED.to_string(), 1).unwrap();
            let reply =
                request_socks_command(&mut control, SOCKS_CMD_UDP_ASSOCIATE, &unspecified_target)
                    .await;
            assert_eq!(reply.status, SOCKS_REPLY_SUCCESS);
            let bound_target = reply.bound_target.unwrap();
            let relay_address = SocketAddr::new(
                bound_target.host.parse::<IpAddr>().unwrap(),
                bound_target.port,
            );
            let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

            send_and_receive_udp(
                &udp_client,
                relay_address,
                NetworkTarget::new("localhost", first_endpoint.port()).unwrap(),
                first_endpoint,
                b"first-datagram",
            )
            .await;
            send_and_receive_udp(
                &udp_client,
                relay_address,
                NetworkTarget::from(second_endpoint),
                second_endpoint,
                b"second-datagram",
            )
            .await;
            join_endpoint(first_endpoint_task).await;
            join_endpoint(second_endpoint_task).await;

            drop(control);
            let replacement_relay = wait_for_udp_relay_release(relay_address).await;
            drop(replacement_relay);
            drop(proxy);
        })
        .await
        .expect("SOCKS UDP integration test timed out");
    }

    #[tokio::test]
    async fn udp_associate_preserves_fifo_without_a_busy_target_starving_others() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let busy_datagrams = MAX_SOCKS_UDP_QUEUED_DATAGRAMS_PER_TARGET;
            let (busy_endpoint, busy_endpoint_task) =
                spawn_udp_echo_endpoint_for(busy_datagrams).await;
            let (quiet_endpoint, quiet_endpoint_task) = spawn_udp_echo_endpoint().await;
            let proxy = start_network_proxy(SocksAuthentication::None).await;
            let mut control = TcpStream::connect(proxy.socks_address).await.unwrap();
            authenticate_without_credentials(&mut control).await;
            let unspecified_target =
                NetworkTarget::new(Ipv4Addr::UNSPECIFIED.to_string(), 1).unwrap();
            let reply =
                request_socks_command(&mut control, SOCKS_CMD_UDP_ASSOCIATE, &unspecified_target)
                    .await;
            assert_eq!(reply.status, SOCKS_REPLY_SUCCESS);
            let bound_target = reply.bound_target.unwrap();
            let relay_address = SocketAddr::new(
                bound_target.host.parse::<IpAddr>().unwrap(),
                bound_target.port,
            );
            let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

            for sequence in 0..busy_datagrams {
                let request = encode_socks_udp_datagram(&SocksUdpDatagram {
                    target: NetworkTarget::from(busy_endpoint),
                    data: Bytes::from(vec![u8::try_from(sequence).unwrap()]),
                })
                .unwrap();
                assert_eq!(
                    udp_client.send_to(&request, relay_address).await.unwrap(),
                    request.len()
                );
            }
            let quiet_request = encode_socks_udp_datagram(&SocksUdpDatagram {
                target: NetworkTarget::from(quiet_endpoint),
                data: Bytes::from_static(b"quiet"),
            })
            .unwrap();
            assert_eq!(
                udp_client
                    .send_to(&quiet_request, relay_address)
                    .await
                    .unwrap(),
                quiet_request.len()
            );

            let mut next_busy_sequence = 0;
            let mut received_quiet = false;
            let mut packet = vec![0_u8; MAX_SOCKS_UDP_PACKET_BYTES];
            for _ in 0..=busy_datagrams {
                let (size, source) = udp_client.recv_from(&mut packet).await.unwrap();
                assert_eq!(source, relay_address);
                let response = decode_socks_udp_datagram(&packet[..size]).unwrap();
                if response.target == NetworkTarget::from(busy_endpoint) {
                    assert_eq!(
                        response.data,
                        Bytes::from(vec![u8::try_from(next_busy_sequence).unwrap()])
                    );
                    next_busy_sequence += 1;
                } else {
                    assert_eq!(response.target, NetworkTarget::from(quiet_endpoint));
                    assert_eq!(response.data, Bytes::from_static(b"quiet"));
                    assert!(!received_quiet);
                    received_quiet = true;
                }
            }
            assert_eq!(next_busy_sequence, busy_datagrams);
            assert!(received_quiet);

            join_endpoint(busy_endpoint_task).await;
            join_endpoint(quiet_endpoint_task).await;
            drop(control);
            drop(proxy);
        })
        .await
        .expect("fair SOCKS UDP integration test timed out");
    }
}
