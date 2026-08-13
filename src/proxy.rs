use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

use crate::debug::debug_log;
use crate::socks::{
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCESS, SocksAuthentication, SocksRequest,
    SocksTarget, SocksUdpDatagram, decode_socks_target, decode_socks_udp_datagram,
    encode_socks_target, encode_socks_udp_datagram, negotiate_socks5_network,
    write_socks5_response,
};

const PACKET_OPEN_TCP: u8 = 0x01;
const PACKET_OPENED: u8 = 0x02;
const PACKET_OPEN_FAILED: u8 = 0x03;
const PACKET_DATA: u8 = 0x04;
const PACKET_EOF: u8 = 0x05;
const PACKET_CLOSE: u8 = 0x06;
const PACKET_OPEN_UDP: u8 = 0x07;
const PACKET_DATAGRAM: u8 = 0x08;
const PACKET_HEADER_BYTES: usize = 9;
const MAX_OPEN_FAILURE_BYTES: usize = 4096;
const TCP_IO_CHUNK_BYTES: usize = 32 * 1024;
const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;
const MAX_SOCKS_UDP_PACKET_BYTES: usize = 65_507;
const OUTGOING_QUEUE_CAPACITY: usize = 256;
const FLOW_QUEUE_CAPACITY: usize = 32;
const UDP_RECEIVE_QUEUE_CAPACITY: usize = 64;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Eq, PartialEq)]
enum TunnelPacket {
    OpenTcp {
        flow_id: u64,
        target: SocksTarget,
    },
    OpenUdp {
        flow_id: u64,
    },
    Opened {
        flow_id: u64,
    },
    OpenFailed {
        flow_id: u64,
        message: String,
    },
    Data {
        flow_id: u64,
        data: Bytes,
    },
    Datagram {
        flow_id: u64,
        target: SocksTarget,
        data: Bytes,
    },
    Eof {
        flow_id: u64,
    },
    Close {
        flow_id: u64,
    },
}

impl TunnelPacket {
    fn flow_id(&self) -> u64 {
        match self {
            Self::OpenTcp { flow_id, .. }
            | Self::OpenUdp { flow_id }
            | Self::Opened { flow_id }
            | Self::OpenFailed { flow_id, .. }
            | Self::Data { flow_id, .. }
            | Self::Datagram { flow_id, .. }
            | Self::Eof { flow_id }
            | Self::Close { flow_id } => *flow_id,
        }
    }

    fn encode(self) -> Result<Bytes> {
        let (packet_type, flow_id, payload) = match self {
            Self::OpenTcp { flow_id, target } => {
                let mut payload = Vec::with_capacity(19);
                encode_socks_target(&target, &mut payload)?;
                (PACKET_OPEN_TCP, flow_id, payload)
            }
            Self::OpenUdp { flow_id } => (PACKET_OPEN_UDP, flow_id, Vec::new()),
            Self::Opened { flow_id } => (PACKET_OPENED, flow_id, Vec::new()),
            Self::OpenFailed { flow_id, message } => {
                if message.len() > MAX_OPEN_FAILURE_BYTES {
                    bail!("tunnel open failure message is too large");
                }
                (PACKET_OPEN_FAILED, flow_id, message.into_bytes())
            }
            Self::Data { flow_id, data } => {
                if data.len() > TCP_IO_CHUNK_BYTES {
                    bail!("tunnel TCP data packet is too large");
                }
                (PACKET_DATA, flow_id, data.to_vec())
            }
            Self::Datagram {
                flow_id,
                target,
                data,
            } => {
                if data.len() > MAX_UDP_DATAGRAM_BYTES {
                    bail!("tunnel UDP datagram is too large");
                }
                let mut payload = Vec::with_capacity(19 + data.len());
                encode_socks_target(&target, &mut payload)?;
                payload.extend_from_slice(&data);
                (PACKET_DATAGRAM, flow_id, payload)
            }
            Self::Eof { flow_id } => (PACKET_EOF, flow_id, Vec::new()),
            Self::Close { flow_id } => (PACKET_CLOSE, flow_id, Vec::new()),
        };
        if flow_id == 0 {
            bail!("tunnel flow ID must not be zero");
        }
        let mut encoded = Vec::with_capacity(PACKET_HEADER_BYTES + payload.len());
        encoded.push(packet_type);
        encoded.extend_from_slice(&flow_id.to_be_bytes());
        encoded.extend_from_slice(&payload);
        Ok(Bytes::from(encoded))
    }

    fn decode(bytes: Bytes) -> Result<Self> {
        if bytes.len() < PACKET_HEADER_BYTES {
            bail!("tunnel packet is shorter than its header");
        }
        let packet_type = bytes[0];
        let flow_id = u64::from_be_bytes(
            bytes[1..PACKET_HEADER_BYTES]
                .try_into()
                .map_err(|_| anyhow!("failed to decode tunnel flow ID"))?,
        );
        if flow_id == 0 {
            bail!("tunnel flow ID must not be zero");
        }
        let payload = bytes.slice(PACKET_HEADER_BYTES..);
        match packet_type {
            PACKET_OPEN_TCP => {
                let (target, consumed) = decode_socks_target(&payload)?;
                if consumed != payload.len() {
                    bail!("tunnel TCP open packet has trailing data");
                }
                Ok(Self::OpenTcp { flow_id, target })
            }
            PACKET_OPEN_UDP => {
                require_empty_payload(packet_type, &payload)?;
                Ok(Self::OpenUdp { flow_id })
            }
            PACKET_OPENED => {
                require_empty_payload(packet_type, &payload)?;
                Ok(Self::Opened { flow_id })
            }
            PACKET_OPEN_FAILED => {
                if payload.len() > MAX_OPEN_FAILURE_BYTES {
                    bail!("tunnel open failure message is too large");
                }
                let message = String::from_utf8(payload.to_vec())
                    .context("tunnel open failure message is not valid UTF-8")?;
                Ok(Self::OpenFailed { flow_id, message })
            }
            PACKET_DATA => {
                if payload.len() > TCP_IO_CHUNK_BYTES {
                    bail!("tunnel TCP data packet is too large");
                }
                Ok(Self::Data {
                    flow_id,
                    data: payload,
                })
            }
            PACKET_DATAGRAM => {
                let (target, target_bytes) = decode_socks_target(&payload)?;
                let data = payload.slice(target_bytes..);
                if data.len() > MAX_UDP_DATAGRAM_BYTES {
                    bail!("tunnel UDP datagram is too large");
                }
                Ok(Self::Datagram {
                    flow_id,
                    target,
                    data,
                })
            }
            PACKET_EOF => {
                require_empty_payload(packet_type, &payload)?;
                Ok(Self::Eof { flow_id })
            }
            PACKET_CLOSE => {
                require_empty_payload(packet_type, &payload)?;
                Ok(Self::Close { flow_id })
            }
            _ => bail!("unsupported tunnel packet type {packet_type}"),
        }
    }
}

enum OutgoingMessage {
    Packet(TunnelPacket),
    Ping,
    Pong(Bytes),
}

enum IncomingMessage {
    Packet(TunnelPacket),
    Control,
    Closed,
}

struct ReceivedUdpDatagram {
    source: SocketAddr,
    data: Bytes,
}

type FlowResult = (u64, Result<()>);

pub async fn run_operator_socks_proxy<S>(
    websocket: WebSocketStream<S>,
    listen_addr: SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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

pub async fn run_client_network_proxy<S>(websocket: WebSocketStream<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, mut stream) = websocket.split();
    let (outgoing_sender, outgoing_receiver) = mpsc::channel(OUTGOING_QUEUE_CAPACITY);
    let (writer_task, mut writer_result_receiver) = spawn_websocket_writer(sink, outgoing_receiver);
    let mut flow_senders = HashMap::<u64, mpsc::Sender<TunnelPacket>>::new();
    let mut flows = JoinSet::<FlowResult>::new();
    let mut keepalive = keepalive_interval();

    let session_result = loop {
        tokio::select! {
            maybe_message = stream.next() => {
                match receive_tunnel_packet(maybe_message, &outgoing_sender).await {
                    Ok(IncomingMessage::Packet(TunnelPacket::OpenTcp { flow_id, target })) => {
                        if flow_senders.contains_key(&flow_id) {
                            break Err(anyhow!("client received duplicate tunnel flow ID {flow_id}"));
                        }
                        let (flow_sender, flow_receiver) = mpsc::channel(FLOW_QUEUE_CAPACITY);
                        flow_senders.insert(flow_id, flow_sender);
                        let task_sender = outgoing_sender.clone();
                        flows.spawn(async move {
                            let result = run_client_tcp_flow(
                                flow_id,
                                target,
                                flow_receiver,
                                task_sender.clone(),
                            )
                            .await;
                            report_finished_flow(flow_id, &task_sender).await;
                            (flow_id, result)
                        });
                    }
                    Ok(IncomingMessage::Packet(TunnelPacket::OpenUdp { flow_id })) => {
                        if flow_senders.contains_key(&flow_id) {
                            break Err(anyhow!("client received duplicate tunnel flow ID {flow_id}"));
                        }
                        let (flow_sender, flow_receiver) = mpsc::channel(FLOW_QUEUE_CAPACITY);
                        flow_senders.insert(flow_id, flow_sender);
                        let task_sender = outgoing_sender.clone();
                        flows.spawn(async move {
                            let result = run_client_udp_flow(
                                flow_id,
                                flow_receiver,
                                task_sender.clone(),
                            )
                            .await;
                            report_finished_flow(flow_id, &task_sender).await;
                            (flow_id, result)
                        });
                    }
                    Ok(IncomingMessage::Packet(packet)) => {
                        if matches!(packet, TunnelPacket::Opened { .. } | TunnelPacket::OpenFailed { .. }) {
                            break Err(anyhow!("client received an operator-only tunnel packet"));
                        }
                        dispatch_flow_packet(packet, &mut flow_senders).await;
                    }
                    Ok(IncomingMessage::Control) => {}
                    Ok(IncomingMessage::Closed) => break Ok(()),
                    Err(error) => break Err(error),
                }
            }
            maybe_result = flows.join_next(), if !flows.is_empty() => {
                if let Err(error) = handle_flow_completion(maybe_result, &mut flow_senders) {
                    break Err(error);
                }
            }
            writer_result = &mut writer_result_receiver => {
                break match writer_result {
                    Ok(result) => result,
                    Err(error) => Err(error).context(
                        "network tunnel writer stopped without reporting a result"
                    ),
                };
            }
            _ = keepalive.tick() => {
                if outgoing_sender.send(OutgoingMessage::Ping).await.is_err() {
                    break Err(anyhow!("network tunnel writer is no longer available"));
                }
            }
        }
    };

    stop_session(flows, outgoing_sender, writer_task).await;
    session_result
}

pub(crate) async fn run_operator_network_proxy_with_listener<S>(
    websocket: WebSocketStream<S>,
    listener: TcpListener,
    authentication: SocksAuthentication,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, mut stream) = websocket.split();
    let (outgoing_sender, outgoing_receiver) = mpsc::channel(OUTGOING_QUEUE_CAPACITY);
    let (writer_task, mut writer_result_receiver) = spawn_websocket_writer(sink, outgoing_receiver);
    let mut flow_senders = HashMap::<u64, mpsc::Sender<TunnelPacket>>::new();
    let mut flows = JoinSet::<FlowResult>::new();
    let mut next_flow_id = 1_u64;
    let mut keepalive = keepalive_interval();

    let session_result = loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, remote_addr) = match accept_result {
                    Ok(parts) => parts,
                    Err(error) => break Err(error).context("failed to accept SOCKS5 connection"),
                };
                let flow_id = next_flow_id;
                next_flow_id = match next_flow_id.checked_add(1) {
                    Some(next_flow_id) => next_flow_id,
                    None => break Err(anyhow!("network tunnel exhausted its flow IDs")),
                };
                let (flow_sender, flow_receiver) = mpsc::channel(FLOW_QUEUE_CAPACITY);
                flow_senders.insert(flow_id, flow_sender);
                debug_log(format!("accepted SOCKS client {remote_addr} as flow {flow_id}"));
                let task_sender = outgoing_sender.clone();
                let flow_authentication = authentication.clone();
                flows.spawn(async move {
                    let result = run_operator_flow(
                        flow_id,
                        socket,
                        flow_receiver,
                        task_sender.clone(),
                        flow_authentication,
                    )
                    .await;
                    report_finished_flow(flow_id, &task_sender).await;
                    (flow_id, result)
                });
            }
            maybe_message = stream.next() => {
                match receive_tunnel_packet(maybe_message, &outgoing_sender).await {
                    Ok(IncomingMessage::Packet(TunnelPacket::OpenTcp { .. } | TunnelPacket::OpenUdp { .. })) => {
                        break Err(anyhow!("operator received a client-only tunnel open packet"));
                    }
                    Ok(IncomingMessage::Packet(packet)) => {
                        dispatch_flow_packet(packet, &mut flow_senders).await;
                    }
                    Ok(IncomingMessage::Control) => {}
                    Ok(IncomingMessage::Closed) => break Ok(()),
                    Err(error) => break Err(error),
                }
            }
            maybe_result = flows.join_next(), if !flows.is_empty() => {
                if let Err(error) = handle_flow_completion(maybe_result, &mut flow_senders) {
                    break Err(error);
                }
            }
            writer_result = &mut writer_result_receiver => {
                break match writer_result {
                    Ok(result) => result,
                    Err(error) => Err(error).context(
                        "network tunnel writer stopped without reporting a result"
                    ),
                };
            }
            _ = keepalive.tick() => {
                if outgoing_sender.send(OutgoingMessage::Ping).await.is_err() {
                    break Err(anyhow!("network tunnel writer is no longer available"));
                }
            }
        }
    };

    stop_session(flows, outgoing_sender, writer_task).await;
    session_result
}

async fn run_operator_flow(
    flow_id: u64,
    mut socket: TcpStream,
    incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
    authentication: SocksAuthentication,
) -> Result<()> {
    match negotiate_socks5_network(&mut socket, &authentication).await? {
        SocksRequest::Connect(target) => {
            run_operator_tcp_flow(flow_id, socket, target, incoming, outgoing).await
        }
        SocksRequest::UdpAssociate => {
            run_operator_udp_flow(flow_id, socket, incoming, outgoing).await
        }
    }
}

async fn run_operator_tcp_flow(
    flow_id: u64,
    mut socket: TcpStream,
    target: SocksTarget,
    mut incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    outgoing
        .send(OutgoingMessage::Packet(TunnelPacket::OpenTcp {
            flow_id,
            target: target.clone(),
        }))
        .await
        .map_err(|_| anyhow!("network tunnel closed before the TCP destination could be opened"))?;

    match incoming.recv().await {
        Some(TunnelPacket::Opened { flow_id: opened_id }) if opened_id == flow_id => {
            write_socks5_response(&mut socket, SOCKS_REPLY_SUCCESS, None).await?;
        }
        Some(TunnelPacket::OpenFailed {
            flow_id: failed_id,
            message,
        }) if failed_id == flow_id => {
            write_socks5_response(&mut socket, SOCKS_REPLY_GENERAL_FAILURE, None).await?;
            bail!(
                "client failed to open SOCKS destination {}:{}: {message}",
                target.host,
                target.port
            );
        }
        Some(unexpected) => {
            bail!("received {unexpected:?} before the tunnel open result for flow {flow_id}");
        }
        None => bail!("network tunnel closed while opening flow {flow_id}"),
    }

    bridge_tcp_stream(flow_id, socket, incoming, outgoing).await
}

async fn run_operator_udp_flow(
    flow_id: u64,
    mut control: TcpStream,
    mut incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    let control_peer = control
        .peer_addr()
        .context("failed to read SOCKS UDP control peer address")?;
    let control_local = control
        .local_addr()
        .context("failed to read SOCKS UDP control listener address")?;
    let relay_bind = ephemeral_port(control_local);
    let relay = UdpSocket::bind(relay_bind)
        .await
        .with_context(|| format!("failed to bind SOCKS UDP relay to {relay_bind}"))?;
    let relay_addr = relay
        .local_addr()
        .context("failed to read SOCKS UDP relay address")?;

    outgoing
        .send(OutgoingMessage::Packet(TunnelPacket::OpenUdp { flow_id }))
        .await
        .map_err(|_| anyhow!("network tunnel closed before the UDP association could be opened"))?;
    match incoming.recv().await {
        Some(TunnelPacket::Opened { flow_id: opened_id }) if opened_id == flow_id => {
            write_socks5_response(&mut control, SOCKS_REPLY_SUCCESS, Some(relay_addr)).await?;
        }
        Some(TunnelPacket::OpenFailed {
            flow_id: failed_id,
            message,
        }) if failed_id == flow_id => {
            write_socks5_response(&mut control, SOCKS_REPLY_GENERAL_FAILURE, None).await?;
            bail!("client failed to open UDP association: {message}");
        }
        Some(unexpected) => {
            bail!("received {unexpected:?} before the UDP open result for flow {flow_id}");
        }
        None => bail!("network tunnel closed while opening UDP flow {flow_id}"),
    }

    let mut relay_client = None::<SocketAddr>;
    let mut udp_buffer = BytesMut::zeroed(MAX_SOCKS_UDP_PACKET_BYTES);
    let mut control_buffer = [0_u8; 1];
    loop {
        tokio::select! {
            read_result = control.read(&mut control_buffer) => {
                let bytes_read = read_result.context("failed to read SOCKS UDP control connection")?;
                if bytes_read == 0 {
                    return Ok(());
                }
                bail!("received unexpected data on SOCKS UDP control connection");
            }
            receive_result = relay.recv_from(&mut udp_buffer) => {
                let (bytes_read, source) = receive_result.context("failed to receive SOCKS UDP datagram")?;
                if source.ip() != control_peer.ip() {
                    debug_log(format!(
                        "discarding SOCKS UDP datagram for flow {flow_id} from unexpected host {source}"
                    ));
                    continue;
                }
                match relay_client {
                    Some(expected) if expected != source => {
                        debug_log(format!(
                            "discarding SOCKS UDP datagram for flow {flow_id} from unexpected endpoint {source}"
                        ));
                        continue;
                    }
                    None => relay_client = Some(source),
                    Some(_) => {}
                }
                let packet = udp_buffer.split_to(bytes_read).freeze();
                udp_buffer.resize(MAX_SOCKS_UDP_PACKET_BYTES, 0);
                let datagram = match decode_socks_udp_datagram(packet) {
                    Ok(datagram) => datagram,
                    Err(error) => {
                        debug_log(format!("discarding invalid SOCKS UDP datagram on flow {flow_id}: {error:#}"));
                        continue;
                    }
                };
                outgoing
                    .send(OutgoingMessage::Packet(TunnelPacket::Datagram {
                        flow_id,
                        target: datagram.target,
                        data: datagram.data,
                    }))
                    .await
                    .map_err(|_| anyhow!("network tunnel closed while sending a UDP datagram"))?;
            }
            maybe_packet = incoming.recv() => {
                match maybe_packet {
                    Some(TunnelPacket::Datagram { target, data, .. }) => {
                        let Some(destination) = relay_client else {
                            debug_log(format!(
                                "discarding early UDP response for flow {flow_id} before the relay client is known"
                            ));
                            continue;
                        };
                        let packet = encode_socks_udp_datagram(&SocksUdpDatagram { target, data })?;
                        relay
                            .send_to(&packet, destination)
                            .await
                            .context("failed to send SOCKS UDP response")?;
                    }
                    Some(TunnelPacket::Close { .. }) => return Ok(()),
                    None => bail!("tunnel routing ended for UDP flow {flow_id}"),
                    Some(unexpected) => {
                        bail!("received unexpected packet while forwarding UDP flow {flow_id}: {unexpected:?}");
                    }
                }
            }
        }
    }
}

async fn run_client_tcp_flow(
    flow_id: u64,
    target: SocksTarget,
    incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    let socket = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(socket) => socket,
        Err(error) => {
            send_open_failure(flow_id, &error, &outgoing).await?;
            return Ok(());
        }
    };
    outgoing
        .send(OutgoingMessage::Packet(TunnelPacket::Opened { flow_id }))
        .await
        .map_err(|_| anyhow!("network tunnel closed while reporting an open TCP destination"))?;
    bridge_tcp_stream(flow_id, socket, incoming, outgoing).await
}

async fn run_client_udp_flow(
    flow_id: u64,
    mut incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    let ipv4_socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => Arc::new(socket),
        Err(error) => {
            send_open_failure(flow_id, &error, &outgoing).await?;
            return Ok(());
        }
    };
    let ipv6_socket = match UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => Some(Arc::new(socket)),
        Err(error) => {
            debug_log(format!(
                "IPv6 is unavailable for UDP flow {flow_id}; IPv4 remains active: {error}"
            ));
            None
        }
    };
    let (received_sender, mut received_receiver) = mpsc::channel(UDP_RECEIVE_QUEUE_CAPACITY);
    let mut readers = JoinSet::<Result<()>>::new();
    readers.spawn(receive_udp_datagrams(
        Arc::clone(&ipv4_socket),
        received_sender.clone(),
    ));
    if let Some(socket) = &ipv6_socket {
        readers.spawn(receive_udp_datagrams(
            Arc::clone(socket),
            received_sender.clone(),
        ));
    }
    drop(received_sender);

    outgoing
        .send(OutgoingMessage::Packet(TunnelPacket::Opened { flow_id }))
        .await
        .map_err(|_| anyhow!("network tunnel closed while reporting an open UDP association"))?;

    let result = loop {
        tokio::select! {
            maybe_packet = incoming.recv() => {
                match maybe_packet {
                    Some(TunnelPacket::Datagram { target, data, .. }) => {
                        if let Err(error) = send_client_udp_datagram(
                            &ipv4_socket,
                            ipv6_socket.as_deref(),
                            &target,
                            &data,
                        )
                        .await
                        {
                            debug_log(format!(
                                "failed to send UDP datagram for flow {flow_id} to {}:{}: {error:#}",
                                target.host, target.port
                            ));
                        }
                    }
                    Some(TunnelPacket::Close { .. }) => break Ok(()),
                    None => break Err(anyhow!("tunnel routing ended for UDP flow {flow_id}")),
                    Some(unexpected) => {
                        break Err(anyhow!(
                            "received unexpected packet while forwarding UDP flow {flow_id}: {unexpected:?}"
                        ));
                    }
                }
            }
            maybe_datagram = received_receiver.recv() => {
                let Some(datagram) = maybe_datagram else {
                    break Err(anyhow!("all UDP sockets stopped for flow {flow_id}"));
                };
                if outgoing
                    .send(OutgoingMessage::Packet(TunnelPacket::Datagram {
                        flow_id,
                        target: SocksTarget::from(datagram.source),
                        data: datagram.data,
                    }))
                    .await
                    .is_err()
                {
                    break Err(anyhow!("network tunnel closed while receiving a UDP datagram"));
                }
            }
            maybe_result = readers.join_next(), if !readers.is_empty() => {
                match maybe_result {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(error)) => break Err(error).context("UDP receive task failed to join"),
                    None => {}
                }
            }
        }
    };

    readers.abort_all();
    while readers.join_next().await.is_some() {}
    result
}

async fn receive_udp_datagrams(
    socket: Arc<UdpSocket>,
    sender: mpsc::Sender<ReceivedUdpDatagram>,
) -> Result<()> {
    let mut buffer = BytesMut::zeroed(MAX_UDP_DATAGRAM_BYTES);
    loop {
        let (bytes_read, source) = socket
            .recv_from(&mut buffer)
            .await
            .context("failed to receive UDP response from client network")?;
        let data = buffer.split_to(bytes_read).freeze();
        buffer.resize(MAX_UDP_DATAGRAM_BYTES, 0);
        if sender
            .send(ReceivedUdpDatagram { source, data })
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}

async fn send_client_udp_datagram(
    ipv4_socket: &UdpSocket,
    ipv6_socket: Option<&UdpSocket>,
    target: &SocksTarget,
    data: &[u8],
) -> Result<()> {
    let addresses = resolve_target(target).await?;
    let mut last_error = None::<std::io::Error>;
    for address in addresses {
        let socket = match address {
            SocketAddr::V4(_) => ipv4_socket,
            SocketAddr::V6(_) => {
                let Some(socket) = ipv6_socket else {
                    continue;
                };
                socket
            }
        };
        match socket.send_to(data, address).await {
            Ok(bytes_sent) if bytes_sent == data.len() => return Ok(()),
            Ok(bytes_sent) => {
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!("sent {bytes_sent} of {} UDP bytes", data.len()),
                ));
            }
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error).context("all resolved UDP destinations failed");
    }
    bail!(
        "destination {}:{} has no address supported by this client",
        target.host,
        target.port
    )
}

async fn resolve_target(target: &SocksTarget) -> Result<Vec<SocketAddr>> {
    if let Ok(address) = target.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, target.port)]);
    }
    let addresses = lookup_host((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("failed to resolve UDP destination {}", target.host))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        bail!("UDP destination {} resolved to no addresses", target.host);
    }
    Ok(addresses)
}

async fn send_open_failure(
    flow_id: u64,
    error: &std::io::Error,
    outgoing: &mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    let message = truncate_utf8(&error.to_string(), MAX_OPEN_FAILURE_BYTES);
    outgoing
        .send(OutgoingMessage::Packet(TunnelPacket::OpenFailed {
            flow_id,
            message,
        }))
        .await
        .map_err(|_| anyhow!("network tunnel closed while reporting an open failure"))
}

async fn report_finished_flow(flow_id: u64, outgoing: &mpsc::Sender<OutgoingMessage>) {
    let _ = outgoing
        .send(OutgoingMessage::Packet(TunnelPacket::Close { flow_id }))
        .await;
}

async fn bridge_tcp_stream(
    flow_id: u64,
    socket: TcpStream,
    mut incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    let (mut socket_reader, mut socket_writer) = socket.into_split();
    let mut read_buffer = BytesMut::zeroed(TCP_IO_CHUNK_BYTES);
    let mut socket_read_open = true;
    let mut tunnel_read_open = true;

    while socket_read_open || tunnel_read_open {
        tokio::select! {
            read_result = socket_reader.read(&mut read_buffer), if socket_read_open => {
                let bytes_read = read_result.context("failed to read tunneled TCP connection")?;
                if bytes_read == 0 {
                    socket_read_open = false;
                    outgoing
                        .send(OutgoingMessage::Packet(TunnelPacket::Eof { flow_id }))
                        .await
                        .map_err(|_| anyhow!("network tunnel closed while sending TCP EOF"))?;
                    continue;
                }
                let data = read_buffer.split_to(bytes_read).freeze();
                read_buffer.resize(TCP_IO_CHUNK_BYTES, 0);
                outgoing
                    .send(OutgoingMessage::Packet(TunnelPacket::Data { flow_id, data }))
                    .await
                    .map_err(|_| anyhow!("network tunnel closed while sending TCP data"))?;
            }
            maybe_packet = incoming.recv(), if tunnel_read_open => {
                match maybe_packet {
                    Some(TunnelPacket::Data { data, .. }) => {
                        socket_writer
                            .write_all(&data)
                            .await
                            .context("failed to write tunneled TCP connection")?;
                    }
                    Some(TunnelPacket::Eof { .. }) => {
                        tunnel_read_open = false;
                        socket_writer
                            .shutdown()
                            .await
                            .context("failed to shut down tunneled TCP connection")?;
                    }
                    Some(TunnelPacket::Close { .. }) => return Ok(()),
                    None => bail!("tunnel routing ended for TCP flow {flow_id}"),
                    Some(unexpected) => {
                        bail!("received unexpected packet while forwarding TCP flow {flow_id}: {unexpected:?}");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn receive_tunnel_packet(
    maybe_message: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    outgoing: &mpsc::Sender<OutgoingMessage>,
) -> Result<IncomingMessage> {
    let Some(message_result) = maybe_message else {
        return Ok(IncomingMessage::Closed);
    };
    match message_result.context("network tunnel WebSocket read failed")? {
        Message::Binary(bytes) => Ok(IncomingMessage::Packet(TunnelPacket::decode(bytes)?)),
        Message::Ping(payload) => {
            outgoing
                .send(OutgoingMessage::Pong(payload))
                .await
                .map_err(|_| anyhow!("network tunnel writer is no longer available"))?;
            Ok(IncomingMessage::Control)
        }
        Message::Pong(_) | Message::Frame(_) => Ok(IncomingMessage::Control),
        Message::Close(_) => Ok(IncomingMessage::Closed),
        Message::Text(_) => bail!("received a text frame during network tunnel transport"),
    }
}

async fn dispatch_flow_packet(
    packet: TunnelPacket,
    flow_senders: &mut HashMap<u64, mpsc::Sender<TunnelPacket>>,
) {
    let flow_id = packet.flow_id();
    let Some(sender) = flow_senders.get(&flow_id) else {
        debug_log(format!(
            "discarding packet for finished network tunnel flow {flow_id}"
        ));
        return;
    };
    match sender.try_send(packet) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            debug_log(format!("closing overloaded network tunnel flow {flow_id}"));
            flow_senders.remove(&flow_id);
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            flow_senders.remove(&flow_id);
        }
    }
}

fn handle_flow_completion(
    maybe_result: Option<Result<FlowResult, tokio::task::JoinError>>,
    flow_senders: &mut HashMap<u64, mpsc::Sender<TunnelPacket>>,
) -> Result<()> {
    let Some(join_result) = maybe_result else {
        return Ok(());
    };
    let (flow_id, result) = join_result.context("network flow task failed to join")?;
    flow_senders.remove(&flow_id);
    if let Err(error) = result {
        debug_log(format!("network tunnel flow {flow_id} failed: {error:#}"));
    }
    Ok(())
}

fn spawn_websocket_writer<S>(
    mut sink: SplitSink<WebSocketStream<S>, Message>,
    mut receiver: mpsc::Receiver<OutgoingMessage>,
) -> (JoinHandle<()>, oneshot::Receiver<Result<()>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (result_sender, result_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let result = async {
            while let Some(outgoing) = receiver.recv().await {
                let message = match outgoing {
                    OutgoingMessage::Packet(packet) => Message::Binary(packet.encode()?),
                    OutgoingMessage::Ping => Message::Ping(Bytes::new()),
                    OutgoingMessage::Pong(payload) => Message::Pong(payload),
                };
                sink.send(message)
                    .await
                    .context("failed to write network tunnel WebSocket")?;
            }
            Result::<(), anyhow::Error>::Ok(())
        }
        .await;
        let _ = result_sender.send(result);
    });
    (task, result_receiver)
}

async fn stop_session(
    mut flows: JoinSet<FlowResult>,
    outgoing_sender: mpsc::Sender<OutgoingMessage>,
    writer_task: JoinHandle<()>,
) {
    flows.abort_all();
    while flows.join_next().await.is_some() {}
    drop(outgoing_sender);
    writer_task.abort();
    let _ = writer_task.await;
}

fn keepalive_interval() -> tokio::time::Interval {
    let mut interval =
        tokio::time::interval_at(Instant::now() + KEEPALIVE_INTERVAL, KEEPALIVE_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

fn ephemeral_port(mut address: SocketAddr) -> SocketAddr {
    address.set_port(0);
    address
}

fn require_empty_payload(packet_type: u8, payload: &Bytes) -> Result<()> {
    if !payload.is_empty() {
        bail!("tunnel packet type {packet_type} must not contain a payload");
    }
    Ok(())
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6};
    use std::time::Duration;

    use anyhow::Result;
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio_tungstenite::{accept_async, connect_async};

    use crate::socks::{
        SOCKS_ATYP_DOMAIN_NAME, SOCKS_ATYP_IPV4, SOCKS_AUTH_NONE, SOCKS_AUTH_USERNAME_PASSWORD,
        SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_REPLY_SUCCESS, SOCKS_VERSION,
        SocksAuthentication, SocksTarget, SocksUdpDatagram, decode_socks_udp_datagram,
        encode_socks_udp_datagram,
    };

    use super::{
        TunnelPacket, ephemeral_port, run_client_network_proxy,
        run_operator_network_proxy_with_listener,
    };

    #[test]
    fn udp_relay_uses_the_control_socket_interface() {
        let ipv4: SocketAddr = "192.0.2.40:1080".parse().unwrap();
        let ipv6 = SocketAddr::V6(SocketAddrV6::new("fe80::40".parse().unwrap(), 1080, 7, 12));

        assert_eq!(ephemeral_port(ipv4), "192.0.2.40:0".parse().unwrap());
        assert_eq!(
            ephemeral_port(ipv6),
            SocketAddr::V6(SocketAddrV6::new("fe80::40".parse().unwrap(), 0, 7, 12))
        );
    }

    #[test]
    fn tunnel_packets_round_trip() {
        let packets = [
            TunnelPacket::OpenTcp {
                flow_id: 42,
                target: SocksTarget {
                    host: "service.client.internal".to_string(),
                    port: 443,
                },
            },
            TunnelPacket::OpenUdp { flow_id: 43 },
            TunnelPacket::Opened { flow_id: 44 },
            TunnelPacket::OpenFailed {
                flow_id: 45,
                message: "refused".to_string(),
            },
            TunnelPacket::Data {
                flow_id: 46,
                data: Bytes::from_static(b"stream"),
            },
            TunnelPacket::Datagram {
                flow_id: 47,
                target: SocksTarget {
                    host: "2001:db8::9".to_string(),
                    port: 53,
                },
                data: Bytes::from_static(b"datagram"),
            },
            TunnelPacket::Eof { flow_id: 48 },
            TunnelPacket::Close { flow_id: 49 },
        ];

        for expected in packets {
            let encoded = expected.clone().encode().unwrap();
            let actual = TunnelPacket::decode(encoded).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn network_proxy_routes_tcp_and_resolves_domains_on_the_client() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            socket.write_all(&request).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let (socks_addr, operator_task, client_task) = start_proxy_pair().await;

        let mut socks_stream = TcpStream::connect(socks_addr).await.unwrap();
        negotiate_no_auth(&mut socks_stream).await;
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
        let response = read_ipv4_socks_response(&mut socks_stream).await;
        assert_eq!(response[1], SOCKS_REPLY_SUCCESS);

        socks_stream
            .write_all(b"raw websocket tunnel")
            .await
            .unwrap();
        socks_stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            socks_stream.read_to_end(&mut echoed),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(echoed, b"raw websocket tunnel");

        echo_task.await.unwrap();
        stop_proxy_pair(operator_task, client_task).await;
    }

    #[tokio::test]
    async fn network_proxy_routes_socks5_udp_associations() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_addr = echo_socket.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            let (bytes_read, source) = echo_socket.recv_from(&mut buffer).await.unwrap();
            echo_socket
                .send_to(&buffer[..bytes_read], source)
                .await
                .unwrap();
        });
        let (socks_addr, operator_task, client_task) = start_proxy_pair().await;

        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        negotiate_no_auth(&mut control).await;
        control
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_CMD_UDP_ASSOCIATE,
                0,
                SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .unwrap();
        let response = read_ipv4_socks_response(&mut control).await;
        assert_eq!(response[1], SOCKS_REPLY_SUCCESS);
        let relay_addr = SocketAddr::from((
            Ipv4Addr::new(response[4], response[5], response[6], response[7]),
            u16::from_be_bytes([response[8], response[9]]),
        ));

        let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let request = encode_socks_udp_datagram(&SocksUdpDatagram {
            target: SocksTarget::from(echo_addr),
            data: Bytes::from_static(b"udp over websocket"),
        })
        .unwrap();
        udp_client.send_to(&request, relay_addr).await.unwrap();
        let mut response_buffer = vec![0_u8; 1024];
        let (bytes_read, source) = tokio::time::timeout(
            Duration::from_secs(5),
            udp_client.recv_from(&mut response_buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(source, relay_addr);
        let datagram =
            decode_socks_udp_datagram(Bytes::copy_from_slice(&response_buffer[..bytes_read]))
                .unwrap();
        assert_eq!(datagram.target, SocksTarget::from(echo_addr));
        assert_eq!(datagram.data, Bytes::from_static(b"udp over websocket"));

        drop(control);
        echo_task.await.unwrap();
        stop_proxy_pair(operator_task, client_task).await;
    }

    #[tokio::test]
    async fn private_network_proxy_authenticates_before_opening_tcp_flow() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            socket.write_all(&request).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let authentication = SocksAuthentication::UsernamePassword {
            username: "sshportal".to_string(),
            password: "private-session-secret".to_string(),
        };
        let (socks_addr, operator_task, client_task) =
            start_proxy_pair_with_authentication(authentication).await;

        let mut socks_stream = TcpStream::connect(socks_addr).await.unwrap();
        socks_stream
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_USERNAME_PASSWORD])
            .await
            .unwrap();
        let mut method = [0_u8; 2];
        socks_stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, SOCKS_AUTH_USERNAME_PASSWORD]);
        socks_stream
            .write_all(&[
                1, 9, b's', b's', b'h', b'p', b'o', b'r', b't', b'a', b'l', 22, b'p', b'r', b'i',
                b'v', b'a', b't', b'e', b'-', b's', b'e', b's', b's', b'i', b'o', b'n', b'-', b's',
                b'e', b'c', b'r', b'e', b't',
            ])
            .await
            .unwrap();
        let mut authentication_result = [0_u8; 2];
        socks_stream
            .read_exact(&mut authentication_result)
            .await
            .unwrap();
        assert_eq!(authentication_result, [1, 0]);

        let port = echo_addr.port().to_be_bytes();
        socks_stream
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_CMD_CONNECT,
                0,
                SOCKS_ATYP_IPV4,
                127,
                0,
                0,
                1,
                port[0],
                port[1],
            ])
            .await
            .unwrap();
        let response = read_ipv4_socks_response(&mut socks_stream).await;
        assert_eq!(response[1], SOCKS_REPLY_SUCCESS);

        socks_stream.write_all(b"private tunnel").await.unwrap();
        socks_stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        socks_stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"private tunnel");

        echo_task.await.unwrap();
        stop_proxy_pair(operator_task, client_task).await;
    }

    async fn start_proxy_pair() -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<()>>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        start_proxy_pair_with_authentication(SocksAuthentication::None).await
    }

    async fn start_proxy_pair_with_authentication(
        authentication: SocksAuthentication,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<()>>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let websocket_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let websocket_addr = websocket_listener.local_addr().unwrap();
        let operator_task = tokio::spawn(async move {
            let (socket, _) = websocket_listener.accept().await.unwrap();
            let websocket = accept_async(socket).await.unwrap();
            run_operator_network_proxy_with_listener(websocket, socks_listener, authentication)
                .await
        });
        let (client_websocket, _) = connect_async(format!("ws://{websocket_addr}"))
            .await
            .unwrap();
        let client_task = tokio::spawn(run_client_network_proxy(client_websocket));
        (socks_addr, operator_task, client_task)
    }

    async fn negotiate_no_auth(stream: &mut TcpStream) {
        stream
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_NONE])
            .await
            .unwrap();
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [SOCKS_VERSION, SOCKS_AUTH_NONE]);
    }

    async fn read_ipv4_socks_response(stream: &mut TcpStream) -> [u8; 10] {
        let mut response = [0_u8; 10];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], SOCKS_VERSION);
        assert_eq!(response[3], SOCKS_ATYP_IPV4);
        response
    }

    async fn stop_proxy_pair(
        operator_task: tokio::task::JoinHandle<Result<()>>,
        client_task: tokio::task::JoinHandle<Result<()>>,
    ) {
        operator_task.abort();
        client_task.abort();
        let _ = operator_task.await;
        let _ = client_task.await;
    }
}
