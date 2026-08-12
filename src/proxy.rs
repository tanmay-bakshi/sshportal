use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

use crate::debug::debug_log;
use crate::socks::{
    SOCKS_REPLY_GENERAL_FAILURE, SOCKS_REPLY_SUCCESS, SocksConnectTarget, negotiate_socks5,
    write_socks5_response,
};

const PACKET_OPEN: u8 = 0x01;
const PACKET_OPENED: u8 = 0x02;
const PACKET_OPEN_FAILED: u8 = 0x03;
const PACKET_DATA: u8 = 0x04;
const PACKET_EOF: u8 = 0x05;
const PACKET_CLOSE: u8 = 0x06;
const PACKET_HEADER_BYTES: usize = 9;
const OPEN_PORT_BYTES: usize = 2;
const MAX_OPEN_FAILURE_BYTES: usize = 4096;
const IO_CHUNK_BYTES: usize = 32 * 1024;
const OUTGOING_QUEUE_CAPACITY: usize = 256;
const CONNECTION_QUEUE_CAPACITY: usize = 32;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug)]
enum TunnelPacket {
    Open {
        stream_id: u64,
        target: SocksConnectTarget,
    },
    Opened {
        stream_id: u64,
    },
    OpenFailed {
        stream_id: u64,
        message: String,
    },
    Data {
        stream_id: u64,
        data: Bytes,
    },
    Eof {
        stream_id: u64,
    },
    Close {
        stream_id: u64,
    },
}

impl TunnelPacket {
    fn stream_id(&self) -> u64 {
        match self {
            Self::Open { stream_id, .. }
            | Self::Opened { stream_id }
            | Self::OpenFailed { stream_id, .. }
            | Self::Data { stream_id, .. }
            | Self::Eof { stream_id }
            | Self::Close { stream_id } => *stream_id,
        }
    }

    fn encode(self) -> Result<Bytes> {
        let (packet_type, stream_id, payload) = match self {
            Self::Open { stream_id, target } => {
                if target.host.is_empty() {
                    bail!("tunnel destination host must not be empty");
                }
                if target.host.len() > u8::MAX.into() {
                    bail!("tunnel destination host is too long");
                }
                let mut payload = Vec::with_capacity(OPEN_PORT_BYTES + target.host.len());
                payload.extend_from_slice(&target.port.to_be_bytes());
                payload.extend_from_slice(target.host.as_bytes());
                (PACKET_OPEN, stream_id, payload)
            }
            Self::Opened { stream_id } => (PACKET_OPENED, stream_id, Vec::new()),
            Self::OpenFailed { stream_id, message } => {
                if message.len() > MAX_OPEN_FAILURE_BYTES {
                    bail!("tunnel open failure message is too large");
                }
                (PACKET_OPEN_FAILED, stream_id, message.into_bytes())
            }
            Self::Data { stream_id, data } => {
                if data.len() > IO_CHUNK_BYTES {
                    bail!("tunnel data packet is too large");
                }
                (PACKET_DATA, stream_id, data.to_vec())
            }
            Self::Eof { stream_id } => (PACKET_EOF, stream_id, Vec::new()),
            Self::Close { stream_id } => (PACKET_CLOSE, stream_id, Vec::new()),
        };
        let mut encoded = Vec::with_capacity(PACKET_HEADER_BYTES + payload.len());
        encoded.push(packet_type);
        encoded.extend_from_slice(&stream_id.to_be_bytes());
        encoded.extend_from_slice(&payload);
        Ok(Bytes::from(encoded))
    }

    fn decode(bytes: Bytes) -> Result<Self> {
        if bytes.len() < PACKET_HEADER_BYTES {
            bail!("tunnel packet is shorter than its header");
        }
        let packet_type = bytes[0];
        let stream_id = u64::from_be_bytes(
            bytes[1..PACKET_HEADER_BYTES]
                .try_into()
                .map_err(|_| anyhow!("failed to decode tunnel stream ID"))?,
        );
        if stream_id == 0 {
            bail!("tunnel stream ID must not be zero");
        }
        let payload = bytes.slice(PACKET_HEADER_BYTES..);
        match packet_type {
            PACKET_OPEN => {
                if payload.len() <= OPEN_PORT_BYTES {
                    bail!("tunnel open packet is missing its destination");
                }
                let port = u16::from_be_bytes([payload[0], payload[1]]);
                let host = String::from_utf8(payload.slice(OPEN_PORT_BYTES..).to_vec())
                    .context("tunnel destination host is not valid UTF-8")?;
                if host.len() > u8::MAX.into() {
                    bail!("tunnel destination host is too long");
                }
                Ok(Self::Open {
                    stream_id,
                    target: SocksConnectTarget { host, port },
                })
            }
            PACKET_OPENED => {
                require_empty_payload(packet_type, &payload)?;
                Ok(Self::Opened { stream_id })
            }
            PACKET_OPEN_FAILED => {
                if payload.len() > MAX_OPEN_FAILURE_BYTES {
                    bail!("tunnel open failure message is too large");
                }
                let message = String::from_utf8(payload.to_vec())
                    .context("tunnel open failure message is not valid UTF-8")?;
                Ok(Self::OpenFailed { stream_id, message })
            }
            PACKET_DATA => {
                if payload.len() > IO_CHUNK_BYTES {
                    bail!("tunnel data packet is too large");
                }
                Ok(Self::Data {
                    stream_id,
                    data: payload,
                })
            }
            PACKET_EOF => {
                require_empty_payload(packet_type, &payload)?;
                Ok(Self::Eof { stream_id })
            }
            PACKET_CLOSE => {
                require_empty_payload(packet_type, &payload)?;
                Ok(Self::Close { stream_id })
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

type ConnectionResult = (u64, Result<()>);

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
    run_operator_socks_proxy_with_listener(websocket, listener).await
}

pub async fn run_client_socks_proxy<S>(websocket: WebSocketStream<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, mut stream) = websocket.split();
    let (outgoing_sender, outgoing_receiver) = mpsc::channel(OUTGOING_QUEUE_CAPACITY);
    let (writer_task, mut writer_result_receiver) = spawn_websocket_writer(sink, outgoing_receiver);
    let mut connection_senders = HashMap::<u64, mpsc::Sender<TunnelPacket>>::new();
    let mut connections = JoinSet::<ConnectionResult>::new();
    let mut keepalive = keepalive_interval();

    let session_result = loop {
        tokio::select! {
            maybe_message = stream.next() => {
                match receive_tunnel_packet(maybe_message, &outgoing_sender).await {
                    Ok(IncomingMessage::Packet(TunnelPacket::Open { stream_id, target })) => {
                        if connection_senders.contains_key(&stream_id) {
                            break Err(anyhow!("client received duplicate tunnel stream ID {stream_id}"));
                        }
                        let (connection_sender, connection_receiver) =
                            mpsc::channel(CONNECTION_QUEUE_CAPACITY);
                        connection_senders.insert(stream_id, connection_sender);
                        let task_sender = outgoing_sender.clone();
                        connections.spawn(async move {
                            let result = run_client_connection(
                                stream_id,
                                target,
                                connection_receiver,
                                task_sender.clone(),
                            )
                            .await;
                            if result.is_err() {
                                let _ = task_sender
                                    .send(OutgoingMessage::Packet(TunnelPacket::Close { stream_id }))
                                    .await;
                            }
                            (stream_id, result)
                        });
                    }
                    Ok(IncomingMessage::Packet(packet)) => {
                        if matches!(packet, TunnelPacket::Opened { .. } | TunnelPacket::OpenFailed { .. }) {
                            break Err(anyhow!("client received an operator-only tunnel packet"));
                        }
                        dispatch_connection_packet(packet, &mut connection_senders).await;
                    }
                    Ok(IncomingMessage::Control) => {}
                    Ok(IncomingMessage::Closed) => break Ok(()),
                    Err(error) => break Err(error),
                }
            }
            maybe_result = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = handle_connection_completion(maybe_result, &mut connection_senders) {
                    break Err(error);
                }
            }
            writer_result = &mut writer_result_receiver => {
                break match writer_result {
                    Ok(result) => result,
                    Err(error) => Err(error).context(
                        "SOCKS tunnel writer stopped without reporting a result"
                    ),
                };
            }
            _ = keepalive.tick() => {
                if outgoing_sender.send(OutgoingMessage::Ping).await.is_err() {
                    break Err(anyhow!("SOCKS tunnel writer is no longer available"));
                }
            }
        }
    };

    stop_session(connections, outgoing_sender, writer_task).await;
    session_result
}

async fn run_operator_socks_proxy_with_listener<S>(
    websocket: WebSocketStream<S>,
    listener: TcpListener,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, mut stream) = websocket.split();
    let (outgoing_sender, outgoing_receiver) = mpsc::channel(OUTGOING_QUEUE_CAPACITY);
    let (writer_task, mut writer_result_receiver) = spawn_websocket_writer(sink, outgoing_receiver);
    let mut connection_senders = HashMap::<u64, mpsc::Sender<TunnelPacket>>::new();
    let mut connections = JoinSet::<ConnectionResult>::new();
    let mut next_stream_id = 1_u64;
    let mut keepalive = keepalive_interval();

    let session_result = loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, remote_addr) = match accept_result {
                    Ok(parts) => parts,
                    Err(error) => break Err(error).context("failed to accept SOCKS5 connection"),
                };
                let stream_id = next_stream_id;
                next_stream_id = match next_stream_id.checked_add(1) {
                    Some(next_stream_id) => next_stream_id,
                    None => break Err(anyhow!("SOCKS tunnel exhausted its stream IDs")),
                };
                let (connection_sender, connection_receiver) =
                    mpsc::channel(CONNECTION_QUEUE_CAPACITY);
                connection_senders.insert(stream_id, connection_sender);
                debug_log(format!("accepted SOCKS-only client {remote_addr} as stream {stream_id}"));
                let task_sender = outgoing_sender.clone();
                connections.spawn(async move {
                    let result = run_operator_connection(
                        stream_id,
                        socket,
                        connection_receiver,
                        task_sender.clone(),
                    )
                    .await;
                    if result.is_err() {
                        let _ = task_sender
                            .send(OutgoingMessage::Packet(TunnelPacket::Close { stream_id }))
                            .await;
                    }
                    (stream_id, result)
                });
            }
            maybe_message = stream.next() => {
                match receive_tunnel_packet(maybe_message, &outgoing_sender).await {
                    Ok(IncomingMessage::Packet(TunnelPacket::Open { .. })) => {
                        break Err(anyhow!("operator received a client-only tunnel open packet"));
                    }
                    Ok(IncomingMessage::Packet(packet)) => {
                        dispatch_connection_packet(packet, &mut connection_senders).await;
                    }
                    Ok(IncomingMessage::Control) => {}
                    Ok(IncomingMessage::Closed) => break Ok(()),
                    Err(error) => break Err(error),
                }
            }
            maybe_result = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = handle_connection_completion(maybe_result, &mut connection_senders) {
                    break Err(error);
                }
            }
            writer_result = &mut writer_result_receiver => {
                break match writer_result {
                    Ok(result) => result,
                    Err(error) => Err(error).context(
                        "SOCKS tunnel writer stopped without reporting a result"
                    ),
                };
            }
            _ = keepalive.tick() => {
                if outgoing_sender.send(OutgoingMessage::Ping).await.is_err() {
                    break Err(anyhow!("SOCKS tunnel writer is no longer available"));
                }
            }
        }
    };

    stop_session(connections, outgoing_sender, writer_task).await;
    session_result
}

async fn run_operator_connection(
    stream_id: u64,
    mut socket: TcpStream,
    mut incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    let target = negotiate_socks5(&mut socket).await?;
    outgoing
        .send(OutgoingMessage::Packet(TunnelPacket::Open {
            stream_id,
            target: target.clone(),
        }))
        .await
        .map_err(|_| anyhow!("SOCKS tunnel closed before the destination could be opened"))?;

    match incoming.recv().await {
        Some(TunnelPacket::Opened {
            stream_id: opened_id,
        }) if opened_id == stream_id => {
            write_socks5_response(&mut socket, SOCKS_REPLY_SUCCESS).await?;
        }
        Some(TunnelPacket::OpenFailed {
            stream_id: failed_id,
            message,
        }) if failed_id == stream_id => {
            write_socks5_response(&mut socket, SOCKS_REPLY_GENERAL_FAILURE).await?;
            bail!(
                "client failed to open SOCKS destination {}:{}: {message}",
                target.host,
                target.port
            );
        }
        Some(unexpected) => {
            bail!(
                "received {:?} before the tunnel open result for stream {stream_id}",
                unexpected
            );
        }
        None => bail!("SOCKS tunnel closed while opening stream {stream_id}"),
    }

    bridge_tcp_stream(stream_id, socket, incoming, outgoing).await
}

async fn run_client_connection(
    stream_id: u64,
    target: SocksConnectTarget,
    incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    let socket = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(socket) => socket,
        Err(error) => {
            let message = truncate_utf8(&error.to_string(), MAX_OPEN_FAILURE_BYTES);
            outgoing
                .send(OutgoingMessage::Packet(TunnelPacket::OpenFailed {
                    stream_id,
                    message,
                }))
                .await
                .map_err(|_| anyhow!("SOCKS tunnel closed while reporting an open failure"))?;
            return Ok(());
        }
    };
    outgoing
        .send(OutgoingMessage::Packet(TunnelPacket::Opened { stream_id }))
        .await
        .map_err(|_| anyhow!("SOCKS tunnel closed while reporting an open destination"))?;
    bridge_tcp_stream(stream_id, socket, incoming, outgoing).await
}

async fn bridge_tcp_stream(
    stream_id: u64,
    socket: TcpStream,
    mut incoming: mpsc::Receiver<TunnelPacket>,
    outgoing: mpsc::Sender<OutgoingMessage>,
) -> Result<()> {
    let (mut socket_reader, mut socket_writer) = socket.into_split();
    let mut read_buffer = BytesMut::zeroed(IO_CHUNK_BYTES);
    let mut socket_read_open = true;
    let mut tunnel_read_open = true;

    while socket_read_open || tunnel_read_open {
        tokio::select! {
            read_result = socket_reader.read(&mut read_buffer), if socket_read_open => {
                let bytes_read = read_result.context("failed to read tunneled TCP connection")?;
                if bytes_read == 0 {
                    socket_read_open = false;
                    outgoing
                        .send(OutgoingMessage::Packet(TunnelPacket::Eof { stream_id }))
                        .await
                        .map_err(|_| anyhow!("SOCKS tunnel closed while sending EOF"))?;
                    continue;
                }
                let data = read_buffer.split_to(bytes_read).freeze();
                read_buffer.resize(IO_CHUNK_BYTES, 0);
                outgoing
                    .send(OutgoingMessage::Packet(TunnelPacket::Data { stream_id, data }))
                    .await
                    .map_err(|_| anyhow!("SOCKS tunnel closed while sending TCP data"))?;
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
                    None => bail!("tunnel routing ended for stream {stream_id}"),
                    Some(unexpected) => {
                        bail!("received unexpected packet while forwarding stream {stream_id}: {unexpected:?}");
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
    match message_result.context("SOCKS tunnel WebSocket read failed")? {
        Message::Binary(bytes) => Ok(IncomingMessage::Packet(TunnelPacket::decode(bytes)?)),
        Message::Ping(payload) => {
            outgoing
                .send(OutgoingMessage::Pong(payload))
                .await
                .map_err(|_| anyhow!("SOCKS tunnel writer is no longer available"))?;
            Ok(IncomingMessage::Control)
        }
        Message::Pong(_) | Message::Frame(_) => Ok(IncomingMessage::Control),
        Message::Close(_) => Ok(IncomingMessage::Closed),
        Message::Text(_) => bail!("received a text frame during SOCKS tunnel transport"),
    }
}

async fn dispatch_connection_packet(
    packet: TunnelPacket,
    connection_senders: &mut HashMap<u64, mpsc::Sender<TunnelPacket>>,
) {
    let stream_id = packet.stream_id();
    let Some(sender) = connection_senders.get(&stream_id) else {
        debug_log(format!(
            "discarding packet for finished SOCKS tunnel stream {stream_id}"
        ));
        return;
    };
    match sender.try_send(packet) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            debug_log(format!(
                "closing overloaded SOCKS tunnel stream {stream_id}"
            ));
            connection_senders.remove(&stream_id);
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            connection_senders.remove(&stream_id);
        }
    }
}

fn handle_connection_completion(
    maybe_result: Option<Result<ConnectionResult, tokio::task::JoinError>>,
    connection_senders: &mut HashMap<u64, mpsc::Sender<TunnelPacket>>,
) -> Result<()> {
    let Some(join_result) = maybe_result else {
        return Ok(());
    };
    let (stream_id, result) = join_result.context("SOCKS connection task failed to join")?;
    connection_senders.remove(&stream_id);
    if let Err(error) = result {
        debug_log(format!("SOCKS tunnel stream {stream_id} failed: {error:#}"));
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
                    .context("failed to write SOCKS tunnel WebSocket")?;
            }
            Result::<(), anyhow::Error>::Ok(())
        }
        .await;
        let _ = result_sender.send(result);
    });
    (task, result_receiver)
}

async fn stop_session(
    mut connections: JoinSet<ConnectionResult>,
    outgoing_sender: mpsc::Sender<OutgoingMessage>,
    writer_task: JoinHandle<()>,
) {
    connections.abort_all();
    while connections.join_next().await.is_some() {}
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
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{accept_async, connect_async};

    use crate::socks::{
        SOCKS_ATYP_DOMAIN_NAME, SOCKS_AUTH_NONE, SOCKS_CMD_CONNECT, SOCKS_REPLY_SUCCESS,
        SOCKS_VERSION,
    };

    use super::{
        SocksConnectTarget, TunnelPacket, run_client_socks_proxy,
        run_operator_socks_proxy_with_listener,
    };

    #[test]
    fn tunnel_open_packet_round_trips() {
        let encoded = TunnelPacket::Open {
            stream_id: 42,
            target: SocksConnectTarget {
                host: "example.com".to_string(),
                port: 443,
            },
        }
        .encode()
        .unwrap();

        let decoded = TunnelPacket::decode(encoded).unwrap();
        match decoded {
            TunnelPacket::Open { stream_id, target } => {
                assert_eq!(stream_id, 42);
                assert_eq!(target.host, "example.com");
                assert_eq!(target.port, 443);
            }
            unexpected => panic!("expected open packet, received {unexpected:?}"),
        }
    }

    #[tokio::test]
    async fn socks_only_proxy_routes_tcp_without_ssh() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            socket.write_all(&request).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let websocket_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let websocket_addr = websocket_listener.local_addr().unwrap();
        let operator_task = tokio::spawn(async move {
            let (socket, _) = websocket_listener.accept().await.unwrap();
            let websocket = accept_async(socket).await.unwrap();
            run_operator_socks_proxy_with_listener(websocket, socks_listener).await
        });
        let (client_websocket, _) = connect_async(format!("ws://{websocket_addr}"))
            .await
            .unwrap();
        let client_task = tokio::spawn(run_client_socks_proxy(client_websocket));

        let mut socks_stream = TcpStream::connect(socks_addr).await.unwrap();
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
            .write_all(b"raw websocket tunnel")
            .await
            .unwrap();
        socks_stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            socks_stream.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, b"raw websocket tunnel");

        echo_task.await.unwrap();
        operator_task.abort();
        client_task.abort();
        let _ = operator_task.await;
        let _ = client_task.await;
    }
}
