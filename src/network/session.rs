use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::{Buf, Bytes};
use h2::{FlowControl, Reason, RecvStream, SendStream};
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::NETWORK_SESSION_FLOW_LIMIT;
use crate::OfferedSession;
use crate::debug::debug_log;
use crate::network::client_resolver::ClientResolver;
use crate::network::egress::{ConnectedUdpSocket, TCP_DIAL_BUDGET, connect_udp, dial_tcp};
use crate::network::policy::ClientNetworkPolicy;
use crate::network::protocol::{
    NetworkError, NetworkErrorKind, NetworkTarget, UdpCapsule, UdpCapsuleDecoder,
    decode_udp_peer_header, encode_udp_capsule, write_udp_peer_header,
};
use crate::network::resolver_session::{
    MAX_CONCURRENT_RESOLVER_REQUESTS, handle_client_resolver_request, is_resolver_request,
};
use crate::websocket::websocket_to_io;

const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_VALUE: &str = "?1";

const STREAM_WINDOW_BYTES: u32 = 1024 * 1024;
const CONNECTION_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
const MAX_SEND_BUFFER_BYTES: usize = 32 * 1024;
const MAX_HEADER_LIST_BYTES: u32 = 8 * 1024;
const MAX_DATA_FRAME_BYTES: u32 = 16 * 1024;
const RESET_RETENTION: Duration = Duration::from_secs(30);
const MAX_RETAINED_RESETS: usize = 256;
const TCP_CHUNK_BYTES: usize = 16 * 1024;
const OPEN_TRANSPORT_GRACE: Duration = Duration::from_secs(5);
pub(crate) const TCP_DESTINATION_OPEN_TIMEOUT: Duration =
    TCP_DIAL_BUDGET.saturating_add(OPEN_TRANSPORT_GRACE);
const UDP_DESTINATION_OPEN_TIMEOUT: Duration = Duration::from_secs(20);
const NETWORK_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const NETWORK_SESSION_STREAM_LIMIT: usize =
    NETWORK_SESSION_FLOW_LIMIT + MAX_CONCURRENT_RESOLVER_REQUESTS;

#[derive(Clone)]
pub(crate) struct OperatorNetworkSession {
    requests: h2::client::SendRequest<Bytes>,
    flow_permits: Arc<Semaphore>,
    pub(super) resolver_permits: Arc<Semaphore>,
}

pub(crate) struct NetworkSessionRuntime {
    connection_task: Option<JoinHandle<Result<()>>>,
    keepalive_task: Option<JoinHandle<Result<()>>>,
}

pub(crate) struct TcpTunnel {
    sender: Option<TcpTunnelSender>,
    receiver: Option<TcpTunnelReceiver>,
}

pub(crate) struct TcpTunnelSender {
    send: SendStream<Bytes>,
    send_finished: bool,
    cancelled: bool,
    _lease: Arc<OwnedSemaphorePermit>,
}

pub(crate) struct TcpTunnelReceiver {
    receive: RecvStream,
    credit: TcpReceiveCredit,
    pending_receive: Option<Bytes>,
    pending_receive_error: Option<io::Error>,
    receive_finished: bool,
    _lease: Arc<OwnedSemaphorePermit>,
}

#[derive(Clone)]
pub(crate) struct TcpReceiveCredit {
    flow_control: FlowControl,
}

pub(crate) struct ReceivedTcpData {
    pub(crate) data: Bytes,
    /// HTTP/2 DATA bytes retained until the consumer accepts this chunk.
    pub(crate) receive_bytes: usize,
}

pub(crate) struct UdpTunnel {
    sender: Option<UdpTunnelSender>,
    receiver: Option<UdpTunnelReceiver>,
    peer: SocketAddr,
}

impl OperatorNetworkSession {
    #[cfg(test)]
    pub(super) fn from_test_transport(
        requests: h2::client::SendRequest<Bytes>,
        flow_limit: usize,
        resolver_limit: usize,
    ) -> Self {
        Self {
            requests,
            flow_permits: Arc::new(Semaphore::new(flow_limit)),
            resolver_permits: Arc::new(Semaphore::new(resolver_limit)),
        }
    }

    #[cfg(test)]
    pub(super) fn acquire_test_flow_permit(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.flow_permits)
            .try_acquire_owned()
            .expect("the test network flow permit must be available")
    }

    pub(crate) async fn connect_tcp(
        &self,
        target: NetworkTarget,
    ) -> Result<TcpTunnel, NetworkError> {
        target
            .validate()
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        let permit = Arc::clone(&self.flow_permits)
            .try_acquire_owned()
            .map_err(|_| NetworkError::resource_limit("network session flow limit reached"))?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri(target.to_connect_uri().map_err(|error| {
                NetworkError::new(NetworkErrorKind::Protocol, error.to_string())
            })?)
            .body(())
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        target
            .write_protocol_headers(request.headers_mut())
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        let deadline = Instant::now() + TCP_DESTINATION_OPEN_TIMEOUT;
        let (response, mut send) =
            match tokio::time::timeout_at(deadline, self.open_request(request, false)).await {
                Ok(result) => result?,
                Err(_) => return Err(tcp_open_timeout_error()),
            };
        let response = match tokio::time::timeout_at(deadline, response).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(map_h2_error(error)),
            Err(_) => {
                send.send_reset(Reason::CANCEL);
                return Err(tcp_open_timeout_error());
            }
        };
        if !response.status().is_success() {
            let error = NetworkError::from_response(response.status(), response.headers());
            send.send_reset(Reason::CANCEL);
            return Err(error);
        }
        let lease = Arc::new(permit);
        let mut receive = response.into_body();
        let credit = TcpReceiveCredit {
            flow_control: receive.flow_control().clone(),
        };
        Ok(TcpTunnel {
            sender: Some(TcpTunnelSender {
                send,
                send_finished: false,
                cancelled: false,
                _lease: Arc::clone(&lease),
            }),
            receiver: Some(TcpTunnelReceiver {
                receive,
                credit,
                pending_receive: None,
                pending_receive_error: None,
                receive_finished: false,
                _lease: lease,
            }),
        })
    }

    pub(crate) async fn open_udp(&self, target: NetworkTarget) -> Result<UdpTunnel, NetworkError> {
        target
            .validate()
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        let permit = Arc::clone(&self.flow_permits)
            .try_acquire_owned()
            .map_err(|_| NetworkError::resource_limit("network session flow limit reached"))?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri(target.to_connect_udp_uri().map_err(|error| {
                NetworkError::new(NetworkErrorKind::Protocol, error.to_string())
            })?)
            .extension(h2::ext::Protocol::from_static("connect-udp"))
            .body(())
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        request.headers_mut().insert(
            CAPSULE_PROTOCOL_HEADER,
            http::HeaderValue::from_static(CAPSULE_PROTOCOL_VALUE),
        );
        target
            .write_protocol_headers(request.headers_mut())
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        let deadline = Instant::now() + UDP_DESTINATION_OPEN_TIMEOUT;
        let (response, mut send) =
            match tokio::time::timeout_at(deadline, self.open_request(request, false)).await {
                Ok(result) => result?,
                Err(_) => return Err(udp_open_timeout_error()),
            };
        let response = match tokio::time::timeout_at(deadline, response).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(map_h2_error(error)),
            Err(_) => {
                send.send_reset(Reason::CANCEL);
                return Err(udp_open_timeout_error());
            }
        };
        if !response.status().is_success() {
            let error = NetworkError::from_response(response.status(), response.headers());
            send.send_reset(Reason::CANCEL);
            return Err(error);
        }
        if let Err(error) = validate_capsule_protocol_header(response.headers(), "response") {
            send.send_reset(Reason::PROTOCOL_ERROR);
            return Err(NetworkError::new(
                NetworkErrorKind::Protocol,
                error.to_string(),
            ));
        }
        let peer = match decode_udp_peer_header(response.headers()) {
            Ok(peer) => peer,
            Err(error) => {
                send.send_reset(Reason::PROTOCOL_ERROR);
                return Err(NetworkError::new(
                    NetworkErrorKind::Protocol,
                    error.to_string(),
                ));
            }
        };
        let lease = Arc::new(permit);
        let mut receive = response.into_body();
        let credit = UdpReceiveCredit {
            flow_control: receive.flow_control().clone(),
        };
        Ok(UdpTunnel {
            sender: Some(UdpTunnelSender {
                send,
                cancelled: false,
                _lease: Arc::clone(&lease),
            }),
            receiver: Some(UdpTunnelReceiver {
                receive,
                credit,
                decoder: UdpCapsuleDecoder::new(),
                pending: VecDeque::new(),
                receive_finished: false,
                _lease: lease,
            }),
            peer,
        })
    }

    /// Opens an HTTP/2 stream without introducing a separate stage timeout.
    ///
    /// Each public operation bounds this step and the response with one end-to-end deadline.
    pub(super) async fn open_request(
        &self,
        request: Request<()>,
        end_stream: bool,
    ) -> Result<(h2::client::ResponseFuture, SendStream<Bytes>), NetworkError> {
        let extended_connect = request.extensions().get::<h2::ext::Protocol>().is_some();
        let mut requests = self.requests.clone().ready().await.map_err(map_h2_error)?;
        if extended_connect && !requests.is_extended_connect_protocol_enabled() {
            return Err(NetworkError::new(
                NetworkErrorKind::Protocol,
                "client did not enable HTTP/2 Extended CONNECT",
            ));
        }
        requests
            .send_request(request, end_stream)
            .map_err(map_h2_error)
    }
}

fn tcp_open_timeout_error() -> NetworkError {
    NetworkError::new(
        NetworkErrorKind::TimedOut,
        "timed out waiting for the client to open the TCP destination",
    )
}

fn udp_open_timeout_error() -> NetworkError {
    NetworkError::new(
        NetworkErrorKind::TimedOut,
        "timed out waiting for the client to open the UDP association",
    )
}

impl NetworkSessionRuntime {
    pub(crate) async fn wait(mut self) -> Result<()> {
        enum CompletedTask {
            Connection(Result<Result<()>, tokio::task::JoinError>),
            Keepalive(Result<Result<()>, tokio::task::JoinError>),
        }

        let completed = tokio::select! {
            result = self.connection_task.as_mut().expect("network connection task is present") => {
                CompletedTask::Connection(result)
            }
            result = self.keepalive_task.as_mut().expect("network keepalive task is present") => {
                CompletedTask::Keepalive(result)
            }
        };
        match completed {
            CompletedTask::Connection(result) => {
                self.connection_task.take();
                abort_network_task(self.keepalive_task.take()).await;
                result
                    .context("HTTP/2 network connection task failed to join")
                    .and_then(|result| result)
            }
            CompletedTask::Keepalive(result) => {
                self.keepalive_task.take();
                abort_network_task(self.connection_task.take()).await;
                result
                    .context("HTTP/2 network keepalive task failed to join")
                    .and_then(|result| result)
            }
        }
    }
}

async fn abort_network_task(task: Option<JoinHandle<Result<()>>>) {
    if let Some(task) = task {
        task.abort();
        let _ = task.await;
    }
}

impl TcpTunnel {
    pub(crate) fn split(mut self) -> (TcpTunnelSender, TcpTunnelReceiver) {
        let sender = self
            .sender
            .take()
            .expect("an unsplit TCP tunnel always owns its sender");
        let receiver = self
            .receiver
            .take()
            .expect("an unsplit TCP tunnel always owns its receiver");
        (sender, receiver)
    }
}

impl TcpReceiveCredit {
    pub(crate) fn release_receive_capacity(&mut self, bytes: usize) -> Result<(), NetworkError> {
        self.flow_control
            .release_capacity(bytes)
            .map_err(map_h2_error)
    }
}

impl TcpTunnelReceiver {
    pub(crate) async fn receive_data(&mut self) -> Result<Option<ReceivedTcpData>, NetworkError> {
        if let Some(error) = self.pending_receive_error.take() {
            self.receive_finished = true;
            self.pending_receive = None;
            return Err(NetworkError::from_io(&error));
        }
        if let Some(data) = self.pending_receive.take() {
            let receive_bytes = data.len();
            return Ok(Some(ReceivedTcpData {
                data,
                receive_bytes,
            }));
        }
        if self.receive_finished {
            return Ok(None);
        }
        loop {
            match self.receive.data().await {
                Some(Ok(data)) if data.is_empty() => continue,
                Some(Ok(data)) => {
                    let receive_bytes = data.len();
                    return Ok(Some(ReceivedTcpData {
                        data,
                        receive_bytes,
                    }));
                }
                Some(Err(error)) => {
                    self.receive_finished = true;
                    return Err(map_h2_error(error));
                }
                None => {
                    let trailers = self.receive.trailers().await.map_err(map_h2_error)?;
                    self.receive_finished = true;
                    if let Some(trailers) = trailers.filter(|trailers| !trailers.is_empty()) {
                        return Err(NetworkError::from_trailers(&trailers));
                    }
                    return Ok(None);
                }
            }
        }
    }

    pub(crate) fn receive_credit(&self) -> TcpReceiveCredit {
        self.credit.clone()
    }
}

impl AsyncWrite for TcpTunnelSender {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        poll_tcp_write(&mut this.send, &mut this.send_finished, context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        shutdown_tcp_send(&mut this.send, &mut this.send_finished)
    }
}

impl TcpTunnelSender {
    pub(crate) fn cancel(&mut self) {
        if self.cancelled {
            return;
        }
        self.send.send_reset(Reason::CANCEL);
        self.send_finished = true;
        self.cancelled = true;
    }
}

impl Drop for TcpTunnelSender {
    fn drop(&mut self) {
        if !self.send_finished {
            self.cancel();
        }
    }
}

impl AsyncRead for TcpTunnelReceiver {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || self.receive_finished {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = self.pending_receive_error.take() {
            self.receive_finished = true;
            self.pending_receive = None;
            return Poll::Ready(Err(error));
        }

        loop {
            if let Some(mut frame) = self.pending_receive.take() {
                let count = frame.len().min(output.remaining());
                output.put_slice(&frame[..count]);
                frame.advance(count);
                if !frame.is_empty() {
                    self.pending_receive = Some(frame);
                }
                if let Err(error) = self
                    .receive
                    .flow_control()
                    .release_capacity(count)
                    .map_err(map_h2_io_error)
                {
                    self.pending_receive_error = Some(error);
                }
                return Poll::Ready(Ok(()));
            }

            match ready!(self.receive.poll_data(context)) {
                Some(Ok(frame)) if frame.is_empty() => continue,
                Some(Ok(frame)) => self.pending_receive = Some(frame),
                Some(Err(error)) => {
                    self.receive_finished = true;
                    return Poll::Ready(Err(map_h2_io_error(error)));
                }
                None => match ready!(self.receive.poll_trailers(context)) {
                    Ok(Some(trailers)) => {
                        self.receive_finished = true;
                        if trailers.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(
                            NetworkError::from_trailers(&trailers).to_io_error()
                        ));
                    }
                    Ok(None) => {
                        self.receive_finished = true;
                        return Poll::Ready(Ok(()));
                    }
                    Err(error) => {
                        self.receive_finished = true;
                        return Poll::Ready(Err(map_h2_io_error(error)));
                    }
                },
            }
        }
    }
}

impl AsyncRead for TcpTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let receiver = self
            .receiver
            .as_mut()
            .expect("an unsplit TCP tunnel always owns its receiver");
        Pin::new(receiver).poll_read(context, output)
    }
}

impl AsyncWrite for TcpTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let sender = this
            .sender
            .as_mut()
            .expect("an unsplit TCP tunnel always owns its sender");
        Pin::new(sender).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let sender = this
            .sender
            .as_mut()
            .expect("an unsplit TCP tunnel always owns its sender");
        Pin::new(sender).poll_shutdown(context)
    }
}

fn poll_tcp_write(
    send: &mut SendStream<Bytes>,
    send_finished: &mut bool,
    context: &mut TaskContext<'_>,
    bytes: &[u8],
) -> Poll<io::Result<usize>> {
    if *send_finished {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "TCP tunnel send direction is closed",
        )));
    }
    if bytes.is_empty() {
        return Poll::Ready(Ok(0));
    }

    let requested = bytes.len().min(TCP_CHUNK_BYTES);
    let capacity = if send.capacity() > 0 {
        send.capacity()
    } else {
        send.reserve_capacity(requested);
        match ready!(send.poll_capacity(context)) {
            Some(Ok(capacity)) => capacity,
            Some(Err(error)) => return Poll::Ready(Err(map_h2_io_error(error))),
            None => {
                *send_finished = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TCP tunnel closed while waiting for send capacity",
                )));
            }
        }
    };
    let count = capacity.min(requested);
    send.send_data(Bytes::copy_from_slice(&bytes[..count]), false)
        .map_err(map_h2_io_error)?;
    send.reserve_capacity(0);
    Poll::Ready(Ok(count))
}

fn shutdown_tcp_send(
    send: &mut SendStream<Bytes>,
    send_finished: &mut bool,
) -> Poll<io::Result<()>> {
    if *send_finished {
        return Poll::Ready(Ok(()));
    }
    send_h2_end_stream(send).map_err(map_h2_io_error)?;
    *send_finished = true;
    Poll::Ready(Ok(()))
}

impl Drop for NetworkSessionRuntime {
    fn drop(&mut self) {
        if let Some(task) = &self.connection_task {
            task.abort();
        }
        if let Some(task) = &self.keepalive_task {
            task.abort();
        }
    }
}

impl UdpTunnel {
    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    pub(crate) fn split(mut self) -> (UdpTunnelSender, UdpTunnelReceiver) {
        let sender = self
            .sender
            .take()
            .expect("an unsplit UDP tunnel always owns its sender");
        let receiver = self
            .receiver
            .take()
            .expect("an unsplit UDP tunnel always owns its receiver");
        (sender, receiver)
    }
}

async fn receive_udp_datagram(
    receive: &mut RecvStream,
    decoder: &mut UdpCapsuleDecoder,
    pending: &mut VecDeque<(UdpCapsule, usize)>,
) -> Result<Option<ReceivedUdpDatagram>, NetworkError> {
    loop {
        if let Some((capsule, wire_bytes)) = pending.pop_front() {
            match capsule {
                UdpCapsule::Datagram(data) => {
                    return Ok(Some(ReceivedUdpDatagram { data, wire_bytes }));
                }
                UdpCapsule::Error(error) => {
                    receive
                        .flow_control()
                        .release_capacity(wire_bytes)
                        .map_err(map_h2_error)?;
                    return Err(error);
                }
                UdpCapsule::Ignored => receive
                    .flow_control()
                    .release_capacity(wire_bytes)
                    .map_err(map_h2_error)?,
            }
            continue;
        }
        let Some(frame) = receive.data().await else {
            decoder.finish().map_err(|error| {
                NetworkError::new(NetworkErrorKind::Protocol, error.to_string())
            })?;
            let trailers = receive.trailers().await.map_err(map_h2_error)?;
            if let Some(trailers) = trailers.filter(|trailers| !trailers.is_empty()) {
                return Err(NetworkError::from_trailers(&trailers));
            }
            return Ok(None);
        };
        let frame = frame.map_err(map_h2_error)?;
        pending.extend(
            decoder.push(frame).map_err(|error| {
                NetworkError::new(NetworkErrorKind::Protocol, error.to_string())
            })?,
        );
    }
}

pub(crate) struct ReceivedUdpDatagram {
    pub(crate) data: Bytes,
    /// HTTP/2 DATA bytes retained for this capsule, including capsule framing.
    pub(crate) wire_bytes: usize,
}

pub(crate) struct UdpTunnelSender {
    send: SendStream<Bytes>,
    cancelled: bool,
    _lease: Arc<OwnedSemaphorePermit>,
}

pub(crate) struct UdpTunnelReceiver {
    receive: RecvStream,
    credit: UdpReceiveCredit,
    decoder: UdpCapsuleDecoder,
    pending: VecDeque<(UdpCapsule, usize)>,
    receive_finished: bool,
    _lease: Arc<OwnedSemaphorePermit>,
}

#[derive(Clone)]
pub(crate) struct UdpReceiveCredit {
    flow_control: FlowControl,
}

impl UdpTunnelSender {
    pub(crate) async fn send_datagram(&mut self, data: Bytes) -> Result<(), NetworkError> {
        let capsule = UdpCapsule::Datagram(data);
        let encoded = encode_udp_capsule(&capsule)
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        send_h2_data(&mut self.send, encoded, false)
            .await
            .map_err(map_session_error)
    }

    pub(crate) fn cancel(&mut self) {
        if self.cancelled {
            return;
        }
        self.send.send_reset(Reason::CANCEL);
        self.cancelled = true;
    }
}

impl Drop for UdpTunnelSender {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl UdpTunnelReceiver {
    pub(crate) async fn receive_datagram(
        &mut self,
    ) -> Result<Option<ReceivedUdpDatagram>, NetworkError> {
        if self.receive_finished {
            return Ok(None);
        }
        let result =
            receive_udp_datagram(&mut self.receive, &mut self.decoder, &mut self.pending).await;
        if matches!(&result, Ok(None)) {
            self.receive_finished = true;
        }
        result
    }

    pub(crate) fn release_receive_capacity(&mut self, wire_len: usize) -> Result<(), NetworkError> {
        self.credit.release_receive_capacity(wire_len)
    }

    pub(crate) fn receive_credit(&self) -> UdpReceiveCredit {
        self.credit.clone()
    }
}

impl UdpReceiveCredit {
    pub(crate) fn release_receive_capacity(&mut self, wire_len: usize) -> Result<(), NetworkError> {
        self.flow_control
            .release_capacity(wire_len)
            .map_err(map_h2_error)
    }
}

pub(crate) async fn start_operator_network_session<S>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
) -> Result<(OperatorNetworkSession, NetworkSessionRuntime)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    start_operator_network_session_with_timeout(websocket, NETWORK_HANDSHAKE_TIMEOUT).await
}

async fn start_operator_network_session_with_timeout<S>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    handshake_timeout: Duration,
) -> Result<(OperatorNetworkSession, NetworkSessionRuntime)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake_deadline = Instant::now() + handshake_timeout;
    let io = websocket_to_io(websocket);
    let mut builder = h2::client::Builder::new();
    configure_client_builder(&mut builder);
    let (requests, mut connection) =
        tokio::time::timeout_at(handshake_deadline, builder.handshake::<_, Bytes>(io))
            .await
            .context("timed out establishing the HTTP/2 network session")?
            .context("failed to establish the HTTP/2 network session")?;
    let mut ping_pong = connection
        .ping_pong()
        .context("HTTP/2 network session does not support keepalive pings")?;
    let connection_task = tokio::spawn(async move {
        connection
            .await
            .context("HTTP/2 network session closed unexpectedly")
    });
    let settings_synchronization: Result<()> = async {
        tokio::time::timeout_at(handshake_deadline, ping_pong.ping(h2::Ping::opaque()))
            .await
            .context("timed out waiting for the peer's HTTP/2 network settings")?
            .context("failed to synchronize the peer's HTTP/2 network settings")?;
        Ok(())
    }
    .await;
    if let Err(error) = settings_synchronization {
        connection_task.abort();
        let _ = connection_task.await;
        return Err(error);
    }
    let keepalive_task = tokio::spawn(run_keepalive(ping_pong));
    Ok((
        OperatorNetworkSession {
            requests,
            flow_permits: Arc::new(Semaphore::new(NETWORK_SESSION_FLOW_LIMIT)),
            resolver_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_RESOLVER_REQUESTS)),
        },
        NetworkSessionRuntime {
            connection_task: Some(connection_task),
            keepalive_task: Some(keepalive_task),
        },
    ))
}

pub async fn run_client_network_session<S>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    approved_session: OfferedSession,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_client_network_session_with_timeout(websocket, approved_session, NETWORK_HANDSHAKE_TIMEOUT)
        .await
}

async fn run_client_network_session_with_timeout<S>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    approved_session: OfferedSession,
    handshake_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let policy = Arc::new(ClientNetworkPolicy::from_approved_session(
        &approved_session,
    )?);
    let handshake_deadline = Instant::now() + handshake_timeout;
    let io = websocket_to_io(websocket);
    let mut builder = h2::server::Builder::new();
    configure_server_builder(&mut builder);
    let mut connection =
        tokio::time::timeout_at(handshake_deadline, builder.handshake::<_, Bytes>(io))
            .await
            .context("timed out establishing the HTTP/2 network session")?
            .context("failed to establish the HTTP/2 network session")?;
    let ping_pong = connection
        .ping_pong()
        .context("HTTP/2 network session does not support keepalive pings")?;
    let keepalive = run_keepalive(ping_pong);
    tokio::pin!(keepalive);
    let flow_permits = Arc::new(Semaphore::new(NETWORK_SESSION_FLOW_LIMIT));
    let resolver_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_RESOLVER_REQUESTS));
    let resolver = Arc::new(ClientResolver::from_system_configuration());
    let mut flows = JoinSet::new();

    let session_result = loop {
        if let Err(error) = reap_completed_client_flows(&mut flows) {
            break Err(error);
        }
        tokio::select! {
            request = connection.accept() => {
                let Some(request) = request else {
                    break Ok(());
                };
                let (request, respond) = match request {
                    Ok(request) => request,
                    Err(error) => {
                        break Err(error).context("failed to accept HTTP/2 network stream");
                    }
                };
                let resolver_request = is_resolver_request(&request);
                let permits = if resolver_request {
                    &resolver_permits
                } else {
                    &flow_permits
                };
                let permit = match Arc::clone(permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let rejection = if resolver_request {
                            crate::network::resolver_session::reject_resolver_capacity(respond)
                        } else {
                            reject_request(
                                respond,
                                NetworkError::resource_limit("client network flow limit reached"),
                            )
                        };
                        if let Err(error) = rejection {
                            break Err(error).context("failed to reject an excess network stream");
                        }
                        continue;
                    }
                };
                let resolver = resolver.clone();
                let policy = Arc::clone(&policy);
                flows.spawn(async move {
                    let _permit = permit;
                    handle_client_request(request, respond, resolver, policy).await
                });
            }
            result = &mut keepalive => {
                break result;
            }
            result = flows.join_next(), if !flows.is_empty() => {
                if let Some(result) = result
                    && let Err(error) = handle_client_flow_completion(result)
                {
                    break Err(error);
                }
            }
        }
    };

    flows.abort_all();
    while flows.join_next().await.is_some() {}
    session_result
}

fn reap_completed_client_flows(flows: &mut JoinSet<Result<()>>) -> Result<()> {
    while let Some(result) = flows.try_join_next() {
        handle_client_flow_completion(result)?;
    }
    Ok(())
}

fn handle_client_flow_completion(result: std::result::Result<Result<()>, JoinError>) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            debug_log(format!(
                "client network flow ended with an error: {error:#}"
            ));
            Ok(())
        }
        Err(error) => Err(error).context("client network flow task failed to join"),
    }
}

async fn handle_client_request(
    request: Request<RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    resolver: Arc<ClientResolver>,
    policy: Arc<ClientNetworkPolicy>,
) -> Result<()> {
    if is_resolver_request(&request) {
        return handle_client_resolver_request(request, respond, resolver, policy).await;
    }
    if request.method() != Method::CONNECT || request.version() != Version::HTTP_2 {
        return reject_request(
            respond,
            NetworkError::new(NetworkErrorKind::Protocol, "invalid network stream request"),
        );
    }
    match request.extensions().get::<h2::ext::Protocol>() {
        None => run_client_tcp(request, respond, &resolver, &policy).await,
        Some(protocol) if protocol.as_ref() == b"connect-udp" => {
            run_client_udp(request, respond, &resolver, &policy).await
        }
        Some(_) => reject_request(
            respond,
            NetworkError::new(
                NetworkErrorKind::Protocol,
                "unsupported Extended CONNECT protocol",
            ),
        ),
    }
}

async fn run_client_tcp(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    resolver: &ClientResolver,
    policy: &ClientNetworkPolicy,
) -> Result<()> {
    let target = match NetworkTarget::from_connect_uri(request.uri(), request.headers()) {
        Ok(target) => target,
        Err(error) => {
            return reject_request(
                respond,
                NetworkError::new(NetworkErrorKind::Protocol, error.to_string()),
            );
        }
    };
    if let Err(error) = policy.authorize_target(&target) {
        return reject_request(respond, error);
    }
    let socket = tokio::select! {
        biased;
        reset = std::future::poll_fn(|context| respond.poll_reset(context)) => {
            reset.context("TCP open was cancelled by a broken HTTP/2 session")?;
            return Ok(());
        },
        result = dial_tcp(&target, resolver) => match result {
            Ok(socket) => socket,
            Err(error) => return reject_request(respond, error),
        }
    };
    let response = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_2)
        .body(())
        .context("failed to build TCP open response")?;
    let send = respond
        .send_response(response, false)
        .context("failed to confirm TCP destination open")?;
    if let Err(error) = bridge_h2_tcp(socket, request.into_body(), send).await {
        debug_log(format!(
            "TCP flow to {}:{} ended with an error: {error:#}",
            target.host, target.port
        ));
    }
    Ok(())
}

async fn run_client_udp(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    resolver: &ClientResolver,
    policy: &ClientNetworkPolicy,
) -> Result<()> {
    if let Err(error) = validate_capsule_protocol_header(request.headers(), "request") {
        return reject_request(
            respond,
            NetworkError::new(NetworkErrorKind::Protocol, error.to_string()),
        );
    }
    let target = match NetworkTarget::from_connect_udp_uri(request.uri(), request.headers()) {
        Ok(target) => target,
        Err(error) => {
            return reject_request(
                respond,
                NetworkError::new(NetworkErrorKind::Protocol, error.to_string()),
            );
        }
    };
    if let Err(error) = policy.authorize_target(&target) {
        return reject_request(respond, error);
    }
    let ConnectedUdpSocket { socket, peer } = tokio::select! {
        biased;
        reset = std::future::poll_fn(|context| respond.poll_reset(context)) => {
            reset.context("UDP open was cancelled by a broken HTTP/2 session")?;
            return Ok(());
        },
        result = connect_udp(&target, resolver) => match result {
            Ok(socket) => socket,
            Err(error) => return reject_request(respond, error),
        }
    };
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_2)
        .body(())
        .context("failed to build UDP open response")?;
    response.headers_mut().insert(
        CAPSULE_PROTOCOL_HEADER,
        http::HeaderValue::from_static(CAPSULE_PROTOCOL_VALUE),
    );
    write_udp_peer_header(response.headers_mut(), peer)?;
    let mut send = respond
        .send_response(response, false)
        .context("failed to confirm UDP association open")?;
    let mut receive = request.into_body();
    let mut decoder = UdpCapsuleDecoder::new();
    let mut pending = VecDeque::new();
    let mut receive_buffer = vec![0_u8; 65_535];

    let result: Result<()> = async {
        loop {
            if let Some((capsule, wire_len)) = pending.pop_front() {
                match capsule {
                    UdpCapsule::Datagram(data) => {
                        let send_result = socket.send(&data).await;
                        receive
                            .flow_control()
                            .release_capacity(wire_len)
                            .context("failed to release UDP request receive capacity")?;
                        match send_result {
                            Ok(size) if size == data.len() => {}
                            Ok(size) => {
                                let capsule = UdpCapsule::Error(NetworkError::new(
                                    NetworkErrorKind::General,
                                    format!("UDP send wrote {size} of {} bytes", data.len()),
                                ));
                                send_h2_data(&mut send, encode_udp_capsule(&capsule)?, false)
                                    .await?;
                            }
                            Err(error) => {
                                let capsule = UdpCapsule::Error(NetworkError::from_io(&error));
                                send_h2_data(&mut send, encode_udp_capsule(&capsule)?, false)
                                    .await?;
                            }
                        }
                    }
                    UdpCapsule::Error(_) => {
                        receive
                            .flow_control()
                            .release_capacity(wire_len)
                            .context("failed to release rejected UDP error-capsule capacity")?;
                        return Err(NetworkError::new(
                            NetworkErrorKind::Protocol,
                            "operator sent an error capsule on a UDP request stream",
                        )
                        .into());
                    }
                    UdpCapsule::Ignored => {
                        receive
                            .flow_control()
                            .release_capacity(wire_len)
                            .context("failed to release ignored UDP capsule capacity")?;
                    }
                }
                continue;
            }

            tokio::select! {
                frame = receive.data() => {
                    let Some(frame) = frame else {
                        decoder.finish().map_err(|error| {
                            NetworkError::new(NetworkErrorKind::Protocol, error.to_string())
                        })?;
                        if receive
                            .trailers()
                            .await
                            .context("failed to receive UDP request trailers")?
                            .is_some_and(|trailers| !trailers.is_empty())
                        {
                            return Err(NetworkError::new(
                                NetworkErrorKind::Protocol,
                                "UDP request stream carried non-empty trailers",
                            ).into());
                        }
                        send_h2_end_stream(&mut send)
                            .context("failed to close UDP response stream")?;
                        return Ok(());
                    };
                    let frame = frame.context("UDP request stream failed")?;
                    pending.extend(decoder.push(frame).map_err(|error| {
                        NetworkError::new(NetworkErrorKind::Protocol, error.to_string())
                    })?);
                }
                result = socket.recv(&mut receive_buffer) => {
                    let size = result.context("failed to receive UDP response")?;
                    let capsule = UdpCapsule::Datagram(Bytes::copy_from_slice(&receive_buffer[..size]));
                    send_h2_data(&mut send, encode_udp_capsule(&capsule)?, false).await?;
                }
            }
        }
    }
    .await;
    if let Err(error) = result {
        send_runtime_error(&mut send, &error);
        debug_log(format!(
            "UDP flow to {}:{} ended with an error: {error:#}",
            target.host, target.port
        ));
    }
    Ok(())
}

fn validate_capsule_protocol_header(headers: &HeaderMap, message_kind: &str) -> Result<()> {
    let mut values = headers.get_all(CAPSULE_PROTOCOL_HEADER).iter();
    let value = values.next().with_context(|| {
        format!("CONNECT-UDP {message_kind} did not negotiate capsule protocol")
    })?;
    if values.next().is_some() {
        bail!("CONNECT-UDP {message_kind} carries multiple capsule-protocol headers");
    }
    if value.as_bytes() != CAPSULE_PROTOCOL_VALUE.as_bytes() {
        bail!("CONNECT-UDP {message_kind} has an invalid capsule-protocol value");
    }
    Ok(())
}

pub(crate) async fn bridge_operator_tcp<T>(stream: T, tunnel: TcpTunnel) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    bridge_tcp_streams(stream, tunnel).await
}

async fn bridge_h2_tcp<T>(stream: T, receive: RecvStream, send: SendStream<Bytes>) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, writer) = tokio::io::split(stream);
    let cancellation = CancellationToken::new();
    let upload = pump_io_to_h2(reader, send, cancellation.clone());
    let download = pump_h2_to_io(receive, writer, cancellation.clone());
    let ((mut send, upload_result), download_result) = tokio::join!(upload, download);
    let result = match (upload_result, download_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(upload_error), Err(download_error)) => Err(upload_error.context(format!(
            "reverse TCP direction also failed: {download_error:#}"
        ))),
    };
    if let Err(error) = &result {
        send_runtime_error(&mut send, error);
    }
    result
}

async fn bridge_tcp_streams<L, R>(left: L, right: R) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (left_reader, left_writer) = tokio::io::split(left);
    let (right_reader, right_writer) = tokio::io::split(right);
    let cancellation = CancellationToken::new();
    let upload = copy_tcp_direction(left_reader, right_writer, cancellation.clone());
    let download = copy_tcp_direction(right_reader, left_writer, cancellation);
    let (upload_result, download_result) = tokio::join!(upload, download);
    match (upload_result, download_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(upload_error), Err(download_error)) => Err(upload_error.context(format!(
            "reverse TCP direction also failed: {download_error:#}"
        ))),
    }
}

async fn copy_tcp_direction<R, W>(
    mut reader: R,
    mut writer: W,
    cancellation: CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result = async {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(()),
            result = tokio::io::copy(&mut reader, &mut writer) => {
                result.context("failed to copy TCP tunnel data")?;
            }
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Ok(()),
            result = writer.shutdown() => {
                result.context("failed to half-close TCP tunnel destination")
            }
        }
    }
    .await;
    if result.is_err() {
        cancellation.cancel();
    }
    result
}

async fn pump_io_to_h2<R>(
    mut reader: R,
    mut send: SendStream<Bytes>,
    cancellation: CancellationToken,
) -> (SendStream<Bytes>, Result<()>)
where
    R: AsyncRead + Unpin,
{
    let result = async {
        let mut buffer = vec![0_u8; TCP_CHUNK_BYTES];
        loop {
            let bytes_read = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                result = reader.read(&mut buffer) => result.context("failed to read TCP source")?,
            };
            if bytes_read == 0 {
                send_h2_end_stream(&mut send).context("failed to send TCP half-close")?;
                return Ok(());
            }

            // The trailing HEADERS block used for END_STREAM is not flow controlled. Reading one
            // bounded chunk first prevents a connection-wide zero window from hiding EOF and
            // indefinitely delaying this stream's half-close.
            let mut offset = 0;
            while offset < bytes_read {
                let capacity = tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return Ok(()),
                    capacity = reserve_send_capacity(&mut send, bytes_read - offset) => capacity?,
                };
                let end = offset + capacity;
                send.send_data(Bytes::copy_from_slice(&buffer[offset..end]), false)
                    .context("failed to send TCP data")?;
                send.reserve_capacity(0);
                offset = end;
            }
        }
    }
    .await;
    if result.is_err() {
        cancellation.cancel();
    }
    (send, result)
}

async fn pump_h2_to_io<W>(
    mut receive: RecvStream,
    mut writer: W,
    cancellation: CancellationToken,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let result = async {
        loop {
            let frame = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                frame = receive.data() => frame,
            };
            let Some(frame) = frame else {
                let trailers = tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return Ok(()),
                    result = receive.trailers() => {
                        result.context("failed to receive TCP request trailers")?
                    }
                };
                if trailers.is_some_and(|trailers| !trailers.is_empty()) {
                    return Err(NetworkError::new(
                        NetworkErrorKind::Protocol,
                        "TCP request stream carried non-empty trailers",
                    )
                    .into());
                }
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return Ok(()),
                    result = writer.shutdown() => {
                        result.context("failed to half-close TCP destination")?;
                    }
                }
                return Ok(());
            };
            let frame = frame.context("failed to receive TCP data")?;
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                result = writer.write_all(&frame) => {
                    result.context("failed to write TCP destination")?;
                }
            }
            receive
                .flow_control()
                .release_capacity(frame.len())
                .context("failed to release TCP receive capacity")?;
        }
    }
    .await;
    if result.is_err() {
        cancellation.cancel();
    }
    result
}

pub(super) async fn send_h2_data(
    send: &mut SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
) -> Result<()> {
    if data.is_empty() {
        if end_stream {
            send_h2_end_stream(send).context("failed to close HTTP/2 network stream")?;
        } else {
            send.send_data(data, false)
                .context("failed to send HTTP/2 network data")?;
        }
        return Ok(());
    }
    let mut offset = 0;
    while offset < data.len() {
        let requested = (data.len() - offset).min(TCP_CHUNK_BYTES);
        let capacity = reserve_send_capacity(send, requested).await?;
        let count = capacity.min(data.len() - offset);
        let final_chunk = offset + count == data.len();
        send.send_data(
            data.slice(offset..offset + count),
            end_stream && final_chunk,
        )
        .context("failed to send HTTP/2 network data")?;
        send.reserve_capacity(0);
        offset += count;
    }
    Ok(())
}

fn send_h2_end_stream(send: &mut SendStream<Bytes>) -> std::result::Result<(), h2::Error> {
    send.reserve_capacity(0);
    send.send_trailers(HeaderMap::new())
}

async fn reserve_send_capacity(send: &mut SendStream<Bytes>, requested: usize) -> Result<usize> {
    send.reserve_capacity(requested);
    let capacity = std::future::poll_fn(|context| send.poll_capacity(context))
        .await
        .context("HTTP/2 network stream closed while waiting for send capacity")?
        .context("failed to reserve HTTP/2 network send capacity")?;
    Ok(capacity.min(requested))
}

fn reject_request(mut respond: h2::server::SendResponse<Bytes>, error: NetworkError) -> Result<()> {
    let mut response = Response::builder()
        .status(error.kind.response_status())
        .version(Version::HTTP_2)
        .body(())
        .context("failed to build network rejection response")?;
    error.write_headers(response.headers_mut());
    respond
        .send_response(response, true)
        .context("failed to reject network stream")?;
    Ok(())
}

fn send_runtime_error(send: &mut SendStream<Bytes>, error: &anyhow::Error) {
    let network_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<NetworkError>())
        .cloned()
        .or_else(|| {
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<io::Error>())
                .map(NetworkError::from_io)
        })
        .unwrap_or_else(|| NetworkError::new(NetworkErrorKind::General, format!("{error:#}")));
    let mut trailers = HeaderMap::new();
    network_error.write_headers(&mut trailers);
    if send.send_trailers(trailers).is_err() {
        send.send_reset(Reason::CONNECT_ERROR);
    }
}

async fn run_keepalive(mut ping_pong: h2::PingPong) -> Result<()> {
    let mut interval =
        tokio::time::interval_at(Instant::now() + KEEPALIVE_INTERVAL, KEEPALIVE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        tokio::time::timeout(KEEPALIVE_TIMEOUT, ping_pong.ping(h2::Ping::opaque()))
            .await
            .context("HTTP/2 network peer did not answer a keepalive ping")?
            .context("HTTP/2 network keepalive failed")?;
        debug_log("HTTP/2 network keepalive acknowledged");
    }
}

fn configure_client_builder(builder: &mut h2::client::Builder) {
    builder
        .enable_push(false)
        .header_table_size(0)
        .max_frame_size(MAX_DATA_FRAME_BYTES)
        .initial_window_size(STREAM_WINDOW_BYTES)
        .initial_connection_window_size(CONNECTION_WINDOW_BYTES)
        .max_concurrent_streams(NETWORK_SESSION_STREAM_LIMIT as u32)
        .max_header_list_size(MAX_HEADER_LIST_BYTES)
        .max_send_buffer_size(MAX_SEND_BUFFER_BYTES)
        .reset_stream_duration(RESET_RETENTION)
        .max_concurrent_reset_streams(MAX_RETAINED_RESETS)
        .max_pending_accept_reset_streams(MAX_RETAINED_RESETS);
}

fn configure_server_builder(builder: &mut h2::server::Builder) {
    builder
        .enable_connect_protocol()
        .header_table_size(0)
        .max_frame_size(MAX_DATA_FRAME_BYTES)
        .initial_window_size(STREAM_WINDOW_BYTES)
        .initial_connection_window_size(CONNECTION_WINDOW_BYTES)
        .max_concurrent_streams(NETWORK_SESSION_STREAM_LIMIT as u32)
        .max_header_list_size(MAX_HEADER_LIST_BYTES)
        .max_send_buffer_size(MAX_SEND_BUFFER_BYTES)
        .reset_stream_duration(RESET_RETENTION)
        .max_concurrent_reset_streams(MAX_RETAINED_RESETS)
        .max_pending_accept_reset_streams(MAX_RETAINED_RESETS);
}

pub(super) fn map_h2_error(error: h2::Error) -> NetworkError {
    if error.is_reset() && error.reason() == Some(Reason::REFUSED_STREAM) {
        return NetworkError::resource_limit("remote network flow limit reached");
    }
    if let Some(io_error) = error.get_io() {
        return NetworkError::from_io(io_error);
    }
    NetworkError::session_closed(format!("HTTP/2 network stream failed: {error}"))
}

fn map_h2_io_error(error: h2::Error) -> io::Error {
    map_h2_error(error).to_io_error()
}

pub(super) fn map_session_error(error: anyhow::Error) -> NetworkError {
    NetworkError::session_closed(format!("network session failed: {error:#}"))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};
    use tokio::sync::oneshot;
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_util::sync::CancellationToken;

    use super::{
        MAX_CONCURRENT_RESOLVER_REQUESTS, NetworkSessionRuntime, NetworkTarget,
        OperatorNetworkSession, bridge_operator_tcp, bridge_tcp_streams, configure_client_builder,
        configure_server_builder, pump_h2_to_io, pump_io_to_h2, run_client_network_session,
        run_client_network_session_with_timeout, start_operator_network_session,
        start_operator_network_session_with_timeout, validate_capsule_protocol_header,
    };
    use crate::control::{OfferedSession, VpnScope};
    use crate::network::protocol::{
        NetworkError, NetworkErrorKind, UdpCapsule, encode_udp_capsule, write_udp_peer_header,
    };
    use crate::network::resolver_protocol::ResolveRequest;
    use crate::vpn::SystemVpnPolicy;

    struct ReadErrorStream;

    #[derive(Debug, Eq, PartialEq)]
    enum BlockedWriterOperation {
        Write,
        Shutdown,
    }

    struct PermanentlyBlockedWriter {
        started: Option<oneshot::Sender<BlockedWriterOperation>>,
    }

    impl AsyncWrite for PermanentlyBlockedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
            _bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(started) = self.started.take() {
                let _ = started.send(BlockedWriterOperation::Write);
            }
            Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(started) = self.started.take() {
                let _ = started.send(BlockedWriterOperation::Shutdown);
            }
            Poll::Pending
        }
    }

    impl AsyncRead for ReadErrorStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
            _output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected read failure",
            )))
        }
    }

    impl AsyncWrite for ReadErrorStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
            _bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn network_runtime_does_not_repoll_its_completed_task() {
        let runtime = NetworkSessionRuntime {
            connection_task: Some(tokio::spawn(async { Ok(()) })),
            keepalive_task: Some(tokio::spawn(std::future::pending())),
        };

        tokio::time::timeout(Duration::from_secs(1), runtime.wait())
            .await
            .expect("network runtime did not observe its completed connection task")
            .unwrap();
    }

    #[tokio::test]
    async fn both_network_roles_time_out_a_silent_websocket_peer() {
        const TEST_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(50);

        let (operator_io, _silent_operator_peer) = duplex(64 * 1024);
        let operator_websocket =
            WebSocketStream::from_raw_socket(operator_io, Role::Client, None).await;
        let operator =
            start_operator_network_session_with_timeout(operator_websocket, TEST_HANDSHAKE_TIMEOUT);

        let (client_io, _silent_client_peer) = duplex(64 * 1024);
        let client_websocket =
            WebSocketStream::from_raw_socket(client_io, Role::Server, None).await;
        let client = run_client_network_session_with_timeout(
            client_websocket,
            OfferedSession::Socks {},
            TEST_HANDSHAKE_TIMEOUT,
        );

        let (operator_result, client_result) =
            tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(operator, client)
            })
            .await
            .expect("network handshakes ignored their deadlines");
        let operator_error = match operator_result {
            Err(error) => error,
            Ok(_) => panic!("operator network handshake accepted a silent peer"),
        };
        let client_error = match client_result {
            Err(error) => error,
            Ok(()) => panic!("client network handshake accepted a silent peer"),
        };
        for error in [operator_error, client_error] {
            assert!(error.to_string().contains("timed out"), "{error:#}");
        }
    }

    #[tokio::test]
    async fn tcp_bridge_cancels_the_other_direction_after_an_io_error() {
        let (right, _right_peer) = duplex(64);

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            bridge_tcp_streams(ReadErrorStream, right),
        )
        .await
        .expect("TCP bridge left its reverse direction running after an I/O error")
        .unwrap_err();

        assert!(error.to_string().contains("failed to copy TCP tunnel data"));
    }

    async fn memory_session() -> (
        OperatorNetworkSession,
        tokio::task::JoinHandle<anyhow::Result<()>>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let (client_io, server_io) = duplex(64 * 1024);
        let server_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let result: anyhow::Result<()> = async {
                let mut server_builder = h2::server::Builder::new();
                configure_server_builder(&mut server_builder);
                let mut connection = server_builder.handshake::<_, Bytes>(server_io).await?;
                while let Some(request) = connection.accept().await {
                    let (request, mut respond) = request?;
                    tokio::spawn(async move {
                        let result: anyhow::Result<()> = async {
                            let response = http::Response::builder().status(200).body(())?;
                            let mut send = respond.send_response(response, false)?;
                            let mut receive = request.into_body();
                            while let Some(frame) = receive.data().await {
                                let frame = frame?;
                                receive.flow_control().release_capacity(frame.len())?;
                                super::send_h2_data(&mut send, frame, false).await?;
                            }
                            super::send_h2_data(&mut send, Bytes::new(), true).await?;
                            Ok(())
                        }
                        .await;
                        assert!(result.is_ok(), "test H2 echo stream failed: {result:?}");
                    });
                }
                Ok(())
            }
            .await;
            if let Err(error) = &result {
                eprintln!("test H2 server failed: {error:#}");
            }
            result
        });
        let mut client_builder = h2::client::Builder::new();
        configure_client_builder(&mut client_builder);
        let (requests, connection) = client_builder
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        let client_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            connection.await?;
            Ok(())
        });
        let session = OperatorNetworkSession {
            requests,
            flow_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
            resolver_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_RESOLVER_REQUESTS,
            )),
        };
        (session, client_task, server_task)
    }

    #[tokio::test]
    async fn udp_success_requires_negotiation_and_a_peer_and_preserves_datagram_order() {
        let peer: SocketAddr = "[2001:db8::7]:5353".parse().unwrap();
        let (client_io, server_io) = duplex(64 * 1024);
        let server_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            configure_server_builder(&mut builder);
            let mut connection = builder.handshake::<_, Bytes>(server_io).await?;
            let Some(request) = connection.accept().await else {
                anyhow::bail!("test H2 client did not open the first CONNECT-UDP stream");
            };
            let (_request, mut respond) = request?;
            let mut response = http::Response::builder().status(200).body(())?;
            write_udp_peer_header(response.headers_mut(), peer)?;
            respond.send_response(response, true)?;

            let Some(request) = connection.accept().await else {
                anyhow::bail!("test H2 client did not open the second CONNECT-UDP stream");
            };
            let (_request, mut respond) = request?;
            let mut response = http::Response::builder().status(200).body(())?;
            response.headers_mut().insert(
                super::CAPSULE_PROTOCOL_HEADER,
                HeaderValue::from_static(super::CAPSULE_PROTOCOL_VALUE),
            );
            respond.send_response(response, true)?;

            let Some(request) = connection.accept().await else {
                anyhow::bail!("test H2 client did not open the third CONNECT-UDP stream");
            };
            let (_request, mut respond) = request?;
            let mut response = http::Response::builder().status(200).body(())?;
            response.headers_mut().insert(
                super::CAPSULE_PROTOCOL_HEADER,
                HeaderValue::from_static(super::CAPSULE_PROTOCOL_VALUE),
            );
            write_udp_peer_header(response.headers_mut(), peer)?;
            let mut send = respond.send_response(response, false)?;
            let first = encode_udp_capsule(&UdpCapsule::Datagram(Bytes::from_static(b"first")))?;
            let second = encode_udp_capsule(&UdpCapsule::Datagram(Bytes::from_static(b"second")))?;
            let reported_error = encode_udp_capsule(&UdpCapsule::Error(NetworkError::new(
                NetworkErrorKind::ConnectionRefused,
                "test error",
            )))?;
            let mut coalesced =
                Vec::with_capacity(first.len() + second.len() + reported_error.len());
            coalesced.extend_from_slice(&first);
            coalesced.extend_from_slice(&second);
            coalesced.extend_from_slice(&reported_error);
            super::send_h2_data(&mut send, Bytes::from(coalesced), true).await?;
            while connection.accept().await.is_some() {}
            Ok(())
        });

        let mut builder = h2::client::Builder::new();
        configure_client_builder(&mut builder);
        let (requests, mut connection) = builder.handshake::<_, Bytes>(client_io).await.unwrap();
        let mut ping_pong = connection.ping_pong().unwrap();
        let client_task = tokio::spawn(async move {
            connection.await?;
            Ok::<(), anyhow::Error>(())
        });
        ping_pong.ping(h2::Ping::opaque()).await.unwrap();
        let session = OperatorNetworkSession {
            requests,
            flow_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            resolver_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_RESOLVER_REQUESTS,
            )),
        };

        let missing_negotiation_error = session
            .open_udp(NetworkTarget::new("192.0.2.7", 5353).unwrap())
            .await
            .err()
            .expect("CONNECT-UDP unexpectedly accepted a success response without negotiation");
        assert_eq!(missing_negotiation_error.kind, NetworkErrorKind::Protocol);
        assert!(
            missing_negotiation_error
                .message
                .contains("did not negotiate capsule protocol")
        );

        let missing_peer_error = session
            .open_udp(NetworkTarget::new("192.0.2.7", 5353).unwrap())
            .await
            .err()
            .expect("CONNECT-UDP unexpectedly accepted a success response without its peer");
        assert_eq!(missing_peer_error.kind, NetworkErrorKind::Protocol);
        assert!(missing_peer_error.message.contains("connected-peer header"));

        let tunnel = session
            .open_udp(NetworkTarget::new("service.example", 5353).unwrap())
            .await
            .unwrap();
        assert_eq!(tunnel.peer_addr(), peer);
        let (sender, mut receiver) = tunnel.split();
        for expected in [b"first".as_slice(), b"second".as_slice()] {
            let datagram = receiver.receive_datagram().await.unwrap().unwrap();
            assert_eq!(datagram.data, Bytes::copy_from_slice(expected));
            receiver
                .release_receive_capacity(datagram.wire_bytes)
                .unwrap();
        }
        let reported_error = match receiver.receive_datagram().await {
            Err(error) => error,
            Ok(_) => panic!("UDP receiver did not report the peer's error capsule"),
        };
        assert_eq!(reported_error.kind, NetworkErrorKind::ConnectionRefused);
        assert!(receiver.receive_datagram().await.unwrap().is_none());

        drop(sender);
        drop(receiver);
        drop(session);
        client_task.abort();
        server_task.abort();
    }

    #[test]
    fn capsule_protocol_negotiation_is_unique_and_canonical() {
        assert!(validate_capsule_protocol_header(&HeaderMap::new(), "request").is_err());

        let mut headers = HeaderMap::new();
        headers.insert(
            super::CAPSULE_PROTOCOL_HEADER,
            HeaderValue::from_static(super::CAPSULE_PROTOCOL_VALUE),
        );
        validate_capsule_protocol_header(&headers, "request").unwrap();

        headers.append(
            super::CAPSULE_PROTOCOL_HEADER,
            HeaderValue::from_static(super::CAPSULE_PROTOCOL_VALUE),
        );
        assert!(validate_capsule_protocol_header(&headers, "request").is_err());

        for invalid in ["?0", "?1; parameter=1", "?1, ?1"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                super::CAPSULE_PROTOCOL_HEADER,
                HeaderValue::from_str(invalid).unwrap(),
            );
            assert!(validate_capsule_protocol_header(&headers, "response").is_err());
        }
    }

    #[tokio::test]
    async fn h2_download_cancellation_interrupts_a_blocked_destination_write() {
        let (session, client_task, server_task) = memory_session().await;
        let tunnel = session
            .connect_tcp(NetworkTarget::new("192.0.2.1", 443).unwrap())
            .await
            .unwrap();
        let (mut sender, receiver) = tunnel.split();
        let receive = receiver.receive;
        let cancellation = CancellationToken::new();
        let (started_tx, started_rx) = oneshot::channel();
        let pump = tokio::spawn(pump_h2_to_io(
            receive,
            PermanentlyBlockedWriter {
                started: Some(started_tx),
            },
            cancellation.clone(),
        ));

        sender.write_all(b"blocked").await.unwrap();
        let operation = tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("H2 download never reached the destination write")
            .unwrap();
        assert_eq!(operation, BlockedWriterOperation::Write);
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .expect("H2 download did not stop after cancellation")
            .unwrap()
            .unwrap();

        drop(sender);
        drop(session);
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn h2_download_cancellation_interrupts_a_blocked_destination_shutdown() {
        let (session, client_task, server_task) = memory_session().await;
        let tunnel = session
            .connect_tcp(NetworkTarget::new("192.0.2.1", 443).unwrap())
            .await
            .unwrap();
        let (mut sender, receiver) = tunnel.split();
        let receive = receiver.receive;
        let cancellation = CancellationToken::new();
        let (started_tx, started_rx) = oneshot::channel();
        let pump = tokio::spawn(pump_h2_to_io(
            receive,
            PermanentlyBlockedWriter {
                started: Some(started_tx),
            },
            cancellation.clone(),
        ));

        sender.shutdown().await.unwrap();
        let operation = tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("H2 download never reached destination shutdown")
            .unwrap();
        assert_eq!(operation, BlockedWriterOperation::Shutdown);
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .expect("H2 download shutdown did not stop after cancellation")
            .unwrap()
            .unwrap();

        drop(sender);
        drop(session);
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn h2_upload_half_close_does_not_wait_for_connection_data_credit() {
        const DEFAULT_H2_WINDOW_BYTES: usize = 65_535;

        let (client_io, server_io) = duplex(256 * 1024);
        let server_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await?;

            let Some(first_request) = connection.accept().await else {
                anyhow::bail!("test client did not open the window-consuming stream");
            };
            let (first_request, mut first_respond) = first_request?;
            let first_response = http::Response::builder().status(200).body(())?;
            first_respond.send_response(first_response, true)?;
            let _retained_first_body = first_request.into_body();

            let Some(second_request) = connection.accept().await else {
                anyhow::bail!("test client did not open the half-closing stream");
            };
            let (second_request, mut second_respond) = second_request?;
            let second_response = http::Response::builder().status(200).body(())?;
            second_respond.send_response(second_response, true)?;
            let mut second_body = second_request.into_body();
            let half_close = async {
                if second_body.data().await.is_some() {
                    anyhow::bail!("TCP half-close unexpectedly carried a DATA frame");
                }
                let Some(trailers) = second_body.trailers().await? else {
                    anyhow::bail!("TCP half-close did not use its canonical empty trailers");
                };
                if !trailers.is_empty() {
                    anyhow::bail!("TCP half-close unexpectedly carried non-empty trailers");
                }
                Ok::<(), anyhow::Error>(())
            };
            tokio::pin!(half_close);
            tokio::time::timeout(Duration::from_secs(1), async {
                tokio::select! {
                    result = &mut half_close => result,
                    request = connection.accept() => match request {
                        Some(Ok(_)) => anyhow::bail!(
                            "test client opened an unexpected third stream"
                        ),
                        Some(Err(error)) => Err(error.into()),
                        None => anyhow::bail!(
                            "test HTTP/2 connection closed before the TCP half-close"
                        ),
                    }
                }
            })
            .await
            .expect("half-close did not arrive while the connection DATA window was zero")?;
            Ok(())
        });

        let (requests, connection) = h2::client::handshake(client_io).await.unwrap();
        let client_task = tokio::spawn(async move {
            connection.await?;
            Ok::<(), anyhow::Error>(())
        });

        let first_request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("window.test:443")
            .body(())
            .unwrap();
        let (first_response, mut first_send) = requests
            .clone()
            .ready()
            .await
            .unwrap()
            .send_request(first_request, false)
            .unwrap();
        first_response.await.unwrap();
        super::send_h2_data(
            &mut first_send,
            Bytes::from(vec![0_u8; DEFAULT_H2_WINDOW_BYTES]),
            false,
        )
        .await
        .unwrap();

        let second_request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("half-close.test:443")
            .body(())
            .unwrap();
        let (second_response, second_send) = requests
            .clone()
            .ready()
            .await
            .unwrap()
            .send_request(second_request, false)
            .unwrap();
        second_response.await.unwrap();
        let (_second_send, result) = tokio::time::timeout(
            Duration::from_secs(1),
            pump_io_to_h2(tokio::io::empty(), second_send, CancellationToken::new()),
        )
        .await
        .expect("EOF handling waited for unavailable HTTP/2 DATA credit");
        result.unwrap();

        server_task.await.unwrap().unwrap();
        drop(first_send);
        drop(requests);
        client_task.abort();
    }

    async fn policy_session(
        approved_session: OfferedSession,
    ) -> (
        OperatorNetworkSession,
        NetworkSessionRuntime,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let (operator_io, client_io) = duplex(64 * 1024);
        let operator_websocket =
            WebSocketStream::from_raw_socket(operator_io, Role::Client, None).await;
        let client_websocket =
            WebSocketStream::from_raw_socket(client_io, Role::Server, None).await;
        let client_task = tokio::spawn(run_client_network_session(
            client_websocket,
            approved_session,
        ));
        let (session, runtime) = start_operator_network_session(operator_websocket)
            .await
            .unwrap();
        (session, runtime, client_task)
    }

    #[tokio::test]
    async fn client_udp_flow_negotiates_capsules_and_preserves_a_datagram() {
        let echo_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo_socket.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            let (size, peer) = echo_socket.recv_from(&mut buffer).await.unwrap();
            echo_socket.send_to(&buffer[..size], peer).await.unwrap();
        });
        let (session, runtime, client_task) = policy_session(OfferedSession::Socks {}).await;

        let tunnel = session.open_udp(echo_address.into()).await.unwrap();
        assert_eq!(tunnel.peer_addr(), echo_address);
        let (mut sender, mut receiver) = tunnel.split();
        sender
            .send_datagram(Bytes::from_static(b"capsule round trip"))
            .await
            .unwrap();
        let datagram = tokio::time::timeout(Duration::from_secs(2), receiver.receive_datagram())
            .await
            .expect("client did not return the UDP response")
            .unwrap()
            .expect("client ended the UDP association before returning its response");
        assert_eq!(datagram.data, Bytes::from_static(b"capsule round trip"));
        receiver
            .release_receive_capacity(datagram.wire_bytes)
            .unwrap();

        drop(sender);
        drop(receiver);
        drop(session);
        drop(runtime);
        client_task.abort();
        let _ = client_task.await;
        echo_task.await.unwrap();
    }

    #[tokio::test]
    async fn multi_megabyte_tcp_stream_is_lossless_beyond_old_queue_cliff() {
        let (session, client_task, server_task) = memory_session().await;
        let tunnel = session
            .connect_tcp(NetworkTarget::new("192.0.2.1", 443).unwrap())
            .await
            .unwrap();
        let (application, proxy) = duplex(32 * 1024);
        let bridge = tokio::spawn(bridge_operator_tcp(proxy, tunnel));
        let payload = (0..5 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let expected = payload.clone();
        let (mut application_reader, mut application_writer) = tokio::io::split(application);
        let writer = tokio::spawn(async move {
            application_writer.write_all(&payload).await.unwrap();
            application_writer.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut echoed = Vec::new();
            application_reader.read_to_end(&mut echoed).await.unwrap();
            echoed
        });
        let (writer_result, reader_result) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(writer, reader)
        })
        .await
        .unwrap();
        writer_result.unwrap();
        let echoed = reader_result.unwrap();
        assert_eq!(echoed, expected);
        bridge.await.unwrap().unwrap();
        drop(session);
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn selective_policy_rejects_unapproved_streams_without_ending_the_session() {
        let policy = SystemVpnPolicy::new(
            vec!["10.20.0.0/16".parse().unwrap()],
            vec!["allowed.example".to_string()],
        )
        .unwrap();
        let (session, runtime, client_task) = policy_session(OfferedSession::Vpn {
            scope: VpnScope::System { policy },
        })
        .await;

        let tcp_error = tokio::time::timeout(
            Duration::from_secs(2),
            session.connect_tcp(NetworkTarget::new("192.0.2.1", 443).unwrap()),
        )
        .await
        .expect("selective policy TCP rejection timed out")
        .err()
        .expect("selective policy unexpectedly opened a TCP destination");
        assert_eq!(tcp_error.kind, NetworkErrorKind::PermissionDenied);

        let udp_error = tokio::time::timeout(
            Duration::from_secs(2),
            session.open_udp(NetworkTarget::new("blocked.example", 53).unwrap()),
        )
        .await
        .expect("selective policy UDP rejection timed out")
        .err()
        .expect("selective policy unexpectedly opened a UDP destination");
        assert_eq!(udp_error.kind, NetworkErrorKind::PermissionDenied);

        let resolver_error = tokio::time::timeout(
            Duration::from_secs(2),
            session.resolve(ResolveRequest::new("blocked.example", 1, 1, 1_000).unwrap()),
        )
        .await
        .expect("selective policy resolver rejection timed out")
        .unwrap_err();
        assert_eq!(resolver_error.kind, NetworkErrorKind::PermissionDenied);

        let final_error = tokio::time::timeout(
            Duration::from_secs(2),
            session.connect_tcp(NetworkTarget::new("198.51.100.1", 443).unwrap()),
        )
        .await
        .expect("network session stopped accepting streams after policy rejections")
        .err()
        .expect("selective policy unexpectedly opened the final TCP destination");
        assert_eq!(final_error.kind, NetworkErrorKind::PermissionDenied);

        drop(session);
        drop(runtime);
        client_task.abort();
        let _ = client_task.await;
    }

    #[tokio::test]
    async fn sessions_without_domain_routing_reject_resolver_streams() {
        let cidr_only =
            SystemVpnPolicy::new(vec!["10.20.0.0/16".parse().unwrap()], Vec::new()).unwrap();
        for approved_session in [
            OfferedSession::Socks {},
            OfferedSession::Vpn {
                scope: VpnScope::Application {
                    application: "Firefox".to_string(),
                },
            },
            OfferedSession::Vpn {
                scope: VpnScope::System { policy: cidr_only },
            },
        ] {
            let (session, runtime, client_task) = policy_session(approved_session).await;

            let error = tokio::time::timeout(
                Duration::from_secs(2),
                session.resolve(ResolveRequest::new("blocked.example", 1, 1, 1_000).unwrap()),
            )
            .await
            .expect("resolver stream policy rejection timed out")
            .unwrap_err();
            assert_eq!(error.kind, NetworkErrorKind::PermissionDenied);

            drop(session);
            drop(runtime);
            client_task.abort();
            let _ = client_task.await;
        }
    }
}
