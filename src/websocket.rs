use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use futures_util::{Sink, SinkExt, StreamExt, stream::SplitStream};
use hyper::Uri;
use hyper::header::HeaderValue;
use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use pin_project_lite::pin_project;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_platform_verifier::Verifier;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{
        Error as WebSocketError, Message, handshake::client::Response, protocol::WebSocketConfig,
    },
};
use tokio_util::io::StreamReader;
use tokio_util::sync::PollSender;
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::DEFAULT_CONNECT_PATH;

pub trait AsyncStream: AsyncRead + AsyncWrite + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send {}

pub trait WebSocketClientTransport: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> WebSocketClientTransport for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type ClientWebSocketStream = WebSocketStream<MaybeTlsStream<Box<dyn WebSocketClientTransport>>>;

const MAX_PROXY_RESPONSE_HEADER_BYTES: usize = 8192;
const MAX_WEBSOCKET_IO_WRITE_BYTES: usize = 16 * 1024;
const WEBSOCKET_BUFFER_BYTES: usize = 64 * 1024;
const MAX_WEBSOCKET_WRITE_BUFFER_BYTES: usize = 256 * 1024;
const WEBSOCKET_WRITER_QUEUE_FRAMES: usize = WEBSOCKET_BUFFER_BYTES / MAX_WEBSOCKET_IO_WRITE_BYTES;

#[derive(Clone, Copy)]
struct WebSocketConnectTimeouts {
    overall: Duration,
    tcp: Duration,
    proxy_tls: Duration,
    proxy_tunnel: Duration,
    websocket: Duration,
}

const WEBSOCKET_CONNECT_TIMEOUTS: WebSocketConnectTimeouts = WebSocketConnectTimeouts {
    overall: Duration::from_secs(45),
    tcp: Duration::from_secs(15),
    proxy_tls: Duration::from_secs(15),
    proxy_tunnel: Duration::from_secs(15),
    websocket: Duration::from_secs(20),
};

pin_project! {
    struct DuplexIo<R, W> {
        #[pin]
        reader: R,
        #[pin]
        writer: W,
    }
}

enum WebSocketWriteCommand {
    Data(Bytes),
    Flush(oneshot::Sender<()>),
    Shutdown,
}

enum WebSocketWriterState {
    Open,
    Flushing(oneshot::Receiver<()>),
    ReservingShutdown,
    ShuttingDown,
    Closed,
    Failed(StoredIoError),
}

struct StoredIoError {
    kind: io::ErrorKind,
    message: String,
}

struct WebSocketWriter {
    commands: PollSender<WebSocketWriteCommand>,
    state: WebSocketWriterState,
    pump: Option<AbortOnDropHandle<io::Result<()>>>,
}

impl<R, W> AsyncRead for DuplexIo<R, W>
where
    R: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().reader.poll_read(cx, read_buf)
    }
}

impl<R, W> AsyncWrite for DuplexIo<R, W>
where
    W: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().writer.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().writer.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().writer.poll_shutdown(cx)
    }
}

impl AsyncWrite for WebSocketWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if matches!(this.state, WebSocketWriterState::Flushing(_)) {
            match this.poll_flush_barrier(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match &this.state {
            WebSocketWriterState::Open => {}
            WebSocketWriterState::ReservingShutdown
            | WebSocketWriterState::ShuttingDown
            | WebSocketWriterState::Closed => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "websocket writer is shut down",
                )));
            }
            WebSocketWriterState::Failed(error) => {
                return Poll::Ready(Err(error.to_io_error()));
            }
            WebSocketWriterState::Flushing(_) => {
                unreachable!("the flush barrier was completed before writing")
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match this.commands.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return this.poll_closed_channel_for_write(cx),
            Poll::Pending => return Poll::Pending,
        }
        let write_len = buf.len().min(MAX_WEBSOCKET_IO_WRITE_BYTES);
        if this
            .commands
            .send_item(WebSocketWriteCommand::Data(Bytes::copy_from_slice(
                &buf[..write_len],
            )))
            .is_err()
        {
            return this.poll_closed_channel_for_write(cx);
        }
        Poll::Ready(Ok(write_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_inner(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown_inner(cx)
    }
}

impl StoredIoError {
    fn new(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

impl WebSocketWriter {
    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.state {
                WebSocketWriterState::Open => {
                    match self.commands.poll_reserve(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_)) => return self.poll_closed_channel(cx),
                        Poll::Pending => return Poll::Pending,
                    }
                    let (completed, completion) = oneshot::channel();
                    if self
                        .commands
                        .send_item(WebSocketWriteCommand::Flush(completed))
                        .is_err()
                    {
                        return self.poll_closed_channel(cx);
                    }
                    self.state = WebSocketWriterState::Flushing(completion);
                }
                WebSocketWriterState::Flushing(_) => return self.poll_flush_barrier(cx),
                WebSocketWriterState::ReservingShutdown | WebSocketWriterState::ShuttingDown => {
                    return self.poll_shutdown_inner(cx);
                }
                WebSocketWriterState::Closed => return Poll::Ready(Ok(())),
                WebSocketWriterState::Failed(ref error) => {
                    return Poll::Ready(Err(error.to_io_error()));
                }
            }
        }
    }

    fn poll_flush_barrier(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let WebSocketWriterState::Flushing(completion) = &mut self.state else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(completion).poll(cx) {
            Poll::Ready(Ok(())) => {
                self.state = WebSocketWriterState::Open;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => self.poll_closed_channel(cx),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.state {
                WebSocketWriterState::Open => {
                    self.state = WebSocketWriterState::ReservingShutdown;
                }
                WebSocketWriterState::Flushing(_) => match self.poll_flush_barrier(cx) {
                    Poll::Ready(Ok(())) => {}
                    result => return result,
                },
                WebSocketWriterState::ReservingShutdown => {
                    match self.commands.poll_reserve(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_)) => return self.poll_closed_channel(cx),
                        Poll::Pending => return Poll::Pending,
                    }
                    if self
                        .commands
                        .send_item(WebSocketWriteCommand::Shutdown)
                        .is_err()
                    {
                        return self.poll_closed_channel(cx);
                    }
                    self.commands.close();
                    self.state = WebSocketWriterState::ShuttingDown;
                }
                WebSocketWriterState::ShuttingDown => return self.poll_pump_completion(cx),
                WebSocketWriterState::Closed => return Poll::Ready(Ok(())),
                WebSocketWriterState::Failed(ref error) => {
                    return Poll::Ready(Err(error.to_io_error()));
                }
            }
        }
    }

    fn poll_closed_channel(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pump_completion(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket writer pump stopped unexpectedly",
            ))),
            result => result,
        }
    }

    fn poll_closed_channel_for_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        match self.poll_closed_channel(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                unreachable!("a closed writer channel always reports an I/O error")
            }
        }
    }

    fn poll_pump_completion(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let WebSocketWriterState::Failed(error) = &self.state {
            return Poll::Ready(Err(error.to_io_error()));
        }
        if matches!(self.state, WebSocketWriterState::Closed) {
            return Poll::Ready(Ok(()));
        }
        let Some(pump) = &mut self.pump else {
            return Poll::Pending;
        };
        let result = match Pin::new(pump).poll(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => return Poll::Pending,
        };
        self.pump = None;
        match result {
            Ok(Ok(())) => {
                self.state = WebSocketWriterState::Closed;
                Poll::Ready(Ok(()))
            }
            Ok(Err(error)) => Poll::Ready(Err(self.fail(error))),
            Err(error) => Poll::Ready(Err(self.fail(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("websocket writer pump failed to join: {error}"),
            )))),
        }
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        let error = StoredIoError::new(error);
        let result = error.to_io_error();
        self.state = WebSocketWriterState::Failed(error);
        result
    }
}

fn start_websocket_writer<W>(sink: W) -> WebSocketWriter
where
    W: Sink<Message, Error = WebSocketError> + Unpin + Send + 'static,
{
    start_websocket_writer_with_capacity(sink, WEBSOCKET_WRITER_QUEUE_FRAMES)
}

fn start_websocket_writer_with_capacity<W>(sink: W, capacity: usize) -> WebSocketWriter
where
    W: Sink<Message, Error = WebSocketError> + Unpin + Send + 'static,
{
    let (commands, receiver) = mpsc::channel(capacity);
    // A write is acknowledged only after the bounded channel owns its bytes, and
    // this handle prevents the sink-driving task from outliving the adapter.
    let pump = AbortOnDropHandle::new(tokio::spawn(run_websocket_writer(sink, receiver)));
    WebSocketWriter {
        commands: PollSender::new(commands),
        state: WebSocketWriterState::Open,
        pump: Some(pump),
    }
}

async fn run_websocket_writer<W>(
    mut sink: W,
    mut commands: mpsc::Receiver<WebSocketWriteCommand>,
) -> io::Result<()>
where
    W: Sink<Message, Error = WebSocketError> + Unpin,
{
    while let Some(command) = commands.recv().await {
        match command {
            WebSocketWriteCommand::Data(data) => sink
                .send(Message::Binary(data))
                .await
                .map_err(map_websocket_error)?,
            WebSocketWriteCommand::Flush(completed) => {
                sink.flush().await.map_err(map_websocket_error)?;
                let _ = completed.send(());
            }
            WebSocketWriteCommand::Shutdown => {
                sink.close().await.map_err(map_websocket_error)?;
                return Ok(());
            }
        }
    }
    Ok(())
}

pub async fn connect_async_with_env_proxy(url: &Url) -> Result<(ClientWebSocketStream, Response)> {
    connect_async_with_env_proxy_and_extra_roots(url, Vec::new()).await
}

pub async fn connect_async_with_env_proxy_and_extra_roots(
    url: &Url,
    extra_roots: Vec<CertificateDer<'static>>,
) -> Result<(ClientWebSocketStream, Response)> {
    crate::install_default_rustls_crypto_provider();
    let matcher = Matcher::from_env();
    let tls_config = tls_client_config(extra_roots)?;
    connect_async_with_proxy_matcher_and_timeouts_with_tls(
        url,
        &matcher,
        WEBSOCKET_CONNECT_TIMEOUTS,
        tls_config,
    )
    .await
}

pub fn websocket_to_io<S>(websocket: WebSocketStream<S>) -> Pin<Box<dyn AsyncStream + 'static>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = websocket.split();
    Box::pin(DuplexIo {
        reader: StreamReader::new(websocket_reader(stream)),
        writer: start_websocket_writer(sink),
    })
}

fn websocket_reader<S>(
    stream: SplitStream<WebSocketStream<S>>,
) -> impl futures_util::stream::Stream<Item = io::Result<Bytes>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    stream.filter_map(|message_result| async move {
        match message_result {
            Ok(Message::Binary(bytes)) => Some(Ok(bytes)),
            Ok(Message::Text(_)) => Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received a websocket text frame during binary transport",
            ))),
            Ok(Message::Close(_)) => None,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => None,
            Err(error) => Some(Err(map_websocket_error(error))),
        }
    })
}

fn map_websocket_error(error: WebSocketError) -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        format!("websocket transport error: {error}"),
    )
}

#[cfg(test)]
async fn connect_async_with_proxy_matcher(
    url: &Url,
    matcher: &Matcher,
) -> Result<(ClientWebSocketStream, Response)> {
    connect_async_with_proxy_matcher_and_timeouts(url, matcher, WEBSOCKET_CONNECT_TIMEOUTS).await
}

#[cfg(test)]
async fn connect_async_with_proxy_matcher_and_timeouts(
    url: &Url,
    matcher: &Matcher,
    timeouts: WebSocketConnectTimeouts,
) -> Result<(ClientWebSocketStream, Response)> {
    connect_async_with_proxy_matcher_and_timeouts_with_tls(
        url,
        matcher,
        timeouts,
        tls_client_config(Vec::new())?,
    )
    .await
}

async fn connect_async_with_proxy_matcher_and_timeouts_with_tls(
    url: &Url,
    matcher: &Matcher,
    timeouts: WebSocketConnectTimeouts,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<(ClientWebSocketStream, Response)> {
    let overall_deadline = Instant::now() + timeouts.overall;
    let maybe_proxy = selected_proxy_for_websocket_url(matcher, url)?;
    let stream = match maybe_proxy {
        Some(proxy) => {
            connect_via_proxy(
                url,
                &proxy,
                overall_deadline,
                timeouts,
                Arc::clone(&tls_config),
            )
            .await?
        }
        None => connect_direct(url, overall_deadline, timeouts).await?,
    };

    let connector = match url.scheme() {
        "wss" => Some(Connector::Rustls(tls_config)),
        "ws" => None,
        unsupported => bail!("unsupported websocket URL scheme `{unsupported}`"),
    };

    run_connect_phase(
        overall_deadline,
        timeouts.websocket,
        "websocket handshake",
        client_async_tls_with_config(url.as_str(), stream, Some(websocket_config()), connector),
    )
    .await?
    .context("failed to complete websocket handshake")
}

pub fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(WEBSOCKET_BUFFER_BYTES)
        .write_buffer_size(WEBSOCKET_BUFFER_BYTES)
        .max_write_buffer_size(MAX_WEBSOCKET_WRITE_BUFFER_BYTES)
        .max_message_size(Some(WEBSOCKET_BUFFER_BYTES))
        .max_frame_size(Some(WEBSOCKET_BUFFER_BYTES))
}

fn selected_proxy_for_websocket_url(matcher: &Matcher, url: &Url) -> Result<Option<Intercept>> {
    let destination_uri = websocket_destination_uri(url)?;
    Ok(matcher.intercept(&destination_uri))
}

fn websocket_destination_uri(url: &Url) -> Result<Uri> {
    let mut destination_url = url.clone();
    match destination_url.scheme() {
        "ws" => {
            destination_url
                .set_scheme("http")
                .map_err(|_| anyhow!("failed to convert ws URL to http"))?;
        }
        "wss" => {
            destination_url
                .set_scheme("https")
                .map_err(|_| anyhow!("failed to convert wss URL to https"))?;
        }
        unsupported => {
            bail!("unsupported websocket URL scheme `{unsupported}`");
        }
    }

    destination_url
        .as_str()
        .parse::<Uri>()
        .with_context(|| format!("failed to build proxy destination URI from `{destination_url}`"))
}

async fn connect_direct(
    url: &Url,
    overall_deadline: Instant,
    timeouts: WebSocketConnectTimeouts,
) -> Result<Box<dyn WebSocketClientTransport>> {
    let (host, port) = destination_host_and_port(url)?;
    let socket = open_tcp_stream(
        &host,
        port,
        "sshportal server",
        overall_deadline,
        timeouts.tcp,
    )
    .await?;
    Ok(Box::new(socket))
}

async fn connect_via_proxy(
    url: &Url,
    proxy: &Intercept,
    overall_deadline: Instant,
    timeouts: WebSocketConnectTimeouts,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<Box<dyn WebSocketClientTransport>> {
    let (proxy_host, proxy_port, proxy_scheme) = proxy_endpoint(proxy)?;
    let proxy_socket = open_tcp_stream(
        &proxy_host,
        proxy_port,
        "HTTP proxy",
        overall_deadline,
        timeouts.tcp,
    )
    .await?;
    let mut proxy_stream: Box<dyn WebSocketClientTransport> = match proxy_scheme.as_str() {
        "http" => Box::new(proxy_socket),
        "https" => Box::new(
            run_connect_phase(
                overall_deadline,
                timeouts.proxy_tls,
                "HTTPS proxy TLS handshake",
                connect_to_https_proxy(proxy_socket, &proxy_host, tls_config),
            )
            .await??,
        ),
        unsupported => {
            bail!(
                "unsupported proxy scheme `{unsupported}`; only http:// and https:// proxies are supported"
            );
        }
    };

    let (destination_host, destination_port) = destination_host_and_port(url)?;
    run_connect_phase(
        overall_deadline,
        timeouts.proxy_tunnel,
        "HTTP proxy CONNECT handshake",
        establish_connect_tunnel(
            proxy_stream.as_mut(),
            &destination_host,
            destination_port,
            proxy.basic_auth(),
        ),
    )
    .await??;

    Ok(proxy_stream)
}

fn destination_host_and_port(url: &Url) -> Result<(String, u16)> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("server URL `{url}` is missing a host"))?
        .to_string();
    let port = url.port_or_known_default().ok_or_else(|| {
        anyhow!(
            "server URL `{url}` is missing a known default port for scheme `{}`",
            url.scheme()
        )
    })?;
    Ok((host, port))
}

fn proxy_endpoint(proxy: &Intercept) -> Result<(String, u16, String)> {
    let proxy_uri = proxy.uri();
    let proxy_scheme = proxy_uri
        .scheme_str()
        .ok_or_else(|| anyhow!("proxy URI `{proxy_uri}` is missing a scheme"))?
        .to_string();
    let proxy_host = proxy_uri
        .host()
        .ok_or_else(|| anyhow!("proxy URI `{proxy_uri}` is missing a host"))?
        .to_string();
    let default_port = match proxy_scheme.as_str() {
        "http" => 80,
        "https" => 443,
        unsupported => {
            bail!("unsupported proxy scheme `{unsupported}`");
        }
    };
    let proxy_port = proxy_uri.port_u16().unwrap_or(default_port);
    Ok((proxy_host, proxy_port, proxy_scheme))
}

async fn open_tcp_stream(
    host: &str,
    port: u16,
    description: &str,
    overall_deadline: Instant,
    timeout: Duration,
) -> Result<TcpStream> {
    let authority = format_authority(host, port);
    let socket = run_connect_phase(
        overall_deadline,
        timeout,
        &format!("TCP connection to {description}"),
        TcpStream::connect((host, port)),
    )
    .await?
    .with_context(|| format!("failed to connect to {description} at {authority}"))?;
    socket.set_nodelay(true).with_context(|| {
        format!("failed to enable TCP_NODELAY for {description} at {authority}")
    })?;
    Ok(socket)
}

async fn run_connect_phase<F, T>(
    overall_deadline: Instant,
    phase_timeout: Duration,
    description: &str,
    future: F,
) -> Result<T>
where
    F: Future<Output = T>,
{
    let phase_deadline = overall_deadline.min(Instant::now() + phase_timeout);
    tokio::time::timeout_at(phase_deadline, future)
        .await
        .with_context(|| format!("{description} timed out"))
}

async fn connect_to_https_proxy(
    socket: TcpStream,
    proxy_host: &str,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = ServerName::try_from(proxy_host.to_string())
        .map_err(|_| anyhow!("proxy host `{proxy_host}` is not a valid TLS server name"))?;
    let connector = TlsConnector::from(tls_config);
    connector
        .connect(server_name, socket)
        .await
        .with_context(|| format!("failed to negotiate TLS with HTTPS proxy `{proxy_host}`"))
}

fn tls_client_config(
    extra_roots: Vec<CertificateDer<'static>>,
) -> Result<Arc<rustls::ClientConfig>> {
    static TLS_CLIENT_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

    if extra_roots.is_empty() {
        if let Some(config) = TLS_CLIENT_CONFIG.get() {
            return Ok(Arc::clone(config));
        }
        let config = build_tls_client_config(extra_roots)?;
        return Ok(Arc::clone(TLS_CLIENT_CONFIG.get_or_init(|| config)));
    }

    build_tls_client_config(extra_roots)
}

fn build_tls_client_config(
    extra_roots: Vec<CertificateDer<'static>>,
) -> Result<Arc<rustls::ClientConfig>> {
    crate::install_default_rustls_crypto_provider();
    let builder = rustls::ClientConfig::builder();
    let verifier = if extra_roots.is_empty() {
        Verifier::new(builder.crypto_provider().clone())
    } else {
        Verifier::new_with_extra_roots(extra_roots, builder.crypto_provider().clone())
    }
    .context("failed to initialize platform TLS certificate verification")?;
    Ok(Arc::new(
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth(),
    ))
}

async fn establish_connect_tunnel(
    stream: &mut dyn WebSocketClientTransport,
    destination_host: &str,
    destination_port: u16,
    proxy_auth: Option<&HeaderValue>,
) -> Result<()> {
    let authority = format_authority(destination_host, destination_port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n").into_bytes();
    if let Some(header) = proxy_auth {
        request.extend_from_slice(b"Proxy-Authorization: ");
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");

    stream
        .write_all(&request)
        .await
        .context("failed to send CONNECT request to proxy")?;
    stream
        .flush()
        .await
        .context("failed to flush CONNECT request to proxy")?;

    let response = read_proxy_response_headers(stream).await?;
    validate_connect_response(&response)
}

async fn read_proxy_response_headers(stream: &mut dyn WebSocketClientTransport) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let bytes_read = stream
            .read(&mut chunk)
            .await
            .context("failed to read proxy CONNECT response")?;
        if bytes_read == 0 {
            bail!("proxy closed the connection before finishing the CONNECT handshake");
        }

        response.extend_from_slice(&chunk[..bytes_read]);
        if let Some(header_end) = header_terminator_offset(&response) {
            if header_end + 4 > MAX_PROXY_RESPONSE_HEADER_BYTES {
                bail!(
                    "proxy CONNECT response headers exceeded {MAX_PROXY_RESPONSE_HEADER_BYTES} bytes"
                );
            }
            return Ok(response);
        }
        if response.len() >= MAX_PROXY_RESPONSE_HEADER_BYTES {
            bail!(
                "proxy CONNECT response headers exceeded {MAX_PROXY_RESPONSE_HEADER_BYTES} bytes"
            );
        }
    }
}

fn validate_connect_response(response: &[u8]) -> Result<()> {
    let Some(header_end) = header_terminator_offset(response) else {
        bail!("proxy CONNECT response was truncated");
    };
    let status_line_end = response[..header_end]
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(header_end);
    let status_line = std::str::from_utf8(&response[..status_line_end])
        .context("proxy CONNECT status line was not valid ASCII text")?;
    let mut fields = status_line.splitn(3, ' ');
    let version = fields
        .next()
        .ok_or_else(|| anyhow!("proxy CONNECT response was empty"))?;
    let status = fields
        .next()
        .filter(|status| status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| anyhow!("proxy CONNECT response had an invalid status line"))?;
    if fields.next().is_none() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        bail!("proxy CONNECT response had an invalid status line");
    }
    if status == "200" {
        return Ok(());
    }
    if status == "407" {
        bail!("proxy authentication was rejected");
    }
    bail!("proxy CONNECT failed with HTTP status {status}");
}

fn header_terminator_offset(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        return format!("[{host}]:{port}");
    }
    format!("{host}:{port}")
}

pub fn normalize_websocket_url(raw_server: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(raw_server)
        .map_err(|error| anyhow::anyhow!("failed to parse server URL `{raw_server}`: {error}"))?;
    match url.scheme() {
        "http" => {
            url.set_scheme("ws")
                .map_err(|_| anyhow::anyhow!("failed to convert http URL to ws"))?;
        }
        "https" => {
            url.set_scheme("wss")
                .map_err(|_| anyhow::anyhow!("failed to convert https URL to wss"))?;
        }
        "ws" | "wss" => {}
        unsupported => {
            anyhow::bail!("unsupported URL scheme `{unsupported}`");
        }
    }

    if url.path().is_empty() || url.path() == "/" {
        url.set_path(DEFAULT_CONNECT_PATH);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use futures_util::Sink;
    use hyper_util::client::proxy::matcher::Matcher;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};

    use super::{
        WebSocketConnectTimeouts, connect_async_with_proxy_matcher,
        connect_async_with_proxy_matcher_and_timeouts, normalize_websocket_url,
        selected_proxy_for_websocket_url, start_websocket_writer_with_capacity, tls_client_config,
        validate_connect_response,
    };

    struct FlushRecordingSink {
        pending: Option<bytes::Bytes>,
        delivered: mpsc::UnboundedSender<bytes::Bytes>,
    }

    impl Sink<Message> for FlushRecordingSink {
        type Error = WebSocketError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            assert!(self.pending.is_none());
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            if let Message::Binary(bytes) = item {
                self.pending = Some(bytes);
            }
            Ok(())
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if let Some(frame) = self.pending.take() {
                let _ = self.delivered.send(frame);
            }
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.as_mut().poll_flush(cx)
        }
    }

    struct GatedFlushSink {
        observed: mpsc::UnboundedSender<bytes::Bytes>,
        flush_allowed: Arc<AtomicBool>,
        flush_waker: Arc<Mutex<Option<Waker>>>,
    }

    impl Sink<Message> for GatedFlushSink {
        type Error = WebSocketError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            if let Message::Binary(bytes) = item {
                let _ = self.observed.send(bytes);
            }
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.flush_allowed.load(Ordering::SeqCst) {
                return Poll::Ready(Ok(()));
            }
            *self.flush_waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.poll_flush(cx)
        }
    }

    #[test]
    fn converts_http_to_websocket() {
        let url = normalize_websocket_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(url.as_str(), "ws://127.0.0.1:8080/connect");
    }

    #[test]
    fn selects_http_proxy_for_ws_urls() {
        let matcher = Matcher::builder()
            .http("http://proxy.internal:8080")
            .build();
        let url = normalize_websocket_url("http://service.internal:7000").unwrap();

        let proxy = selected_proxy_for_websocket_url(&matcher, &url)
            .unwrap()
            .unwrap();

        assert_eq!(proxy.uri().to_string(), "http://proxy.internal:8080/");
    }

    #[test]
    fn bypasses_proxy_when_no_proxy_matches() {
        let matcher = Matcher::builder()
            .https("http://proxy.internal:8080")
            .no("example.com")
            .build();
        let url = normalize_websocket_url("https://api.example.com").unwrap();

        let proxy = selected_proxy_for_websocket_url(&matcher, &url).unwrap();

        assert!(proxy.is_none());
    }

    #[test]
    fn platform_tls_configuration_initializes_once() {
        let first = tls_client_config(Vec::new()).unwrap();
        let second = tls_client_config(Vec::new()).unwrap();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn proxy_connect_status_requires_an_exact_http_status_token() {
        validate_connect_response(b"HTTP/1.1 200 Connection Established\r\nHeader: value\r\n\r\n")
            .unwrap();
        validate_connect_response(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();

        for response in [
            &b"HTTP/1.1 2000 Not A Status\r\n\r\n"[..],
            &b"HTTP/1.1 200x Not A Status\r\n\r\n"[..],
            &b"HTTP/2 200 Fine\r\n\r\n"[..],
            &b"HTTP/1.1 200\r\n\r\n"[..],
        ] {
            assert!(validate_connect_response(response).is_err());
        }
        assert!(
            validate_connect_response(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .unwrap_err()
                .to_string()
                .contains("authentication")
        );
    }

    #[tokio::test]
    async fn websocket_handshake_has_a_bounded_phase_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let url = normalize_websocket_url(&format!("ws://{address}")).unwrap();
        let timeouts = WebSocketConnectTimeouts {
            overall: Duration::from_secs(1),
            tcp: Duration::from_secs(1),
            proxy_tls: Duration::from_secs(1),
            proxy_tunnel: Duration::from_secs(1),
            websocket: Duration::from_millis(50),
        };

        let result = connect_async_with_proxy_matcher_and_timeouts(
            &url,
            &Matcher::builder().build(),
            timeouts,
        )
        .await;
        let error = match result {
            Ok(_) => panic!("a stalled websocket handshake unexpectedly completed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("websocket handshake timed out"));
        server.abort();
    }

    #[tokio::test]
    async fn proxy_connect_headers_have_a_bounded_phase_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _request = read_request_headers(&mut socket).await.unwrap();
            std::future::pending::<()>().await;
        });
        let matcher = Matcher::builder().http(format!("http://{address}")).build();
        let url = normalize_websocket_url("ws://server.invalid").unwrap();
        let timeouts = WebSocketConnectTimeouts {
            overall: Duration::from_secs(1),
            tcp: Duration::from_secs(1),
            proxy_tls: Duration::from_secs(1),
            proxy_tunnel: Duration::from_millis(50),
            websocket: Duration::from_secs(1),
        };

        let result = connect_async_with_proxy_matcher_and_timeouts(&url, &matcher, timeouts).await;
        let error = match result {
            Ok(_) => panic!("a stalled proxy CONNECT handshake unexpectedly completed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("HTTP proxy CONNECT handshake timed out")
        );
        proxy.abort();
    }

    #[tokio::test]
    async fn websocket_writer_delivers_without_a_caller_flush() {
        let (delivered, mut deliveries) = mpsc::unbounded_channel();
        let sink = FlushRecordingSink {
            pending: None,
            delivered,
        };
        let mut writer = start_websocket_writer_with_capacity(sink, 1);

        writer
            .write_all(b"SSH-2.0-identification\r\n")
            .await
            .unwrap();

        let delivered = tokio::time::timeout(Duration::from_secs(1), deliveries.recv())
            .await
            .expect("the writer pump did not autonomously flush accepted bytes")
            .unwrap();
        assert_eq!(delivered, &b"SSH-2.0-identification\r\n"[..]);
        writer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_backpressured_write_never_sends_its_buffer() {
        let (observed, mut observations) = mpsc::unbounded_channel();
        let flush_allowed = Arc::new(AtomicBool::new(false));
        let flush_waker = Arc::new(Mutex::new(None));
        let sink = GatedFlushSink {
            observed,
            flush_allowed: Arc::clone(&flush_allowed),
            flush_waker: Arc::clone(&flush_waker),
        };
        let mut writer = start_websocket_writer_with_capacity(sink, 1);

        writer.write_all(b"blocked-in-pump").await.unwrap();
        assert_eq!(observations.recv().await.unwrap(), &b"blocked-in-pump"[..]);
        writer.write_all(b"queued").await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(25), writer.write(b"cancelled"))
                .await
                .is_err()
        );

        flush_allowed.store(true, Ordering::SeqCst);
        if let Some(waker) = flush_waker.lock().unwrap().take() {
            waker.wake();
        }
        assert_eq!(observations.recv().await.unwrap(), &b"queued"[..]);

        writer.write_all(b"survived").await.unwrap();
        assert_eq!(observations.recv().await.unwrap(), &b"survived"[..]);
        writer.flush().await.unwrap();
        assert!(observations.try_recv().is_err());
        writer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn connects_through_http_proxy_tunnel_with_basic_auth() {
        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (socket, _) = server_listener.accept().await.unwrap();
            let _websocket = accept_async(socket).await.unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut inbound, _) = proxy_listener.accept().await.unwrap();
            let request = read_request_headers(&mut inbound).await.unwrap();
            let expected_authority = format!("127.0.0.1:{}", server_addr.port());
            assert!(request.starts_with(&format!(
                "CONNECT {expected_authority} HTTP/1.1\r\nHost: {expected_authority}\r\n"
            )));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));

            inbound
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();

            let mut outbound = TcpStream::connect(server_addr).await.unwrap();
            let websocket_request = read_request_headers(&mut inbound).await.unwrap();
            outbound
                .write_all(websocket_request.as_bytes())
                .await
                .unwrap();

            let websocket_response = read_request_headers(&mut outbound).await.unwrap();
            inbound
                .write_all(websocket_response.as_bytes())
                .await
                .unwrap();
        });

        let url =
            normalize_websocket_url(&format!("http://127.0.0.1:{}", server_addr.port())).unwrap();
        let matcher = Matcher::builder()
            .all(format!("http://user:pass@127.0.0.1:{}", proxy_addr.port()))
            .build();

        let (websocket, _response) = connect_async_with_proxy_matcher(&url, &matcher)
            .await
            .unwrap();
        drop(websocket);

        server_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    async fn read_request_headers(stream: &mut TcpStream) -> io::Result<String> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1024];

        loop {
            let bytes_read = stream.read(&mut chunk).await?;
            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "proxy client closed before sending headers",
                ));
            }

            bytes.extend_from_slice(&chunk[..bytes_read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return String::from_utf8(bytes).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                });
            }
        }
    }
}
