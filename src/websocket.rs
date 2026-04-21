use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::ready;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use futures_util::{Sink, StreamExt, stream::SplitStream};
use hyper::Uri;
use hyper::header::HeaderValue;
use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use pin_project_lite::pin_project;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{Error as WebSocketError, Message, handshake::client::Response},
};
use tokio_util::io::StreamReader;
use url::Url;

use crate::DEFAULT_CONNECT_PATH;

pub trait AsyncStream: AsyncRead + AsyncWrite + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send {}

pub trait WebSocketClientTransport: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> WebSocketClientTransport for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type ClientWebSocketStream = WebSocketStream<MaybeTlsStream<Box<dyn WebSocketClientTransport>>>;

const MAX_PROXY_RESPONSE_HEADER_BYTES: usize = 8192;

pin_project! {
    struct DuplexIo<R, W> {
        #[pin]
        reader: R,
        #[pin]
        writer: W,
    }
}

pin_project! {
    struct WebSocketWriter<W> {
        #[pin]
        sink: W,
        pending_len: Option<usize>,
    }
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

impl<W> AsyncWrite for WebSocketWriter<W>
where
    W: Sink<Message, Error = WebSocketError>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        if let Some(pending_len) = this.pending_len.as_ref() {
            ready!(
                this.sink
                    .as_mut()
                    .poll_flush(cx)
                    .map_err(map_websocket_error)
            )?;
            let written_len = *pending_len;
            *this.pending_len = None;
            return Poll::Ready(Ok(written_len));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        ready!(
            this.sink
                .as_mut()
                .poll_ready(cx)
                .map_err(map_websocket_error)
        )?;
        this.sink
            .as_mut()
            .start_send(Message::Binary(Bytes::copy_from_slice(buf)))
            .map_err(map_websocket_error)?;
        *this.pending_len = Some(buf.len());
        ready!(
            this.sink
                .as_mut()
                .poll_flush(cx)
                .map_err(map_websocket_error)
        )?;
        *this.pending_len = None;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        ready!(
            this.sink
                .as_mut()
                .poll_flush(cx)
                .map_err(map_websocket_error)
        )?;
        *this.pending_len = None;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if this.pending_len.is_some() {
            ready!(
                this.sink
                    .as_mut()
                    .poll_flush(cx)
                    .map_err(map_websocket_error)
            )?;
            *this.pending_len = None;
        }
        this.sink
            .as_mut()
            .poll_close(cx)
            .map_err(map_websocket_error)
    }
}

pub async fn connect_async_with_env_proxy(url: &Url) -> Result<(ClientWebSocketStream, Response)> {
    crate::install_default_rustls_crypto_provider();
    let matcher = Matcher::from_env();
    connect_async_with_proxy_matcher(url, &matcher).await
}

pub fn websocket_to_io<S>(websocket: WebSocketStream<S>) -> Pin<Box<dyn AsyncStream + 'static>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = websocket.split();
    Box::pin(DuplexIo {
        reader: StreamReader::new(websocket_reader(stream)),
        writer: WebSocketWriter {
            sink,
            pending_len: None,
        },
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
                "received a websocket text frame during SSH transport",
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

async fn connect_async_with_proxy_matcher(
    url: &Url,
    matcher: &Matcher,
) -> Result<(ClientWebSocketStream, Response)> {
    let maybe_proxy = selected_proxy_for_websocket_url(matcher, url)?;
    let stream = match maybe_proxy {
        Some(proxy) => connect_via_proxy(url, &proxy).await?,
        None => connect_direct(url).await?,
    };

    client_async_tls_with_config(url.as_str(), stream, None, None)
        .await
        .context("failed to complete websocket handshake")
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

async fn connect_direct(url: &Url) -> Result<Box<dyn WebSocketClientTransport>> {
    let (host, port) = destination_host_and_port(url)?;
    let socket = open_tcp_stream(&host, port, "sshportal server").await?;
    Ok(Box::new(socket))
}

async fn connect_via_proxy(
    url: &Url,
    proxy: &Intercept,
) -> Result<Box<dyn WebSocketClientTransport>> {
    let (proxy_host, proxy_port, proxy_scheme) = proxy_endpoint(proxy)?;
    let proxy_socket = open_tcp_stream(&proxy_host, proxy_port, "HTTP proxy").await?;
    let mut proxy_stream: Box<dyn WebSocketClientTransport> = match proxy_scheme.as_str() {
        "http" => Box::new(proxy_socket),
        "https" => Box::new(connect_to_https_proxy(proxy_socket, &proxy_host).await?),
        unsupported => {
            bail!(
                "unsupported proxy scheme `{unsupported}`; only http:// and https:// proxies are supported"
            );
        }
    };

    let (destination_host, destination_port) = destination_host_and_port(url)?;
    establish_connect_tunnel(
        proxy_stream.as_mut(),
        &destination_host,
        destination_port,
        proxy.basic_auth(),
    )
    .await?;

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

async fn open_tcp_stream(host: &str, port: u16, description: &str) -> Result<TcpStream> {
    let authority = format_authority(host, port);
    let socket = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("failed to connect to {description} at {authority}"))?;
    socket.set_nodelay(true).with_context(|| {
        format!("failed to enable TCP_NODELAY for {description} at {authority}")
    })?;
    Ok(socket)
}

async fn connect_to_https_proxy(
    socket: TcpStream,
    proxy_host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = ServerName::try_from(proxy_host.to_string())
        .map_err(|_| anyhow!("proxy host `{proxy_host}` is not a valid TLS server name"))?;
    let connector = TlsConnector::from(proxy_tls_config());
    connector
        .connect(server_name, socket)
        .await
        .with_context(|| format!("failed to negotiate TLS with HTTPS proxy `{proxy_host}`"))
}

fn proxy_tls_config() -> Arc<rustls::ClientConfig> {
    static PROXY_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

    Arc::clone(PROXY_TLS_CONFIG.get_or_init(|| {
        crate::install_default_rustls_crypto_provider();
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    }))
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
        if has_header_terminator(&response) {
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
    let response_text = std::str::from_utf8(&response[..header_end])
        .context("proxy CONNECT response headers were not valid UTF-8")?;
    let status_line = response_text
        .lines()
        .next()
        .ok_or_else(|| anyhow!("proxy CONNECT response was empty"))?;
    if status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200") {
        return Ok(());
    }
    if status_line.starts_with("HTTP/1.1 407") || status_line.starts_with("HTTP/1.0 407") {
        bail!("proxy authentication was rejected");
    }
    bail!("proxy CONNECT failed: {status_line}");
}

fn header_terminator_offset(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn has_header_terminator(bytes: &[u8]) -> bool {
    header_terminator_offset(bytes).is_some()
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
    use hyper_util::client::proxy::matcher::Matcher;
    use std::io;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::accept_async;

    use super::{
        connect_async_with_proxy_matcher, normalize_websocket_url, selected_proxy_for_websocket_url,
    };

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
