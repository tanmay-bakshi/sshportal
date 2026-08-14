use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, StatusCode, Uri};

use crate::MAX_NETWORK_UDP_DATAGRAM_BYTES;

const UDP_DATAGRAM_CAPSULE: u64 = 0;
const UDP_ERROR_CAPSULE: u64 = 0x3f00;

const ERROR_CODE_HEADER: &str = "sshportal-error-code";
const ERROR_MESSAGE_HEADER: &str = "sshportal-error-message";
const MAX_ERROR_MESSAGE_BYTES: usize = 512;
const UDP_URI_PREFIX: &str = "/.well-known/masque/udp/";
const NETWORK_AUTHORITY: &str = "network.sshportal.invalid";
const RESOLUTION_FAMILY_HEADER: &str = "sshportal-resolution-family";
const UDP_PEER_HEADER: &str = "sshportal-udp-peer";
pub(crate) const MAX_UDP_CAPSULE_BYTES: usize = 8 + 8 + 1 + MAX_NETWORK_UDP_DATAGRAM_BYTES;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ResolutionFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl ResolutionFamily {
    fn header_value(self) -> HeaderValue {
        match self {
            Self::Any => HeaderValue::from_static("any"),
            Self::Ipv4 => HeaderValue::from_static("ipv4"),
            Self::Ipv6 => HeaderValue::from_static("ipv6"),
        }
    }

    fn from_header_value(value: &HeaderValue) -> Result<Self> {
        match value
            .to_str()
            .context("network resolution-family header is not ASCII text")?
        {
            "any" => Ok(Self::Any),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            value => bail!("unknown network resolution family `{value}`"),
        }
    }

    pub(crate) fn allows(self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct NetworkTarget {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) resolution_family: ResolutionFamily,
}

impl NetworkTarget {
    pub(crate) fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        Self::new_with_resolution_family(host, port, ResolutionFamily::Any)
    }

    pub(crate) fn new_with_resolution_family(
        host: impl Into<String>,
        port: u16,
        resolution_family: ResolutionFamily,
    ) -> Result<Self> {
        let raw_host = host.into();
        let host = if let Ok(address) = raw_host.parse::<IpAddr>() {
            address.to_string()
        } else {
            let trimmed = raw_host.strip_suffix('.').unwrap_or(&raw_host);
            match url::Host::parse(trimmed)
                .with_context(|| format!("invalid network destination host `{raw_host}`"))?
            {
                url::Host::Domain(domain) => domain,
                url::Host::Ipv4(address) => address.to_string(),
                url::Host::Ipv6(address) => address.to_string(),
            }
        };
        let target = Self {
            host,
            port,
            resolution_family,
        };
        target.validate()?;
        Ok(target)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            bail!("network destination host must not be empty");
        }
        if self.host.as_bytes().contains(&0) {
            bail!("network destination host must not contain a NUL byte");
        }
        if let Ok(address) = self.host.parse::<IpAddr>() {
            if self.host != address.to_string() {
                bail!("literal network destination is not canonical");
            }
            if self.resolution_family != ResolutionFamily::Any {
                bail!("a literal network destination cannot constrain name resolution");
            }
        } else {
            let canonical = match url::Host::parse(&self.host)
                .context("network destination host is not a valid URL host")?
            {
                url::Host::Domain(domain) => domain,
                url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
                    bail!("literal network destination is not canonical")
                }
            };
            if canonical != self.host {
                bail!("network destination domain is not canonical");
            }
            validate_dns_domain(&canonical)?;
        }
        if self.port == 0 {
            bail!("network destination port must not be zero");
        }
        Ok(())
    }

    pub(crate) fn write_protocol_headers(&self, headers: &mut HeaderMap) -> Result<()> {
        self.validate()?;
        headers.insert(
            RESOLUTION_FAMILY_HEADER,
            self.resolution_family.header_value(),
        );
        Ok(())
    }

    pub(crate) fn to_connect_uri(&self) -> Result<Uri> {
        self.validate()?;
        self.authority()
            .parse()
            .context("failed to build TCP CONNECT authority")
    }

    pub(crate) fn from_connect_uri(uri: &Uri, headers: &HeaderMap) -> Result<Self> {
        if uri.scheme().is_some() || uri.path_and_query().is_some() {
            bail!("TCP CONNECT target must use authority form");
        }
        let authority = uri
            .authority()
            .context("TCP CONNECT request is missing its authority")?;
        let port = authority
            .port_u16()
            .context("TCP CONNECT authority is missing its port")?;
        let target = Self::new_with_resolution_family(
            authority.host(),
            port,
            decode_resolution_family(headers)?,
        )?;
        if authority.as_str() != target.authority() {
            bail!("TCP CONNECT target is not canonical");
        }
        Ok(target)
    }

    pub(crate) fn to_connect_udp_uri(&self) -> Result<Uri> {
        self.validate()?;
        let encoded_host = percent_encode_path_segment(self.host.as_bytes());
        format!(
            "https://{NETWORK_AUTHORITY}{UDP_URI_PREFIX}{encoded_host}/{}/",
            self.port
        )
        .parse()
        .context("failed to build CONNECT-UDP URI")
    }

    pub(crate) fn from_connect_udp_uri(uri: &Uri, headers: &HeaderMap) -> Result<Self> {
        if uri.scheme_str() != Some("https")
            || uri.authority().map(|value| value.as_str()) != Some(NETWORK_AUTHORITY)
        {
            bail!("CONNECT-UDP request has an invalid scheme or authority");
        }
        let path = uri.path();
        let remainder = path
            .strip_prefix(UDP_URI_PREFIX)
            .context("CONNECT-UDP request has an invalid path")?
            .strip_suffix('/')
            .context("CONNECT-UDP request path must end with a slash")?;
        let (host, port) = remainder
            .rsplit_once('/')
            .context("CONNECT-UDP request path is missing its target port")?;
        if host.contains('/') || port.contains('/') {
            bail!("CONNECT-UDP request has extra path segments");
        }
        let host = String::from_utf8(percent_decode_path_segment(host)?)
            .context("CONNECT-UDP target host is not valid UTF-8")?;
        let port = port
            .parse::<u16>()
            .context("CONNECT-UDP target port is invalid")?;
        let target =
            Self::new_with_resolution_family(host, port, decode_resolution_family(headers)?)?;
        if target.to_connect_udp_uri()?.path_and_query() != uri.path_and_query() {
            bail!("CONNECT-UDP target is not canonical");
        }
        Ok(target)
    }

    fn authority(&self) -> String {
        if self.host.parse::<Ipv6Addr>().is_ok() {
            return format!("[{}]:{}", self.host, self.port);
        }
        format!("{}:{}", self.host, self.port)
    }
}

fn validate_dns_domain(domain: &str) -> Result<()> {
    // A textual name without its terminal root label occupies two more bytes on
    // the DNS wire: one length byte per label replaces each dot, then the root
    // label is appended. RFC 1035 limits that complete representation to 255.
    if domain.len() > 253 {
        bail!("network destination domain is longer than 253 bytes");
    }
    for label in domain.split('.') {
        if label.is_empty() {
            bail!("network destination domain contains an empty label");
        }
        if label.len() > 63 {
            bail!("network destination domain contains a label longer than 63 bytes");
        }
    }
    Ok(())
}

impl From<SocketAddr> for NetworkTarget {
    fn from(address: SocketAddr) -> Self {
        Self {
            host: address.ip().to_string(),
            port: address.port(),
            resolution_family: ResolutionFamily::Any,
        }
    }
}

fn decode_resolution_family(headers: &HeaderMap) -> Result<ResolutionFamily> {
    let mut values = headers.get_all(RESOLUTION_FAMILY_HEADER).iter();
    let value = values
        .next()
        .context("network request is missing its resolution-family header")?;
    if values.next().is_some() {
        bail!("network request carries multiple resolution-family headers");
    }
    ResolutionFamily::from_header_value(value)
}

pub(crate) fn write_udp_peer_header(headers: &mut HeaderMap, peer: SocketAddr) -> Result<()> {
    headers.insert(
        UDP_PEER_HEADER,
        HeaderValue::from_str(&peer.to_string())
            .context("failed to encode the connected UDP peer as an HTTP header")?,
    );
    Ok(())
}

pub(crate) fn decode_udp_peer_header(headers: &HeaderMap) -> Result<SocketAddr> {
    let mut values = headers.get_all(UDP_PEER_HEADER).iter();
    let value = values
        .next()
        .context("CONNECT-UDP response is missing its connected-peer header")?;
    if values.next().is_some() {
        bail!("CONNECT-UDP response carries multiple connected-peer headers");
    }
    let encoded = value
        .to_str()
        .context("CONNECT-UDP connected-peer header is not ASCII text")?;
    let peer = SocketAddr::from_str(encoded)
        .context("CONNECT-UDP connected-peer header is not a socket address")?;
    if peer.port() == 0 {
        bail!("CONNECT-UDP connected-peer header carries port zero");
    }
    if encoded != peer.to_string() {
        bail!("CONNECT-UDP connected-peer header is not canonical");
    }
    Ok(peer)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NetworkErrorKind {
    General = 1,
    PermissionDenied = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TimedOut = 6,
    NameNotFound = 7,
    ResourceLimit = 8,
    Protocol = 9,
    SessionClosed = 10,
}

impl NetworkErrorKind {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::General),
            2 => Ok(Self::PermissionDenied),
            3 => Ok(Self::NetworkUnreachable),
            4 => Ok(Self::HostUnreachable),
            5 => Ok(Self::ConnectionRefused),
            6 => Ok(Self::TimedOut),
            7 => Ok(Self::NameNotFound),
            8 => Ok(Self::ResourceLimit),
            9 => Ok(Self::Protocol),
            10 => Ok(Self::SessionClosed),
            _ => bail!("unknown network error kind {value}"),
        }
    }

    pub(crate) fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::TimedOut => Self::TimedOut,
            io::ErrorKind::NotFound => Self::NameNotFound,
            io::ErrorKind::OutOfMemory => Self::ResourceLimit,
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => Self::Protocol,
            io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof => Self::SessionClosed,
            _ => Self::General,
        }
    }

    pub(crate) fn response_status(self) -> StatusCode {
        match self {
            Self::PermissionDenied => StatusCode::FORBIDDEN,
            Self::ConnectionRefused => StatusCode::BAD_GATEWAY,
            Self::NameNotFound => StatusCode::NOT_FOUND,
            Self::TimedOut => StatusCode::GATEWAY_TIMEOUT,
            Self::ResourceLimit => StatusCode::SERVICE_UNAVAILABLE,
            Self::Protocol => StatusCode::BAD_REQUEST,
            Self::NetworkUnreachable
            | Self::HostUnreachable
            | Self::SessionClosed
            | Self::General => StatusCode::BAD_GATEWAY,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::General => "internal",
            Self::PermissionDenied => "permission_denied",
            Self::NetworkUnreachable => "network_unreachable",
            Self::HostUnreachable => "host_unreachable",
            Self::ConnectionRefused => "connection_refused",
            Self::TimedOut => "timed_out",
            Self::NameNotFound => "dns_not_found",
            Self::ResourceLimit => "resource_exhausted",
            Self::Protocol => "invalid_target",
            Self::SessionClosed => "transport_lost",
        }
    }

    fn from_code(value: &str) -> Option<Self> {
        match value {
            "internal" => Some(Self::General),
            "permission_denied" => Some(Self::PermissionDenied),
            "network_unreachable" => Some(Self::NetworkUnreachable),
            "host_unreachable" => Some(Self::HostUnreachable),
            "connection_refused" => Some(Self::ConnectionRefused),
            "timed_out" => Some(Self::TimedOut),
            "dns_not_found" => Some(Self::NameNotFound),
            "resource_exhausted" => Some(Self::ResourceLimit),
            "invalid_target" => Some(Self::Protocol),
            "transport_lost" => Some(Self::SessionClosed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetworkError {
    pub(crate) kind: NetworkErrorKind,
    pub(crate) message: String,
}

impl NetworkError {
    pub(crate) fn new(kind: NetworkErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: sanitize_error_message(&message.into()),
        }
    }

    pub(crate) fn from_io(error: &io::Error) -> Self {
        Self::new(NetworkErrorKind::from_io(error), error.to_string())
    }

    pub(crate) fn session_closed(message: impl Into<String>) -> Self {
        Self::new(NetworkErrorKind::SessionClosed, message)
    }

    pub(crate) fn resource_limit(message: impl Into<String>) -> Self {
        Self::new(NetworkErrorKind::ResourceLimit, message)
    }

    pub(crate) fn policy_denied(message: impl Into<String>) -> Self {
        Self::new(NetworkErrorKind::PermissionDenied, message)
    }

    pub(crate) fn write_headers(&self, headers: &mut HeaderMap) {
        headers.insert(
            ERROR_CODE_HEADER,
            HeaderValue::from_static(self.kind.code()),
        );
        let message = sanitize_header_message(&self.message);
        let value = HeaderValue::from_str(&message)
            .expect("sanitized network error messages are valid header values");
        headers.insert(ERROR_MESSAGE_HEADER, value);
    }

    pub(crate) fn from_response(status: StatusCode, headers: &HeaderMap) -> Self {
        match decode_network_error_headers(headers) {
            Ok(error) if error.kind.response_status() == status => error,
            Ok(error) => Self::new(
                NetworkErrorKind::Protocol,
                format!(
                    "network rejection status {status} does not match error kind {}",
                    error.kind.code()
                ),
            ),
            Err(error) => Self::new(
                NetworkErrorKind::Protocol,
                format!("invalid network rejection headers: {error}"),
            ),
        }
    }

    pub(crate) fn from_trailers(headers: &HeaderMap) -> Self {
        match decode_network_error_headers(headers) {
            Ok(error) => error,
            Err(error) => Self::new(
                NetworkErrorKind::Protocol,
                format!("invalid network runtime-error trailers: {error}"),
            ),
        }
    }

    pub(crate) fn to_io_error(&self) -> io::Error {
        let kind = match self.kind {
            NetworkErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
            NetworkErrorKind::NetworkUnreachable => io::ErrorKind::NetworkUnreachable,
            NetworkErrorKind::HostUnreachable => io::ErrorKind::HostUnreachable,
            NetworkErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            NetworkErrorKind::TimedOut => io::ErrorKind::TimedOut,
            NetworkErrorKind::NameNotFound => io::ErrorKind::NotFound,
            NetworkErrorKind::ResourceLimit => io::ErrorKind::OutOfMemory,
            NetworkErrorKind::Protocol => io::ErrorKind::InvalidData,
            NetworkErrorKind::SessionClosed | NetworkErrorKind::General => {
                io::ErrorKind::BrokenPipe
            }
        };
        io::Error::new(kind, self.message.clone())
    }
}

fn decode_network_error_headers(headers: &HeaderMap) -> Result<NetworkError> {
    if headers.len() != 2 {
        bail!("expected exactly one error-code and one error-message field");
    }

    let mut code_values = headers.get_all(ERROR_CODE_HEADER).iter();
    let code = code_values
        .next()
        .context("missing network error code")?
        .to_str()
        .context("network error code is not ASCII text")?;
    if code_values.next().is_some() {
        bail!("multiple network error codes");
    }
    let kind = NetworkErrorKind::from_code(code)
        .with_context(|| format!("unknown network error code `{code}`"))?;
    if code != kind.code() {
        bail!("non-canonical network error code `{code}`");
    }

    let mut message_values = headers.get_all(ERROR_MESSAGE_HEADER).iter();
    let message = message_values
        .next()
        .context("missing network error message")?
        .to_str()
        .context("network error message is not ASCII text")?;
    if message_values.next().is_some() {
        bail!("multiple network error messages");
    }
    if message.len() > MAX_ERROR_MESSAGE_BYTES {
        bail!("network error message is too long");
    }
    let error = NetworkError::new(kind, message);
    if error.message != message || sanitize_header_message(message) != message {
        bail!("network error message is not canonical");
    }
    Ok(error)
}

impl fmt::Display for NetworkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NetworkError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UdpCapsule {
    Datagram(Bytes),
    Error(NetworkError),
    Ignored,
}

pub(crate) fn encode_udp_capsule(capsule: &UdpCapsule) -> Result<Bytes> {
    let (capsule_type, body) = match capsule {
        UdpCapsule::Datagram(data) => {
            if data.len() > MAX_NETWORK_UDP_DATAGRAM_BYTES {
                bail!("UDP datagram exceeds {MAX_NETWORK_UDP_DATAGRAM_BYTES} bytes");
            }
            let mut body = Vec::with_capacity(1 + data.len());
            encode_quic_varint(0, &mut body)?;
            body.extend_from_slice(data);
            (UDP_DATAGRAM_CAPSULE, body)
        }
        UdpCapsule::Error(error) => {
            let mut body = Vec::new();
            encode_error(error, &mut body)?;
            (UDP_ERROR_CAPSULE, body)
        }
        UdpCapsule::Ignored => bail!("an ignored UDP capsule cannot be encoded"),
    };
    let mut encoded = Vec::with_capacity(16 + body.len());
    encode_quic_varint(capsule_type, &mut encoded)?;
    encode_quic_varint(body.len() as u64, &mut encoded)?;
    encoded.extend_from_slice(&body);
    Ok(Bytes::from(encoded))
}

pub(crate) struct UdpCapsuleDecoder {
    buffer: BytesMut,
}

impl UdpCapsuleDecoder {
    pub(crate) fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    pub(crate) fn push(&mut self, bytes: Bytes) -> Result<Vec<(UdpCapsule, usize)>> {
        if self.buffer.len().saturating_add(bytes.len()) > MAX_UDP_CAPSULE_BYTES + 16 * 1024 {
            bail!("UDP capsule receive buffer exceeded its limit");
        }
        self.buffer.extend_from_slice(&bytes);
        let mut capsules = Vec::new();
        loop {
            let Some((capsule_type, type_len)) = decode_quic_varint(&self.buffer)? else {
                break;
            };
            let Some((body_len, length_len)) = decode_quic_varint(&self.buffer[type_len..])? else {
                break;
            };
            let body_len = usize::try_from(body_len).context("UDP capsule length is too large")?;
            if body_len > MAX_UDP_CAPSULE_BYTES {
                bail!("invalid UDP capsule length {body_len}");
            }
            let wire_len = type_len + length_len + body_len;
            if self.buffer.len() < wire_len {
                break;
            }
            let mut frame = self.buffer.split_to(wire_len);
            frame.advance(type_len + length_len);
            capsules.push((decode_udp_capsule_body(capsule_type, &frame)?, wire_len));
        }
        Ok(capsules)
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        bail!("UDP association ended with a truncated capsule")
    }
}

fn decode_udp_capsule_body(capsule_type: u64, body: &[u8]) -> Result<UdpCapsule> {
    match capsule_type {
        UDP_DATAGRAM_CAPSULE => {
            let Some((context_id, context_len)) = decode_quic_varint(body)? else {
                bail!("UDP datagram capsule is missing its context ID");
            };
            if context_id != 0 {
                bail!("unsupported UDP datagram context ID {context_id}");
            }
            let payload = &body[context_len..];
            if payload.len() > MAX_NETWORK_UDP_DATAGRAM_BYTES {
                bail!("UDP datagram exceeds {MAX_NETWORK_UDP_DATAGRAM_BYTES} bytes");
            }
            Ok(UdpCapsule::Datagram(Bytes::copy_from_slice(payload)))
        }
        UDP_ERROR_CAPSULE => Ok(UdpCapsule::Error(decode_error(body)?)),
        _ => Ok(UdpCapsule::Ignored),
    }
}

fn encode_quic_varint(value: u64, output: &mut Vec<u8>) -> Result<()> {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => {
            let encoded = (value as u16) | 0x4000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
        16_384..=1_073_741_823 => {
            let encoded = (value as u32) | 0x8000_0000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
        1_073_741_824..=4_611_686_018_427_387_903 => {
            let encoded = value | 0xc000_0000_0000_0000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
        _ => bail!("value exceeds the QUIC variable-length integer range"),
    }
    Ok(())
}

fn decode_quic_varint(bytes: &[u8]) -> Result<Option<(u64, usize)>> {
    let Some(first) = bytes.first().copied() else {
        return Ok(None);
    };
    let length = 1_usize << (first >> 6);
    if bytes.len() < length {
        return Ok(None);
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(Some((value, length)))
}

fn encode_error(error: &NetworkError, output: &mut Vec<u8>) -> Result<()> {
    output.push(error.kind as u8);
    let message = truncate_utf8(&error.message, MAX_ERROR_MESSAGE_BYTES);
    let message_len = u16::try_from(message.len()).context("network error message is too long")?;
    output.put_u16(message_len);
    output.extend_from_slice(message.as_bytes());
    Ok(())
}

fn decode_error(bytes: &[u8]) -> Result<NetworkError> {
    if bytes.len() < 3 {
        bail!("network error is truncated");
    }
    let kind = NetworkErrorKind::decode(bytes[0])?;
    let message_len = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
    if message_len > MAX_ERROR_MESSAGE_BYTES {
        bail!("network error message is too long");
    }
    if bytes.len() != 3 + message_len {
        bail!("network error has an invalid message length");
    }
    let message = String::from_utf8(bytes[3..].to_vec())
        .context("network error message is not valid UTF-8")?;
    let error = NetworkError::new(kind, &message);
    if error.message != message {
        bail!("network error message is not canonical");
    }
    Ok(error)
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

fn sanitize_error_message(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    truncate_utf8(&sanitized, MAX_ERROR_MESSAGE_BYTES)
}

fn sanitize_header_message(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character == '\t' || (' '..='~').contains(&character) {
                character
            } else {
                ' '
            }
        })
        .collect::<String>();
    truncate_utf8(&sanitized, MAX_ERROR_MESSAGE_BYTES)
}

fn hex_digit(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("invalid hex digit"),
    }
}

fn percent_encode_path_segment(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn percent_decode_path_segment(value: &str) -> Result<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let high = *bytes.get(index + 1).context("truncated percent escape")?;
        let low = *bytes.get(index + 2).context("truncated percent escape")?;
        decoded.push((hex_digit(high)? << 4) | hex_digit(low)?);
        index += 3;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, StatusCode};

    use super::{
        MAX_UDP_CAPSULE_BYTES, NetworkError, NetworkErrorKind, NetworkTarget, ResolutionFamily,
        UdpCapsule, UdpCapsuleDecoder, decode_udp_peer_header, encode_quic_varint,
        encode_udp_capsule, write_udp_peer_header,
    };

    #[test]
    fn connect_targets_round_trip_for_every_address_type() {
        for target in [
            NetworkTarget::new("192.0.2.7", 53).unwrap(),
            NetworkTarget::new("resolver.client.internal", 5353).unwrap(),
            NetworkTarget::new("2001:db8::7", 443).unwrap(),
            NetworkTarget::new_with_resolution_family(
                "ipv4.client.internal",
                80,
                ResolutionFamily::Ipv4,
            )
            .unwrap(),
            NetworkTarget::new_with_resolution_family(
                "ipv6.client.internal",
                443,
                ResolutionFamily::Ipv6,
            )
            .unwrap(),
        ] {
            let mut headers = HeaderMap::new();
            target.write_protocol_headers(&mut headers).unwrap();
            let tcp_uri = target.to_connect_uri().unwrap();
            assert_eq!(
                NetworkTarget::from_connect_uri(&tcp_uri, &headers).unwrap(),
                target
            );
            let udp_uri = target.to_connect_udp_uri().unwrap();
            assert_eq!(
                NetworkTarget::from_connect_udp_uri(&udp_uri, &headers).unwrap(),
                target
            );
        }
    }

    #[test]
    fn resolution_family_is_mandatory_and_canonical() {
        let target = NetworkTarget::new("service.example", 443).unwrap();
        let uri = target.to_connect_uri().unwrap();

        assert!(NetworkTarget::from_connect_uri(&uri, &HeaderMap::new()).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(
            super::RESOLUTION_FAMILY_HEADER,
            HeaderValue::from_static("IPv4"),
        );
        assert!(NetworkTarget::from_connect_uri(&uri, &headers).is_err());

        headers.append(
            super::RESOLUTION_FAMILY_HEADER,
            HeaderValue::from_static("ipv6"),
        );
        assert!(NetworkTarget::from_connect_uri(&uri, &headers).is_err());
    }

    #[test]
    fn connect_targets_reject_noncanonical_wire_spellings() {
        let target = NetworkTarget::new("service.example", 443).unwrap();
        let mut headers = HeaderMap::new();
        target.write_protocol_headers(&mut headers).unwrap();

        let tcp_uri = "SERVICE.example:443".parse().unwrap();
        assert!(NetworkTarget::from_connect_uri(&tcp_uri, &headers).is_err());

        let udp_uri =
            "https://network.sshportal.invalid/.well-known/masque/udp/service%2Eexample/443/"
                .parse()
                .unwrap();
        assert!(NetworkTarget::from_connect_udp_uri(&udp_uri, &headers).is_err());
    }

    #[test]
    fn literal_destinations_cannot_carry_name_resolution_constraints() {
        for (host, family) in [
            ("192.0.2.1", ResolutionFamily::Ipv4),
            ("2001:db8::1", ResolutionFamily::Ipv6),
        ] {
            assert!(NetworkTarget::new_with_resolution_family(host, 443, family).is_err());
        }
    }

    #[test]
    fn destination_domains_obey_dns_wire_bounds() {
        let longest = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(longest.len(), 253);
        assert!(NetworkTarget::new(longest, 443).is_ok());
        assert!(NetworkTarget::new("_service._tcp.example", 443).is_ok());

        let overlong_name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62),
        ]
        .join(".");
        for invalid in [
            format!("{}.example", "a".repeat(64)),
            overlong_name,
            ".example".to_string(),
            "example..com".to_string(),
            "example.com..".to_string(),
        ] {
            assert!(
                NetworkTarget::new(&invalid, 443).is_err(),
                "destination unexpectedly accepted: {invalid}"
            );
        }
    }

    #[test]
    fn destination_host_normalization_cannot_hide_dns_labels() {
        assert_eq!(
            NetworkTarget::new("EXAMPLE.com.", 443).unwrap().host,
            "example.com"
        );
        assert_eq!(NetworkTarget::new("127.1", 443).unwrap().host, "127.0.0.1");

        for invalid in [
            "example%2e%2ecom",
            "%2eexample.com",
            "example.com%2e",
            "example.com%00.attacker.invalid",
        ] {
            assert!(
                NetworkTarget::new(invalid, 443).is_err(),
                "destination unexpectedly accepted: {invalid}"
            );
        }
    }

    #[test]
    fn connected_udp_peer_header_is_mandatory_unique_and_canonical() {
        let peer: SocketAddr = "[2001:db8::7]:5353".parse().unwrap();
        let mut headers = HeaderMap::new();
        write_udp_peer_header(&mut headers, peer).unwrap();
        assert_eq!(decode_udp_peer_header(&headers).unwrap(), peer);

        let scoped_peer = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 7));
        let mut scoped_headers = HeaderMap::new();
        write_udp_peer_header(&mut scoped_headers, scoped_peer).unwrap();
        assert_eq!(
            decode_udp_peer_header(&scoped_headers).unwrap(),
            scoped_peer
        );

        assert!(decode_udp_peer_header(&HeaderMap::new()).is_err());

        headers.append(
            super::UDP_PEER_HEADER,
            HeaderValue::from_static("192.0.2.7:5353"),
        );
        assert!(decode_udp_peer_header(&headers).is_err());

        for invalid in ["[2001:0db8::7]:5353", "192.000.002.007:5353", "192.0.2.7:0"] {
            let mut headers = HeaderMap::new();
            headers.insert(super::UDP_PEER_HEADER, HeaderValue::from_static(invalid));
            assert!(decode_udp_peer_header(&headers).is_err());
        }
    }

    #[test]
    fn udp_capsules_survive_arbitrary_h2_data_boundaries() {
        let capsules = [
            UdpCapsule::Datagram(Bytes::from_static(b"query")),
            UdpCapsule::Datagram(Bytes::new()),
            UdpCapsule::Error(NetworkError::new(
                NetworkErrorKind::HostUnreachable,
                "unreachable",
            )),
        ];
        let wire = capsules
            .iter()
            .map(encode_udp_capsule)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .concat();
        let mut decoder = UdpCapsuleDecoder::new();
        let mut decoded = Vec::new();
        for chunk in wire.chunks(3) {
            decoded.extend(
                decoder
                    .push(Bytes::copy_from_slice(chunk))
                    .unwrap()
                    .into_iter()
                    .map(|(capsule, _wire_len)| capsule),
            );
        }
        decoder.finish().unwrap();
        assert_eq!(decoded, capsules);
    }

    #[test]
    fn udp_decoder_rejects_truncated_and_oversized_capsules() {
        let capsule =
            encode_udp_capsule(&UdpCapsule::Datagram(Bytes::from_static(b"abc"))).unwrap();
        let mut decoder = UdpCapsuleDecoder::new();
        decoder.push(capsule.slice(..capsule.len() - 1)).unwrap();
        assert!(decoder.finish().is_err());

        let mut oversized = Vec::new();
        encode_quic_varint(0, &mut oversized).unwrap();
        encode_quic_varint((MAX_UDP_CAPSULE_BYTES + 1) as u64, &mut oversized).unwrap();
        let mut decoder = UdpCapsuleDecoder::new();
        assert!(decoder.push(Bytes::from(oversized)).is_err());
    }

    #[test]
    fn structured_errors_round_trip_through_bounded_headers() {
        let error = NetworkError::new(
            NetworkErrorKind::ConnectionRefused,
            "destination refused\r\nthe connection",
        );
        let mut headers = http::HeaderMap::new();

        error.write_headers(&mut headers);
        let decoded = NetworkError::from_response(http::StatusCode::BAD_GATEWAY, &headers);

        assert_eq!(decoded.kind, NetworkErrorKind::ConnectionRefused);
        assert_eq!(decoded.message, "destination refused  the connection");
        assert!(decoded.message.len() <= 512);
    }

    #[test]
    fn network_errors_cannot_carry_terminal_control_text() {
        let error = NetworkError::new(
            NetworkErrorKind::General,
            "remote\u{001b}[2J\u{202e}spoof\nnext",
        );

        assert_eq!(error.message, "remote [2J spoof next");

        let encoded_noncanonical = [NetworkErrorKind::General as u8, 0, 3, b'a', b'\n', b'b'];
        assert!(super::decode_error(&encoded_noncanonical).is_err());
    }

    #[test]
    fn rejection_errors_require_canonical_headers_and_matching_status() {
        let error = NetworkError::new(NetworkErrorKind::PermissionDenied, "policy denied");
        let mut headers = HeaderMap::new();
        error.write_headers(&mut headers);

        assert_eq!(
            NetworkError::from_response(StatusCode::BAD_GATEWAY, &headers).kind,
            NetworkErrorKind::Protocol
        );

        headers.insert(
            super::ERROR_CODE_HEADER,
            HeaderValue::from_static("policy_denied"),
        );
        assert_eq!(
            NetworkError::from_response(StatusCode::FORBIDDEN, &headers).kind,
            NetworkErrorKind::Protocol
        );
    }

    #[test]
    fn runtime_error_trailers_are_complete_unique_and_canonical() {
        let error = NetworkError::new(NetworkErrorKind::ConnectionRefused, "destination refused");
        let mut headers = HeaderMap::new();
        error.write_headers(&mut headers);
        assert_eq!(NetworkError::from_trailers(&headers), error);

        let mut missing_message = headers.clone();
        missing_message.remove(super::ERROR_MESSAGE_HEADER);
        assert_eq!(
            NetworkError::from_trailers(&missing_message).kind,
            NetworkErrorKind::Protocol
        );

        let mut duplicate_code = headers.clone();
        duplicate_code.append(
            super::ERROR_CODE_HEADER,
            HeaderValue::from_static("connection_refused"),
        );
        assert_eq!(
            NetworkError::from_trailers(&duplicate_code).kind,
            NetworkErrorKind::Protocol
        );

        let mut noncanonical_code = headers;
        noncanonical_code.insert(
            super::ERROR_CODE_HEADER,
            HeaderValue::from_static("policy_denied"),
        );
        assert_eq!(
            NetworkError::from_trailers(&noncanonical_code).kind,
            NetworkErrorKind::Protocol
        );

        for message in ["line\tbreak", "unicode caf\u{e9}"] {
            let mut noncanonical_message = HeaderMap::new();
            noncanonical_message.insert(
                super::ERROR_CODE_HEADER,
                HeaderValue::from_static("connection_refused"),
            );
            noncanonical_message.insert(
                super::ERROR_MESSAGE_HEADER,
                HeaderValue::from_bytes(message.as_bytes()).unwrap(),
            );
            assert_eq!(
                NetworkError::from_trailers(&noncanonical_message).kind,
                NetworkErrorKind::Protocol
            );
        }
    }
}
