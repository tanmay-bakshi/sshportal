use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::MAX_NETWORK_UDP_DATAGRAM_BYTES;
use crate::network::NetworkTarget;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SocksRequest {
    Connect(NetworkTarget),
    UdpAssociate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocksUdpDatagram {
    pub(crate) target: NetworkTarget,
    pub(crate) data: Bytes,
}

pub(crate) const SOCKS_VERSION: u8 = 0x05;
pub(crate) const SOCKS_AUTH_NONE: u8 = 0x00;
pub(crate) const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;
pub(crate) const SOCKS_CMD_CONNECT: u8 = 0x01;
pub(crate) const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
pub(crate) const SOCKS_REPLY_SUCCESS: u8 = 0x00;
pub(crate) const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
pub(crate) const SOCKS_REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub(crate) const SOCKS_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
pub(crate) const SOCKS_REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub(crate) const SOCKS_REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub(crate) const SOCKS_REPLY_TTL_EXPIRED: u8 = 0x06;
pub(crate) const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub(crate) const SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
pub(crate) const SOCKS_ATYP_IPV4: u8 = 0x01;
pub(crate) const SOCKS_ATYP_DOMAIN_NAME: u8 = 0x03;
pub(crate) const SOCKS_ATYP_IPV6: u8 = 0x04;

const SOCKS_UDP_HEADER_PREFIX_BYTES: usize = 3;
pub(crate) async fn negotiate_socks5_connect<S>(stream: &mut S) -> Result<NetworkTarget>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match negotiate_socks5(stream, false).await? {
        SocksRequest::Connect(target) => Ok(target),
        SocksRequest::UdpAssociate => unreachable!("UDP is rejected when it is disabled"),
    }
}

pub(crate) async fn negotiate_socks5_network<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_socks5(stream, true).await
}

async fn negotiate_socks5<S>(stream: &mut S, udp_supported: bool) -> Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_authentication(stream).await?;

    let mut request_header = [0_u8; 4];
    stream
        .read_exact(&mut request_header)
        .await
        .context("failed to read SOCKS request header")?;
    if request_header[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS request version {}", request_header[0]);
    }
    if request_header[2] != 0 {
        bail!("invalid SOCKS reserved byte {}", request_header[2]);
    }
    if !matches!(
        request_header[3],
        SOCKS_ATYP_IPV4 | SOCKS_ATYP_DOMAIN_NAME | SOCKS_ATYP_IPV6
    ) {
        write_socks5_response(stream, SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED, None)
            .await
            .context("failed to reject unsupported SOCKS address type")?;
        bail!("unsupported SOCKS address type {}", request_header[3]);
    }

    let (host, port) = read_socks_address(stream, request_header[3]).await?;
    match request_header[1] {
        SOCKS_CMD_CONNECT => Ok(SocksRequest::Connect(NetworkTarget::new(host, port)?)),
        // RFC 1928 permits an unspecified source endpoint, including port zero.
        SOCKS_CMD_UDP_ASSOCIATE if udp_supported => Ok(SocksRequest::UdpAssociate),
        command => {
            write_socks5_response(stream, SOCKS_REPLY_COMMAND_NOT_SUPPORTED, None)
                .await
                .context("failed to reject unsupported SOCKS command")?;
            bail!("unsupported SOCKS command {command}");
        }
    }
}

async fn negotiate_authentication<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .context("failed to read SOCKS greeting header")?;
    if greeting[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version {}", greeting[0]);
    }

    let method_count = usize::from(greeting[1]);
    let mut methods = vec![0_u8; method_count];
    stream
        .read_exact(&mut methods)
        .await
        .context("failed to read SOCKS methods")?;
    if !methods.contains(&SOCKS_AUTH_NONE) {
        stream
            .write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE_METHODS])
            .await
            .context("failed to reject SOCKS authentication methods")?;
        stream
            .flush()
            .await
            .context("failed to flush SOCKS authentication rejection")?;
        bail!("SOCKS client did not offer the required authentication method");
    }

    stream
        .write_all(&[SOCKS_VERSION, SOCKS_AUTH_NONE])
        .await
        .context("failed to accept SOCKS authentication method")?;
    stream
        .flush()
        .await
        .context("failed to flush SOCKS authentication response")
}

async fn read_socks_address<S>(stream: &mut S, address_type: u8) -> Result<(String, u16)>
where
    S: AsyncRead + Unpin,
{
    let host = match address_type {
        SOCKS_ATYP_IPV4 => {
            let mut address_bytes = [0_u8; 4];
            stream
                .read_exact(&mut address_bytes)
                .await
                .context("failed to read SOCKS IPv4 destination")?;
            Ipv4Addr::from(address_bytes).to_string()
        }
        SOCKS_ATYP_DOMAIN_NAME => {
            let mut name_length = [0_u8; 1];
            stream
                .read_exact(&mut name_length)
                .await
                .context("failed to read SOCKS domain length")?;
            if name_length[0] == 0 {
                bail!("SOCKS domain name must not be empty");
            }
            let mut name_bytes = vec![0_u8; usize::from(name_length[0])];
            stream
                .read_exact(&mut name_bytes)
                .await
                .context("failed to read SOCKS domain name")?;
            String::from_utf8(name_bytes).context("SOCKS domain name is not valid UTF-8")?
        }
        SOCKS_ATYP_IPV6 => {
            let mut address_bytes = [0_u8; 16];
            stream
                .read_exact(&mut address_bytes)
                .await
                .context("failed to read SOCKS IPv6 destination")?;
            Ipv6Addr::from(address_bytes).to_string()
        }
        unsupported => bail!("unsupported SOCKS address type {unsupported}"),
    };

    let mut port_bytes = [0_u8; 2];
    stream
        .read_exact(&mut port_bytes)
        .await
        .context("failed to read SOCKS destination port")?;
    Ok((host, u16::from_be_bytes(port_bytes)))
}

pub(crate) async fn write_socks5_response<S>(
    stream: &mut S,
    reply: u8,
    bound_address: Option<SocketAddr>,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = Vec::with_capacity(22);
    response.extend_from_slice(&[SOCKS_VERSION, reply, 0]);
    if let Some(bound_address) = bound_address {
        encode_socks_target(&NetworkTarget::from(bound_address), &mut response)?;
    } else {
        response.extend_from_slice(&[SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
    }
    stream
        .write_all(&response)
        .await
        .context("failed to write SOCKS response")?;
    stream
        .flush()
        .await
        .context("failed to flush SOCKS response")
}

pub(crate) fn encode_socks_udp_datagram(datagram: &SocksUdpDatagram) -> Result<Bytes> {
    let mut encoded = Vec::with_capacity(SOCKS_UDP_HEADER_PREFIX_BYTES + 19 + datagram.data.len());
    encoded.extend_from_slice(&[0, 0, 0]);
    encode_socks_target(&datagram.target, &mut encoded)?;
    encoded.extend_from_slice(&datagram.data);
    if encoded.len() > MAX_NETWORK_UDP_DATAGRAM_BYTES {
        bail!("SOCKS UDP datagram is too large");
    }
    Ok(Bytes::from(encoded))
}

pub(crate) fn decode_socks_udp_datagram(bytes: &[u8]) -> Result<SocksUdpDatagram> {
    if bytes.len() < SOCKS_UDP_HEADER_PREFIX_BYTES {
        bail!("SOCKS UDP datagram is shorter than its header");
    }
    if bytes[0] != 0 || bytes[1] != 0 {
        bail!("SOCKS UDP datagram has a nonzero reserved field");
    }
    if bytes[2] != 0 {
        bail!("fragmented SOCKS UDP datagrams are not supported");
    }
    let (target, target_bytes) = decode_socks_target(&bytes[SOCKS_UDP_HEADER_PREFIX_BYTES..])?;
    let data_offset = SOCKS_UDP_HEADER_PREFIX_BYTES + target_bytes;
    Ok(SocksUdpDatagram {
        target,
        data: Bytes::copy_from_slice(&bytes[data_offset..]),
    })
}

pub(crate) fn encode_socks_target(target: &NetworkTarget, output: &mut Vec<u8>) -> Result<()> {
    if target.host.is_empty() {
        bail!("SOCKS destination host must not be empty");
    }
    if let Ok(address) = target.host.parse::<IpAddr>() {
        match address {
            IpAddr::V4(address) => {
                output.push(SOCKS_ATYP_IPV4);
                output.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                output.push(SOCKS_ATYP_IPV6);
                output.extend_from_slice(&address.octets());
            }
        }
    } else {
        let name_length = u8::try_from(target.host.len())
            .context("SOCKS destination domain is longer than 255 bytes")?;
        output.extend_from_slice(&[SOCKS_ATYP_DOMAIN_NAME, name_length]);
        output.extend_from_slice(target.host.as_bytes());
    }
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

pub(crate) fn decode_socks_target(bytes: &[u8]) -> Result<(NetworkTarget, usize)> {
    let Some(address_type) = bytes.first().copied() else {
        bail!("SOCKS destination is missing its address type");
    };
    let (host, address_bytes) = match address_type {
        SOCKS_ATYP_IPV4 => {
            let address = bytes
                .get(1..5)
                .context("SOCKS IPv4 destination is truncated")?;
            (
                Ipv4Addr::new(address[0], address[1], address[2], address[3]).to_string(),
                5,
            )
        }
        SOCKS_ATYP_DOMAIN_NAME => {
            let name_length = usize::from(
                *bytes
                    .get(1)
                    .context("SOCKS domain destination is missing its length")?,
            );
            let name_end = 2 + name_length;
            let name = bytes
                .get(2..name_end)
                .context("SOCKS domain destination is truncated")?;
            (
                String::from_utf8(name.to_vec())
                    .context("SOCKS domain destination is not valid UTF-8")?,
                name_end,
            )
        }
        SOCKS_ATYP_IPV6 => {
            let address: [u8; 16] = bytes
                .get(1..17)
                .context("SOCKS IPv6 destination is truncated")?
                .try_into()
                .context("failed to decode SOCKS IPv6 destination")?;
            (Ipv6Addr::from(address).to_string(), 17)
        }
        unsupported => bail!("unsupported SOCKS address type {unsupported}"),
    };
    let port_end = address_bytes + 2;
    let port_bytes: [u8; 2] = bytes
        .get(address_bytes..port_end)
        .context("SOCKS destination is missing its port")?
        .try_into()
        .context("failed to decode SOCKS destination port")?;
    Ok((
        NetworkTarget::new(host, u16::from_be_bytes(port_bytes))?,
        port_end,
    ))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use crate::network::NetworkTarget;

    use super::{
        SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, SOCKS_AUTH_NONE, SOCKS_CMD_CONNECT,
        SOCKS_CMD_UDP_ASSOCIATE, SOCKS_NO_ACCEPTABLE_METHODS, SOCKS_VERSION, SocksRequest,
        SocksUdpDatagram, decode_socks_target, decode_socks_udp_datagram, encode_socks_target,
        encode_socks_udp_datagram, negotiate_socks5_connect, negotiate_socks5_network,
    };

    #[test]
    fn targets_round_trip_for_every_address_type() {
        let targets = [
            NetworkTarget::new("192.0.2.7", 53).unwrap(),
            NetworkTarget::new("resolver.client.internal", 5353).unwrap(),
            NetworkTarget::new("2001:db8::7", 443).unwrap(),
        ];

        for expected in targets {
            let mut encoded = Vec::new();
            encode_socks_target(&expected, &mut encoded).unwrap();
            let (actual, consumed) = decode_socks_target(&encoded).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn udp_datagram_round_trips() {
        let expected = SocksUdpDatagram {
            target: NetworkTarget::new("dns.client.internal", 53).unwrap(),
            data: Bytes::from_static(b"query"),
        };

        let encoded = encode_socks_udp_datagram(&expected).unwrap();
        let actual = decode_socks_udp_datagram(&encoded).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn udp_fragments_are_rejected() {
        let encoded = Bytes::from_static(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53]);

        let error = decode_socks_udp_datagram(&encoded).unwrap_err();

        assert!(error.to_string().contains("fragmented"));
    }

    #[test]
    fn oversized_udp_datagrams_are_rejected_after_encapsulation() {
        let datagram = SocksUdpDatagram {
            target: NetworkTarget::new("192.0.2.7", 53).unwrap(),
            data: Bytes::from(vec![0_u8; 65_498]),
        };

        let error = encode_socks_udp_datagram(&datagram).unwrap_err();

        assert!(error.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn connect_selects_no_authentication_from_offered_methods() {
        let (mut client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move { negotiate_socks5_connect(&mut server).await });

        client
            .write_all(&[SOCKS_VERSION, 2, 0x02, SOCKS_AUTH_NONE])
            .await
            .unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, SOCKS_AUTH_NONE]);

        client
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_CMD_CONNECT,
                0,
                SOCKS_ATYP_IPV4,
                192,
                0,
                2,
                4,
                0x01,
                0xbb,
            ])
            .await
            .unwrap();

        let target = server_task.await.unwrap().unwrap();
        assert_eq!(target, NetworkTarget::new("192.0.2.4", 443).unwrap());
    }

    #[tokio::test]
    async fn udp_associate_accepts_unspecified_endpoints_without_allowing_zero_port_connects() {
        for (address_type, address_bytes) in [(SOCKS_ATYP_IPV4, 4), (SOCKS_ATYP_IPV6, 16)] {
            for command in [SOCKS_CMD_UDP_ASSOCIATE, SOCKS_CMD_CONNECT] {
                let (mut client, mut server) = duplex(1024);
                let server_task =
                    tokio::spawn(async move { negotiate_socks5_network(&mut server).await });
                client
                    .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_NONE])
                    .await
                    .unwrap();
                let mut method = [0_u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [SOCKS_VERSION, SOCKS_AUTH_NONE]);
                let mut request = vec![SOCKS_VERSION, command, 0, address_type];
                request.resize(request.len() + address_bytes + 2, 0);
                client.write_all(&request).await.unwrap();
                let result = server_task.await.unwrap();
                if command == SOCKS_CMD_UDP_ASSOCIATE {
                    assert_eq!(result.unwrap(), SocksRequest::UdpAssociate);
                } else {
                    assert!(result.is_err());
                }
            }
        }
    }

    #[tokio::test]
    async fn negotiation_rejects_clients_without_no_authentication_support() {
        for greeting in [vec![SOCKS_VERSION, 0], vec![SOCKS_VERSION, 1, 0x02]] {
            let (mut client, mut server) = duplex(1024);
            let server_task =
                tokio::spawn(async move { negotiate_socks5_connect(&mut server).await });

            client.write_all(&greeting).await.unwrap();
            let mut method = [0_u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [SOCKS_VERSION, SOCKS_NO_ACCEPTABLE_METHODS]);
            assert!(server_task.await.unwrap().is_err());
        }
    }
}
