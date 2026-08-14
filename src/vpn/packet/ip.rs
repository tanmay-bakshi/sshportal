use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;

use bytes::{Bytes, BytesMut};

pub(super) const IP_PROTOCOL_TCP: u8 = 6;
pub(super) const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_FRAGMENT: u8 = 44;
const IP_PROTOCOL_HOP_BY_HOP: u8 = 0;
const IP_PROTOCOL_ROUTING: u8 = 43;
const IP_PROTOCOL_AUTHENTICATION: u8 = 51;
const IP_PROTOCOL_DESTINATION_OPTIONS: u8 = 60;
const IPV4_HEADER_BYTES: usize = 20;
const IPV6_HEADER_BYTES: usize = 40;
const IPV6_FRAGMENT_HEADER_BYTES: usize = 8;
const UDP_HEADER_BYTES: usize = 8;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum FragmentKey {
    Ipv4 {
        source: Ipv4Addr,
        target: Ipv4Addr,
        protocol: u8,
        identification: u16,
    },
    Ipv6 {
        source: Ipv6Addr,
        target: Ipv6Addr,
        identification: u32,
    },
}

#[derive(Clone, Debug)]
pub(super) enum FragmentTemplate {
    Ipv4(Bytes),
    Ipv6 { header: Bytes, protocol: u8 },
}

#[derive(Clone, Debug)]
pub(super) struct IpFragment {
    pub(super) key: FragmentKey,
    pub(super) protocol: u8,
    pub(super) offset: usize,
    pub(super) more: bool,
    pub(super) data: Bytes,
    pub(super) template: Option<FragmentTemplate>,
}

#[derive(Clone, Debug)]
pub(super) struct CompleteIpPacket {
    pub(super) raw: Bytes,
    pub(super) source: IpAddr,
    pub(super) target: IpAddr,
    pub(super) protocol: u8,
    transport: Range<usize>,
}

impl CompleteIpPacket {
    pub(super) fn transport(&self) -> &[u8] {
        &self.raw[self.transport.clone()]
    }
}

#[derive(Clone, Debug)]
pub(super) enum ParsedIpPacket {
    Complete(CompleteIpPacket),
    Fragment(IpFragment),
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct TcpTuple {
    pub(super) operator: SocketAddr,
    pub(super) target: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UdpDatagram {
    pub(super) operator: SocketAddr,
    pub(super) target: SocketAddr,
    pub(super) payload: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParseError {
    Malformed,
    InvalidChecksum,
    UnsupportedExtension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UdpBuildError {
    AddressFamiliesDiffer,
    DatagramTooLarge,
    MtuTooSmall,
}

pub(super) fn parse_ip_packet(packet: Bytes) -> Result<ParsedIpPacket, ParseError> {
    let version = packet.first().ok_or(ParseError::Malformed)? >> 4;
    match version {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => Ok(ParsedIpPacket::Unsupported),
    }
}

fn parse_ipv4(packet: Bytes) -> Result<ParsedIpPacket, ParseError> {
    if packet.len() < IPV4_HEADER_BYTES {
        return Err(ParseError::Malformed);
    }
    let header_bytes = usize::from(packet[0] & 0x0f) * 4;
    if header_bytes < IPV4_HEADER_BYTES || packet.len() < header_bytes {
        return Err(ParseError::Malformed);
    }
    if header_bytes != IPV4_HEADER_BYTES {
        return Err(ParseError::UnsupportedExtension);
    }
    let total_bytes = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_bytes < header_bytes || total_bytes > packet.len() {
        return Err(ParseError::Malformed);
    }
    if internet_checksum(&packet[..header_bytes]) != 0 {
        return Err(ParseError::InvalidChecksum);
    }

    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let target = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let protocol = packet[9];
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment_field & 0x8000 != 0 || fragment_field & 0x4000 != 0 && fragment_field & 0x3fff != 0
    {
        return Err(ParseError::Malformed);
    }
    let fragment_offset = usize::from(fragment_field & 0x1fff) * 8;
    let more_fragments = fragment_field & 0x2000 != 0;
    if fragment_offset != 0 || more_fragments {
        // Reassembly accounts retained memory by fragment and template length.
        // Compact both slices here so neither can retain unaccounted packet bytes.
        let payload = Bytes::copy_from_slice(&packet[header_bytes..total_bytes]);
        if more_fragments && (payload.is_empty() || !payload.len().is_multiple_of(8)) {
            return Err(ParseError::Malformed);
        }
        let end = fragment_offset
            .checked_add(payload.len())
            .ok_or(ParseError::Malformed)?;
        if end > u16::MAX as usize - IPV4_HEADER_BYTES {
            return Err(ParseError::Malformed);
        }
        return Ok(ParsedIpPacket::Fragment(IpFragment {
            key: FragmentKey::Ipv4 {
                source,
                target,
                protocol,
                identification: u16::from_be_bytes([packet[4], packet[5]]),
            },
            protocol,
            offset: fragment_offset,
            more: more_fragments,
            data: payload,
            template: if fragment_offset == 0 {
                Some(FragmentTemplate::Ipv4(Bytes::copy_from_slice(
                    &packet[..header_bytes],
                )))
            } else {
                None
            },
        }));
    }

    let transport = &packet[header_bytes..total_bytes];
    let raw = normalize_ipv4(&packet[..header_bytes], transport)?;
    Ok(ParsedIpPacket::Complete(CompleteIpPacket {
        transport: IPV4_HEADER_BYTES..raw.len(),
        raw,
        source: IpAddr::V4(source),
        target: IpAddr::V4(target),
        protocol,
    }))
}

fn normalize_ipv4(header: &[u8], transport: &[u8]) -> Result<Bytes, ParseError> {
    if header.len() != IPV4_HEADER_BYTES {
        return Err(ParseError::Malformed);
    }
    let total_bytes = IPV4_HEADER_BYTES
        .checked_add(transport.len())
        .ok_or(ParseError::Malformed)?;
    let total_bytes = u16::try_from(total_bytes).map_err(|_| ParseError::Malformed)?;
    let mut output = BytesMut::zeroed(usize::from(total_bytes));
    output[0] = 0x45;
    output[1] = header[1];
    output[2..4].copy_from_slice(&total_bytes.to_be_bytes());
    output[4..6].copy_from_slice(&header[4..6]);
    let flags = u16::from_be_bytes([header[6], header[7]]) & 0x4000;
    output[6..8].copy_from_slice(&flags.to_be_bytes());
    output[8] = header[8];
    output[9] = header[9];
    output[12..20].copy_from_slice(&header[12..20]);
    output[IPV4_HEADER_BYTES..].copy_from_slice(transport);
    let checksum = internet_checksum(&output[..IPV4_HEADER_BYTES]);
    output[10..12].copy_from_slice(&checksum.to_be_bytes());
    Ok(output.freeze())
}

fn parse_ipv6(packet: Bytes) -> Result<ParsedIpPacket, ParseError> {
    if packet.len() < IPV6_HEADER_BYTES {
        return Err(ParseError::Malformed);
    }
    let payload_bytes = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_bytes == 0 {
        return Err(ParseError::UnsupportedExtension);
    }
    let total_bytes = IPV6_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(ParseError::Malformed)?;
    if total_bytes > packet.len() {
        return Err(ParseError::Malformed);
    }
    let source =
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).map_err(|_| ParseError::Malformed)?);
    let target =
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).map_err(|_| ParseError::Malformed)?);

    let protocol = packet[6];
    match protocol {
        IP_PROTOCOL_HOP_BY_HOP
        | IP_PROTOCOL_ROUTING
        | IP_PROTOCOL_AUTHENTICATION
        | IP_PROTOCOL_DESTINATION_OPTIONS => Err(ParseError::UnsupportedExtension),
        IP_PROTOCOL_FRAGMENT => {
            let offset = IPV6_HEADER_BYTES;
            let fragment = packet
                .get(offset..offset + IPV6_FRAGMENT_HEADER_BYTES)
                .ok_or(ParseError::Malformed)?;
            let fragment_field = u16::from_be_bytes([fragment[2], fragment[3]]);
            if fragment_field & 0x0006 != 0 {
                return Err(ParseError::Malformed);
            }
            let fragment_offset = usize::from(fragment_field & 0xfff8);
            let more_fragments = fragment_field & 1 != 0;
            // Fragment state is length-accounted, so own only the exact bytes
            // that reassembly retains.
            let data =
                Bytes::copy_from_slice(&packet[offset + IPV6_FRAGMENT_HEADER_BYTES..total_bytes]);
            if more_fragments && (data.is_empty() || !data.len().is_multiple_of(8)) {
                return Err(ParseError::Malformed);
            }
            let end = fragment_offset
                .checked_add(data.len())
                .ok_or(ParseError::Malformed)?;
            let unfragmentable_payload = offset - IPV6_HEADER_BYTES;
            if unfragmentable_payload
                .checked_add(end)
                .ok_or(ParseError::Malformed)?
                > u16::MAX as usize
            {
                return Err(ParseError::Malformed);
            }
            let fragment_protocol = fragment[0];
            if matches!(
                fragment_protocol,
                IP_PROTOCOL_HOP_BY_HOP
                    | IP_PROTOCOL_ROUTING
                    | IP_PROTOCOL_AUTHENTICATION
                    | IP_PROTOCOL_FRAGMENT
                    | IP_PROTOCOL_DESTINATION_OPTIONS
            ) {
                return Err(ParseError::UnsupportedExtension);
            }
            Ok(ParsedIpPacket::Fragment(IpFragment {
                key: FragmentKey::Ipv6 {
                    source,
                    target,
                    identification: u32::from_be_bytes([
                        fragment[4],
                        fragment[5],
                        fragment[6],
                        fragment[7],
                    ]),
                },
                protocol: fragment_protocol,
                offset: fragment_offset,
                more: more_fragments,
                data,
                template: if fragment_offset == 0 {
                    Some(FragmentTemplate::Ipv6 {
                        header: Bytes::copy_from_slice(&packet[..IPV6_HEADER_BYTES]),
                        protocol: fragment_protocol,
                    })
                } else {
                    None
                },
            }))
        }
        _ => {
            let transport = &packet[IPV6_HEADER_BYTES..total_bytes];
            let raw = normalize_ipv6(&packet[..IPV6_HEADER_BYTES], protocol, transport)?;
            Ok(ParsedIpPacket::Complete(CompleteIpPacket {
                transport: IPV6_HEADER_BYTES..raw.len(),
                raw,
                source: IpAddr::V6(source),
                target: IpAddr::V6(target),
                protocol,
            }))
        }
    }
}

fn normalize_ipv6(header: &[u8], protocol: u8, transport: &[u8]) -> Result<Bytes, ParseError> {
    if header.len() != IPV6_HEADER_BYTES {
        return Err(ParseError::Malformed);
    }
    let payload_bytes = u16::try_from(transport.len()).map_err(|_| ParseError::Malformed)?;
    let mut output = BytesMut::zeroed(IPV6_HEADER_BYTES + transport.len());
    output[..4].copy_from_slice(&header[..4]);
    output[4..6].copy_from_slice(&payload_bytes.to_be_bytes());
    output[6] = protocol;
    output[7..IPV6_HEADER_BYTES].copy_from_slice(&header[7..IPV6_HEADER_BYTES]);
    output[IPV6_HEADER_BYTES..].copy_from_slice(transport);
    Ok(output.freeze())
}

pub(super) fn rebuild_fragmented_packet(
    template: FragmentTemplate,
    payload: &[u8],
) -> Result<Bytes, ParseError> {
    match template {
        FragmentTemplate::Ipv4(header) => normalize_ipv4(&header, payload),
        FragmentTemplate::Ipv6 { header, protocol } => normalize_ipv6(&header, protocol, payload),
    }
}

pub(super) fn initial_tcp_syn(packet: &CompleteIpPacket) -> Option<TcpTuple> {
    if packet.protocol != IP_PROTOCOL_TCP {
        return None;
    }
    let tcp = packet.transport();
    if tcp.len() < 20 {
        return None;
    }
    let header_bytes = usize::from(tcp[12] >> 4) * 4;
    if header_bytes < 20 || header_bytes > tcp.len() {
        return None;
    }
    if transport_checksum(packet.source, packet.target, IP_PROTOCOL_TCP, tcp) != 0 {
        return None;
    }
    let flags = tcp[13];
    if flags & 0x02 == 0 || flags & 0x3d != 0 {
        return None;
    }
    let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let target_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if source_port == 0 || target_port == 0 {
        return None;
    }
    Some(TcpTuple {
        operator: SocketAddr::new(packet.source, source_port),
        target: SocketAddr::new(packet.target, target_port),
    })
}

pub(super) fn parse_udp(packet: &CompleteIpPacket) -> Result<Option<UdpDatagram>, ParseError> {
    if packet.protocol != IP_PROTOCOL_UDP {
        return Ok(None);
    }
    let udp = packet.transport();
    if udp.len() < UDP_HEADER_BYTES {
        return Err(ParseError::Malformed);
    }
    let udp_bytes = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_bytes < UDP_HEADER_BYTES || udp_bytes > udp.len() {
        return Err(ParseError::Malformed);
    }
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let target_port = u16::from_be_bytes([udp[2], udp[3]]);
    if target_port == 0 {
        return Err(ParseError::Malformed);
    }
    let transmitted_checksum = u16::from_be_bytes([udp[6], udp[7]]);
    match (packet.source, packet.target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            if transmitted_checksum != 0
                && udp_checksum(IpAddr::V4(source), IpAddr::V4(target), &udp[..udp_bytes]) != 0
            {
                return Err(ParseError::InvalidChecksum);
            }
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            if transmitted_checksum == 0
                || udp_checksum(IpAddr::V6(source), IpAddr::V6(target), &udp[..udp_bytes]) != 0
            {
                return Err(ParseError::InvalidChecksum);
            }
        }
        _ => return Err(ParseError::Malformed),
    }
    Ok(Some(UdpDatagram {
        operator: SocketAddr::new(packet.source, source_port),
        target: SocketAddr::new(packet.target, target_port),
        payload: packet
            .raw
            .slice(packet.transport.start + UDP_HEADER_BYTES..packet.transport.start + udp_bytes),
    }))
}

pub(super) fn synthesize_udp_response(
    source: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
    mtu: usize,
    ipv4_identification: u16,
    ipv6_identification: u32,
) -> Result<Vec<Bytes>, UdpBuildError> {
    match (source, target) {
        (SocketAddr::V4(source), SocketAddr::V4(target)) => synthesize_udp_ipv4(
            *source.ip(),
            source.port(),
            *target.ip(),
            target.port(),
            payload,
            mtu,
            ipv4_identification,
        ),
        (SocketAddr::V6(source), SocketAddr::V6(target)) => synthesize_udp_ipv6(
            *source.ip(),
            source.port(),
            *target.ip(),
            target.port(),
            payload,
            mtu,
            ipv6_identification,
        ),
        _ => Err(UdpBuildError::AddressFamiliesDiffer),
    }
}

fn synthesize_udp_ipv4(
    source: Ipv4Addr,
    source_port: u16,
    target: Ipv4Addr,
    target_port: u16,
    payload: &[u8],
    mtu: usize,
    identification: u16,
) -> Result<Vec<Bytes>, UdpBuildError> {
    if mtu < IPV4_HEADER_BYTES + UDP_HEADER_BYTES {
        return Err(UdpBuildError::MtuTooSmall);
    }
    let udp_bytes = UDP_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(UdpBuildError::DatagramTooLarge)?;
    let udp_length = u16::try_from(udp_bytes).map_err(|_| UdpBuildError::DatagramTooLarge)?;
    if IPV4_HEADER_BYTES + udp_bytes > u16::MAX as usize {
        return Err(UdpBuildError::DatagramTooLarge);
    }
    let mut udp = BytesMut::zeroed(udp_bytes);
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&target_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
    udp[UDP_HEADER_BYTES..].copy_from_slice(payload);
    let checksum = udp_checksum(IpAddr::V4(source), IpAddr::V4(target), &udp);
    udp[6..8].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
    fragment_ipv4(source, target, identification, IP_PROTOCOL_UDP, &udp, mtu)
}

fn fragment_ipv4(
    source: Ipv4Addr,
    target: Ipv4Addr,
    identification: u16,
    protocol: u8,
    payload: &[u8],
    mtu: usize,
) -> Result<Vec<Bytes>, UdpBuildError> {
    let fragment_payload_bytes = ((mtu - IPV4_HEADER_BYTES) / 8) * 8;
    if fragment_payload_bytes == 0 {
        return Err(UdpBuildError::MtuTooSmall);
    }
    let mut packets = Vec::with_capacity(payload.len().div_ceil(fragment_payload_bytes));
    let mut offset = 0_usize;
    while offset < payload.len() {
        let remaining = payload.len() - offset;
        let data_bytes = remaining.min(fragment_payload_bytes);
        let more = data_bytes < remaining;
        let total_bytes = IPV4_HEADER_BYTES + data_bytes;
        let mut packet = BytesMut::zeroed(total_bytes);
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_bytes as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&identification.to_be_bytes());
        let mut fragment_field =
            u16::try_from(offset / 8).map_err(|_| UdpBuildError::DatagramTooLarge)?;
        if more {
            fragment_field |= 0x2000;
        }
        packet[6..8].copy_from_slice(&fragment_field.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&target.octets());
        packet[IPV4_HEADER_BYTES..].copy_from_slice(&payload[offset..offset + data_bytes]);
        let checksum = internet_checksum(&packet[..IPV4_HEADER_BYTES]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packets.push(packet.freeze());
        offset += data_bytes;
    }
    Ok(packets)
}

fn synthesize_udp_ipv6(
    source: Ipv6Addr,
    source_port: u16,
    target: Ipv6Addr,
    target_port: u16,
    payload: &[u8],
    mtu: usize,
    identification: u32,
) -> Result<Vec<Bytes>, UdpBuildError> {
    if mtu < IPV6_HEADER_BYTES + UDP_HEADER_BYTES {
        return Err(UdpBuildError::MtuTooSmall);
    }
    let udp_bytes = UDP_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(UdpBuildError::DatagramTooLarge)?;
    let udp_length = u16::try_from(udp_bytes).map_err(|_| UdpBuildError::DatagramTooLarge)?;
    let mut udp = BytesMut::zeroed(udp_bytes);
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&target_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
    udp[UDP_HEADER_BYTES..].copy_from_slice(payload);
    let checksum = udp_checksum(IpAddr::V6(source), IpAddr::V6(target), &udp);
    udp[6..8].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());

    if IPV6_HEADER_BYTES + udp.len() <= mtu {
        let mut packet = BytesMut::zeroed(IPV6_HEADER_BYTES + udp.len());
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&udp_length.to_be_bytes());
        packet[6] = IP_PROTOCOL_UDP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&target.octets());
        packet[IPV6_HEADER_BYTES..].copy_from_slice(&udp);
        return Ok(vec![packet.freeze()]);
    }

    if mtu < IPV6_HEADER_BYTES + IPV6_FRAGMENT_HEADER_BYTES + 8 {
        return Err(UdpBuildError::MtuTooSmall);
    }
    let fragment_payload_bytes = ((mtu - IPV6_HEADER_BYTES - IPV6_FRAGMENT_HEADER_BYTES) / 8) * 8;
    let mut packets = Vec::with_capacity(udp.len().div_ceil(fragment_payload_bytes));
    let mut offset = 0_usize;
    while offset < udp.len() {
        let remaining = udp.len() - offset;
        let data_bytes = remaining.min(fragment_payload_bytes);
        let more = data_bytes < remaining;
        let ipv6_payload_bytes = IPV6_FRAGMENT_HEADER_BYTES + data_bytes;
        let mut packet = BytesMut::zeroed(IPV6_HEADER_BYTES + ipv6_payload_bytes);
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(ipv6_payload_bytes as u16).to_be_bytes());
        packet[6] = IP_PROTOCOL_FRAGMENT;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&target.octets());
        packet[40] = IP_PROTOCOL_UDP;
        let mut fragment_field =
            u16::try_from(offset).map_err(|_| UdpBuildError::DatagramTooLarge)?;
        if more {
            fragment_field |= 1;
        }
        packet[42..44].copy_from_slice(&fragment_field.to_be_bytes());
        packet[44..48].copy_from_slice(&identification.to_be_bytes());
        packet[48..].copy_from_slice(&udp[offset..offset + data_bytes]);
        packets.push(packet.freeze());
        offset += data_bytes;
    }
    Ok(packets)
}

fn udp_checksum(source: IpAddr, target: IpAddr, udp: &[u8]) -> u16 {
    transport_checksum(source, target, IP_PROTOCOL_UDP, udp)
}

fn transport_checksum(source: IpAddr, target: IpAddr, protocol: u8, data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            sum = add_checksum_bytes(sum, &source.octets());
            sum = add_checksum_bytes(sum, &target.octets());
            sum += u32::from(protocol);
            sum += data.len() as u32;
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            sum = add_checksum_bytes(sum, &source.octets());
            sum = add_checksum_bytes(sum, &target.octets());
            let length = (data.len() as u32).to_be_bytes();
            sum = add_checksum_bytes(sum, &length);
            sum += u32::from(protocol);
        }
        _ => return u16::MAX,
    }
    finalize_checksum(add_checksum_bytes(sum, data))
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    finalize_checksum(add_checksum_bytes(0, bytes))
}

fn add_checksum_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use bytes::{Bytes, BytesMut};

    use super::{
        FragmentTemplate, ParseError, ParsedIpPacket, parse_ip_packet, parse_udp,
        rebuild_fragmented_packet, synthesize_udp_response,
    };

    fn points_into(candidate: &Bytes, owner: &Bytes) -> bool {
        let candidate = candidate.as_ptr() as usize;
        let owner_start = owner.as_ptr() as usize;
        candidate >= owner_start && candidate < owner_start + owner.len()
    }

    #[test]
    fn udp_ipv4_round_trip_includes_a_valid_checksum() {
        let source: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let target: SocketAddr = "198.51.100.7:49152".parse().unwrap();
        let packets = synthesize_udp_response(source, target, b"answer", 1500, 9, 9).unwrap();
        assert_eq!(packets.len(), 1);

        let ParsedIpPacket::Complete(packet) = parse_ip_packet(packets[0].clone()).unwrap() else {
            panic!("expected a complete packet");
        };
        let datagram = parse_udp(&packet).unwrap().unwrap();
        assert_eq!(datagram.operator, source);
        assert_eq!(datagram.target, target);
        assert_eq!(datagram.payload, Bytes::from_static(b"answer"));
    }

    #[test]
    fn udp_source_port_zero_remains_available_for_one_way_datagrams() {
        let packets = synthesize_udp_response(
            "192.0.2.53:0".parse().unwrap(),
            "198.51.100.7:443".parse().unwrap(),
            b"one-way",
            1500,
            10,
            10,
        )
        .unwrap();
        let ParsedIpPacket::Complete(packet) = parse_ip_packet(packets[0].clone()).unwrap() else {
            panic!("expected a complete packet");
        };

        let datagram = parse_udp(&packet).unwrap().unwrap();
        assert_eq!(datagram.operator.port(), 0);
        assert_eq!(datagram.target.port(), 443);
    }

    #[test]
    fn udp_destination_port_zero_is_rejected() {
        let packets = synthesize_udp_response(
            "192.0.2.53:443".parse().unwrap(),
            "198.51.100.7:0".parse().unwrap(),
            b"invalid",
            1500,
            11,
            11,
        )
        .unwrap();
        let ParsedIpPacket::Complete(packet) = parse_ip_packet(packets[0].clone()).unwrap() else {
            panic!("expected a complete packet");
        };

        assert_eq!(parse_udp(&packet), Err(ParseError::Malformed));
    }

    #[test]
    fn udp_ipv6_fragment_headers_use_byte_offsets() {
        let source = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53);
        let target = SocketAddr::new("2001:db8::7".parse().unwrap(), 49152);
        let packets = synthesize_udp_response(source, target, &[3_u8; 3000], 1280, 4, 77).unwrap();
        assert_eq!(packets.len(), 3);
        assert_eq!(
            u16::from_be_bytes([packets[0][42], packets[0][43]]) & 0xfff8,
            0
        );
        assert_eq!(
            u16::from_be_bytes([packets[1][42], packets[1][43]]) & 0xfff8,
            1232
        );
        assert_eq!(
            u32::from_be_bytes(packets[0][44..48].try_into().unwrap()),
            77
        );
    }

    #[test]
    fn ipv4_options_are_rejected_instead_of_reinterpreted() {
        let mut packet = BytesMut::zeroed(44);
        packet[0] = 0x46;
        packet[2..4].copy_from_slice(&44_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 9).octets());
        packet[24..26].copy_from_slice(&50123_u16.to_be_bytes());
        packet[26..28].copy_from_slice(&443_u16.to_be_bytes());
        packet[36] = 5 << 4;
        packet[37] = 0x02;
        let tcp_checksum = super::transport_checksum(
            "10.0.0.2".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
            super::IP_PROTOCOL_TCP,
            &packet[24..],
        );
        packet[40..42].copy_from_slice(&tcp_checksum.to_be_bytes());
        let checksum = super::internet_checksum(&packet[..24]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        assert!(matches!(
            parse_ip_packet(packet.freeze()),
            Err(ParseError::UnsupportedExtension)
        ));
    }

    #[test]
    fn ipv6_fragment_rebuild_removes_the_fragment_header() {
        let packets = synthesize_udp_response(
            "[2001:db8::53]:53".parse().unwrap(),
            "[2001:db8::7]:49152".parse().unwrap(),
            &[9_u8; 1400],
            1280,
            1,
            12,
        )
        .unwrap();
        let ParsedIpPacket::Fragment(first) = parse_ip_packet(packets[0].clone()).unwrap() else {
            panic!("expected a fragment");
        };
        let ParsedIpPacket::Fragment(second) = parse_ip_packet(packets[1].clone()).unwrap() else {
            panic!("expected a fragment");
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(&first.data);
        payload.extend_from_slice(&second.data);
        let rebuilt = rebuild_fragmented_packet(first.template.unwrap(), &payload).unwrap();
        let ParsedIpPacket::Complete(packet) = parse_ip_packet(rebuilt).unwrap() else {
            panic!("expected a complete packet");
        };
        assert_eq!(parse_udp(&packet).unwrap().unwrap().payload.len(), 1400);
    }

    #[test]
    fn malformed_fragment_templates_are_rejected_without_indexing_them() {
        for template in [
            FragmentTemplate::Ipv4(Bytes::from_static(b"short")),
            FragmentTemplate::Ipv6 {
                header: Bytes::from_static(b"short"),
                protocol: super::IP_PROTOCOL_UDP,
            },
        ] {
            assert!(matches!(
                rebuild_fragmented_packet(template, b"payload"),
                Err(ParseError::Malformed)
            ));
        }
    }

    #[test]
    fn fragment_parser_owns_only_the_retained_ipv4_bytes() {
        let mut storage = BytesMut::zeroed(4096);
        storage[0] = 0x45;
        storage[2..4].copy_from_slice(&28_u16.to_be_bytes());
        storage[4..6].copy_from_slice(&7_u16.to_be_bytes());
        storage[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        storage[8] = 64;
        storage[9] = super::IP_PROTOCOL_UDP;
        storage[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
        storage[16..20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 2).octets());
        storage[20..28].copy_from_slice(b"fragment");
        let checksum = super::internet_checksum(&storage[..20]);
        storage[10..12].copy_from_slice(&checksum.to_be_bytes());
        let packet = storage.freeze();

        let ParsedIpPacket::Fragment(fragment) = parse_ip_packet(packet.clone()).unwrap() else {
            panic!("expected a fragment");
        };
        let Some(FragmentTemplate::Ipv4(header)) = fragment.template else {
            panic!("expected an IPv4 template");
        };
        assert_eq!(fragment.data.len(), 8);
        assert_eq!(header.len(), 20);
        assert!(!points_into(&fragment.data, &packet));
        assert!(!points_into(&header, &packet));
    }

    #[test]
    fn fragment_parser_owns_only_the_retained_ipv6_bytes() {
        let mut storage = BytesMut::zeroed(4096);
        storage[0] = 0x60;
        storage[4..6].copy_from_slice(&16_u16.to_be_bytes());
        storage[6] = super::IP_PROTOCOL_FRAGMENT;
        storage[7] = 64;
        storage[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        storage[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        storage[40] = super::IP_PROTOCOL_UDP;
        storage[42..44].copy_from_slice(&1_u16.to_be_bytes());
        storage[44..48].copy_from_slice(&9_u32.to_be_bytes());
        storage[48..56].copy_from_slice(b"fragment");
        let packet = storage.freeze();

        let ParsedIpPacket::Fragment(fragment) = parse_ip_packet(packet.clone()).unwrap() else {
            panic!("expected a fragment");
        };
        let Some(FragmentTemplate::Ipv6 { header, .. }) = fragment.template else {
            panic!("expected an IPv6 template");
        };
        assert_eq!(fragment.data.len(), 8);
        assert_eq!(header.len(), 40);
        assert!(!points_into(&fragment.data, &packet));
        assert!(!points_into(&header, &packet));
    }

    #[test]
    fn ipv6_extension_headers_are_rejected_instead_of_reinterpreted() {
        let mut packet = BytesMut::zeroed(48);
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = super::IP_PROTOCOL_HOP_BY_HOP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = super::IP_PROTOCOL_UDP;

        assert!(matches!(
            parse_ip_packet(packet.freeze()),
            Err(ParseError::UnsupportedExtension)
        ));
    }
}
