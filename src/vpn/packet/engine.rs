use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU64;
use std::time::Duration;

use bytes::Bytes;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{CongestionControl, Socket as TcpSocket, SocketBuffer, State};
use smoltcp::time::Instant;
use smoltcp::wire::HardwareAddress;
use smoltcp::wire::{IpCidr, Ipv4Cidr, Ipv6Cidr};

use super::device::{QueueDevice, QueueError};
use super::fragment::{FragmentDropReason, FragmentLimits, FragmentReassembler, ReassemblyResult};
use super::ip::{
    IP_PROTOCOL_TCP, ParseError, ParsedIpPacket, TcpTuple, UdpBuildError, UdpDatagram,
    initial_tcp_syn, parse_ip_packet, parse_udp, synthesize_udp_response,
};
use super::transport::{
    FlowId, PacketTransport, TcpOpenRequest, TcpResetReason, TransportSendError, UdpOpenRequest,
};
use crate::network::TCP_DESTINATION_OPEN_TIMEOUT;
use crate::{MAX_NETWORK_UDP_DATAGRAM_BYTES, NETWORK_SESSION_FLOW_LIMIT};

const TCP_SYNTHETIC_HANDSHAKE_GRACE: Duration = Duration::from_secs(5);
const MAX_FRAGMENTS_PER_DATAGRAM: usize = 64;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PacketEngineLimits {
    pub(crate) mtu: usize,
    pub(crate) max_flows: usize,
    pub(crate) max_tcp_flows: usize,
    pub(crate) max_udp_flows: usize,
    pub(crate) tcp_receive_bytes_per_flow: usize,
    pub(crate) tcp_send_bytes_per_flow: usize,
    pub(crate) max_ingress_packets: usize,
    pub(crate) max_ingress_bytes: usize,
    pub(crate) max_egress_packets: usize,
    pub(crate) max_egress_bytes: usize,
    pub(crate) max_ingress_packet_bytes: usize,
    pub(crate) max_commands: usize,
    pub(crate) max_command_bytes: usize,
    pub(crate) max_commands_per_flow: usize,
    pub(crate) max_command_bytes_per_flow: usize,
    pub(crate) max_pending_controls: usize,
    pub(crate) max_tcp_data_event_bytes: usize,
    pub(crate) max_udp_datagram_bytes: usize,
    pub(crate) max_pending_udp_datagrams: usize,
    pub(crate) max_pending_udp_bytes: usize,
    pub(crate) tcp_open_timeout: Duration,
    pub(crate) tcp_idle_timeout: Duration,
    pub(crate) udp_idle_timeout: Duration,
    pub(crate) fragments: FragmentLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketEngineAddresses {
    pub(crate) gateway_ipv4: Ipv4Addr,
    pub(crate) gateway_ipv6: Ipv6Addr,
}

impl Default for PacketEngineLimits {
    fn default() -> Self {
        Self {
            mtu: 1500,
            max_flows: NETWORK_SESSION_FLOW_LIMIT,
            max_tcp_flows: 512,
            max_udp_flows: 512,
            tcp_receive_bytes_per_flow: 64 * 1024,
            tcp_send_bytes_per_flow: 64 * 1024,
            max_ingress_packets: 256,
            max_ingress_bytes: 384 * 1024,
            max_egress_packets: 256,
            max_egress_bytes: 384 * 1024,
            max_ingress_packet_bytes: u16::MAX as usize,
            max_commands: 1024,
            max_command_bytes: 8 * 1024 * 1024,
            max_commands_per_flow: 128,
            max_command_bytes_per_flow: 2 * 1024 * 1024,
            max_pending_controls: 2048,
            max_tcp_data_event_bytes: 16 * 1024,
            max_udp_datagram_bytes: MAX_NETWORK_UDP_DATAGRAM_BYTES,
            max_pending_udp_datagrams: 1024,
            max_pending_udp_bytes: 4 * 1024 * 1024,
            tcp_open_timeout: TCP_DESTINATION_OPEN_TIMEOUT
                .saturating_add(TCP_SYNTHETIC_HANDSHAKE_GRACE),
            tcp_idle_timeout: Duration::from_secs(2 * 60 * 60),
            udp_idle_timeout: Duration::from_secs(2 * 60),
            fragments: FragmentLimits {
                max_datagrams: 64,
                max_fragments_per_datagram: MAX_FRAGMENTS_PER_DATAGRAM,
                max_buffered_bytes: 4 * 1024 * 1024,
                max_unfragmentable_header_bytes: 512,
                timeout: Duration::from_secs(60),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PacketEngineStats {
    pub(crate) malformed_packets: u64,
    pub(crate) unsupported_packets: u64,
    pub(crate) ingress_overflow: u64,
    pub(crate) fragment_drops: u64,
    pub(crate) flow_limit_drops: u64,
    pub(crate) command_limit_drops: u64,
    pub(crate) oversized_udp_drops: u64,
    pub(crate) stale_commands: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PacketCommand {
    TcpOpened {
        flow_id: FlowId,
    },
    TcpOpenFailed {
        flow_id: FlowId,
    },
    TcpData {
        flow_id: FlowId,
        data: Bytes,
        receive_bytes: usize,
    },
    TcpHalfClose {
        flow_id: FlowId,
    },
    TcpStopped {
        flow_id: FlowId,
        reset_operator: bool,
    },
    UdpOpened {
        flow_id: FlowId,
    },
    UdpOpenFailed {
        flow_id: FlowId,
    },
    UdpDatagram {
        flow_id: FlowId,
        data: Bytes,
        receive_bytes: usize,
    },
    UdpClose {
        flow_id: FlowId,
    },
}

impl PacketCommand {
    pub(crate) fn flow_id(&self) -> FlowId {
        match self {
            Self::TcpOpened { flow_id }
            | Self::TcpOpenFailed { flow_id }
            | Self::TcpData { flow_id, .. }
            | Self::TcpHalfClose { flow_id }
            | Self::TcpStopped { flow_id, .. }
            | Self::UdpOpened { flow_id }
            | Self::UdpOpenFailed { flow_id }
            | Self::UdpDatagram { flow_id, .. }
            | Self::UdpClose { flow_id } => *flow_id,
        }
    }

    fn buffered_bytes(&self) -> usize {
        match self {
            Self::TcpData { data, .. } | Self::UdpDatagram { data, .. } => data.len(),
            _ => 0,
        }
    }

    fn is_data(&self) -> bool {
        matches!(self, Self::TcpData { .. } | Self::UdpDatagram { .. })
    }

    fn compact_data(self) -> Self {
        match self {
            Self::TcpData {
                flow_id,
                data,
                receive_bytes,
            } => Self::TcpData {
                flow_id,
                data: Bytes::copy_from_slice(&data),
                receive_bytes,
            },
            Self::UdpDatagram {
                flow_id,
                data,
                receive_bytes,
            } => Self::UdpDatagram {
                flow_id,
                data: Bytes::copy_from_slice(&data),
                receive_bytes,
            },
            command => command,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketCommandErrorKind {
    Full,
    DataTooLarge,
    InvalidReceiveCredit,
    UnknownFlow,
}

/// A command whose retained payload has been compacted to its logical length.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PendingPacketCommand(PacketCommand);

impl PendingPacketCommand {
    pub(crate) fn flow_id(&self) -> FlowId {
        self.0.flow_id()
    }

    pub(crate) fn as_command(&self) -> &PacketCommand {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PacketCommandError {
    pub(crate) kind: PacketCommandErrorKind,
    pub(crate) command: PendingPacketCommand,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IngressError {
    Full(Bytes),
    PacketTooLarge(Bytes),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketEngineError<E> {
    TransportClosed(E),
    ControlSchedulerExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ControlMessage {
    OpenTcp(TcpOpenRequest),
    OpenUdp(UdpOpenRequest),
    ResetTcp(FlowId, TcpResetReason),
    CloseTcp(FlowId),
    CloseUdp(FlowId),
}

impl ControlMessage {
    fn flow_id(&self) -> FlowId {
        match self {
            Self::OpenTcp(request) => request.flow_id,
            Self::OpenUdp(request) => request.flow_id,
            Self::ResetTcp(flow_id, _) | Self::CloseTcp(flow_id) | Self::CloseUdp(flow_id) => {
                *flow_id
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpIngressDisposition {
    Deliver,
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ControlSchedulerExhausted;

#[derive(Debug)]
struct TcpFlow {
    id: FlowId,
    tuple: TcpTuple,
    socket: SocketHandle,
    state: TcpFlowState,
    open_deadline: Duration,
    idle_deadline: Duration,
    operator_half_closed: bool,
    session_half_closed: bool,
    half_close_reported: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpFlowState {
    Opening,
    Handshaking,
    Established,
    // Close is ordered behind every accepted output byte. The bounded runtime
    // queue remains the owner until its task acknowledges that complete drain.
    Draining { close_sent: bool },
    Terminating { report: Option<TcpResetReason> },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpTuple {
    operator: SocketAddr,
    target: SocketAddr,
}

#[derive(Debug)]
struct UdpFlow {
    id: FlowId,
    tuple: UdpTuple,
    state: UdpFlowState,
    idle_deadline: Duration,
    pending_datagrams: VecDeque<Bytes>,
    pending_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct CommandUsage {
    count: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpFlowState {
    Opening,
    Established,
}

/// Single-owner packet-termination actor.
///
/// Callers feed raw IP packets and typed transport completions, then call
/// [`PacketEngine::poll`]. No method awaits. Every memory-bearing boundary is
/// limited by bytes and entries, and TCP bytes leave smoltcp only after the
/// transport has synchronously accepted them.
pub(crate) struct PacketEngine {
    limits: PacketEngineLimits,
    device: QueueDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    fragments: FragmentReassembler,
    tcp_by_id: HashMap<FlowId, TcpFlow>,
    tcp_by_tuple: HashMap<TcpTuple, FlowId>,
    udp_by_id: HashMap<FlowId, UdpFlow>,
    udp_by_tuple: HashMap<UdpTuple, FlowId>,
    commands: VecDeque<PacketCommand>,
    data_commands: usize,
    command_bytes: usize,
    command_usage: HashMap<FlowId, CommandUsage>,
    pending_udp_datagrams: usize,
    pending_udp_bytes: usize,
    control_messages: VecDeque<ControlMessage>,
    next_flow_id: Option<NonZeroU64>,
    next_ipv4_identification: u16,
    next_ipv6_identification: u32,
    stats: PacketEngineStats,
}

impl PacketEngine {
    #[cfg(test)]
    pub(crate) fn new(limits: PacketEngineLimits, random_seed: u64) -> Self {
        Self::new_with_addresses(
            limits,
            random_seed,
            PacketEngineAddresses {
                gateway_ipv4: Ipv4Addr::new(10, 254, 0, 1),
                gateway_ipv6: Ipv6Addr::new(0xfd73, 0x6870, 0x6f72, 0x7461, 0x6c00, 0, 0, 1),
            },
        )
    }

    pub(crate) fn new_with_addresses(
        limits: PacketEngineLimits,
        random_seed: u64,
        network_addresses: PacketEngineAddresses,
    ) -> Self {
        assert!(limits.mtu >= 1280, "packet engine MTU must support IPv6");
        assert!(limits.max_tcp_flows > 0, "packet engine needs TCP capacity");
        assert!(limits.max_udp_flows > 0, "packet engine needs UDP capacity");
        assert!(
            limits.max_tcp_data_event_bytes > 0,
            "TCP data event size must not be zero"
        );
        assert!(limits.max_commands > 0, "command capacity must not be zero");
        assert!(
            limits.max_commands_per_flow > 0,
            "per-flow command capacity must not be zero"
        );
        assert!(
            limits.max_command_bytes_per_flow <= limits.max_command_bytes,
            "per-flow command byte capacity cannot exceed the aggregate capacity"
        );
        assert!(
            limits.max_flows <= limits.max_tcp_flows.saturating_add(limits.max_udp_flows),
            "aggregate flow capacity must be reachable by the protocol limits"
        );
        assert!(
            limits.max_pending_controls >= limits.max_flows.saturating_mul(2),
            "control capacity must hold open and terminal state for every flow"
        );
        let mut device = QueueDevice::new(
            limits.mtu,
            limits.max_ingress_packets,
            limits.max_ingress_bytes,
            limits.max_egress_packets,
            limits.max_egress_bytes,
            limits.max_ingress_packet_bytes,
        );
        let mut config = InterfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = random_seed;
        let mut interface = Interface::new(config, &mut device, Instant::ZERO);
        interface.update_ip_addrs(|interface_addresses| {
            interface_addresses
                .push(IpCidr::Ipv4(Ipv4Cidr::new(
                    network_addresses.gateway_ipv4,
                    32,
                )))
                .expect("smoltcp must have IPv4 address capacity");
            interface_addresses
                .push(IpCidr::Ipv6(Ipv6Cidr::new(
                    network_addresses.gateway_ipv6,
                    128,
                )))
                .expect("smoltcp must have IPv6 address capacity");
        });
        interface.set_any_ip(true);

        Self {
            limits,
            device,
            interface,
            sockets: SocketSet::new(Vec::new()),
            fragments: FragmentReassembler::new(limits.fragments),
            tcp_by_id: HashMap::with_capacity(limits.max_tcp_flows),
            tcp_by_tuple: HashMap::with_capacity(limits.max_tcp_flows),
            udp_by_id: HashMap::with_capacity(limits.max_udp_flows),
            udp_by_tuple: HashMap::with_capacity(limits.max_udp_flows),
            commands: VecDeque::with_capacity(limits.max_commands),
            data_commands: 0,
            command_bytes: 0,
            command_usage: HashMap::with_capacity(limits.max_flows),
            pending_udp_datagrams: 0,
            pending_udp_bytes: 0,
            control_messages: VecDeque::with_capacity(limits.max_pending_controls),
            next_flow_id: Some(NonZeroU64::MIN),
            next_ipv4_identification: 1,
            next_ipv6_identification: 1,
            stats: PacketEngineStats::default(),
        }
    }

    pub(crate) fn push_ingress(&mut self, packet: Bytes) -> Result<(), IngressError> {
        self.device.push_ingress(packet).map_err(|(error, packet)| {
            self.stats.ingress_overflow += 1;
            match error {
                QueueError::Full => IngressError::Full(packet),
                QueueError::PacketTooLarge => IngressError::PacketTooLarge(packet),
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn push_command(
        &mut self,
        command: PacketCommand,
    ) -> Result<(), PacketCommandError> {
        self.admit_command(Self::prepare_command(command))
    }

    pub(crate) fn prepare_command(command: PacketCommand) -> PendingPacketCommand {
        PendingPacketCommand(command.compact_data())
    }

    pub(crate) fn admit_command(
        &mut self,
        command: PendingPacketCommand,
    ) -> Result<(), PacketCommandError> {
        self.push_prepared_command(command)
    }

    fn push_prepared_command(
        &mut self,
        command: PendingPacketCommand,
    ) -> Result<(), PacketCommandError> {
        let PendingPacketCommand(command) = command;
        let flow_id = command.flow_id();
        let known_flow = match &command {
            PacketCommand::TcpOpened { .. }
            | PacketCommand::TcpOpenFailed { .. }
            | PacketCommand::TcpData { .. }
            | PacketCommand::TcpHalfClose { .. }
            | PacketCommand::TcpStopped { .. } => self.tcp_by_id.contains_key(&flow_id),
            PacketCommand::UdpOpened { .. }
            | PacketCommand::UdpOpenFailed { .. }
            | PacketCommand::UdpDatagram { .. }
            | PacketCommand::UdpClose { .. } => self.udp_by_id.contains_key(&flow_id),
        };
        if !known_flow {
            self.stats.stale_commands += 1;
            return Err(PacketCommandError {
                kind: PacketCommandErrorKind::UnknownFlow,
                command: PendingPacketCommand(command),
            });
        }
        if matches!(&command, PacketCommand::TcpData { data, .. } if data.len() > self.limits.max_tcp_data_event_bytes)
        {
            return Err(PacketCommandError {
                kind: PacketCommandErrorKind::DataTooLarge,
                command: PendingPacketCommand(command),
            });
        }
        if matches!(
            &command,
            PacketCommand::TcpData {
                data,
                receive_bytes,
                ..
            } if *receive_bytes != 0 && *receive_bytes != data.len()
        ) {
            return Err(PacketCommandError {
                kind: PacketCommandErrorKind::InvalidReceiveCredit,
                command: PendingPacketCommand(command),
            });
        }
        if matches!(&command, PacketCommand::UdpDatagram { data, .. } if data.len() > self.limits.max_udp_datagram_bytes)
        {
            return Err(PacketCommandError {
                kind: PacketCommandErrorKind::DataTooLarge,
                command: PendingPacketCommand(command),
            });
        }
        if matches!(
            &command,
            PacketCommand::UdpDatagram {
                data,
                receive_bytes,
                ..
            } if *receive_bytes != 0 && *receive_bytes < data.len()
        ) {
            return Err(PacketCommandError {
                kind: PacketCommandErrorKind::InvalidReceiveCredit,
                command: PendingPacketCommand(command),
            });
        }
        if !command.is_data() {
            self.commands.push_back(command);
            return Ok(());
        }
        let command_bytes = command.buffered_bytes();
        let usage = self
            .command_usage
            .get(&flow_id)
            .copied()
            .unwrap_or_default();
        if self.data_commands >= self.limits.max_commands
            || self.command_bytes.saturating_add(command_bytes) > self.limits.max_command_bytes
            || usage.count >= self.limits.max_commands_per_flow
            || usage.bytes.saturating_add(command_bytes) > self.limits.max_command_bytes_per_flow
        {
            self.stats.command_limit_drops += 1;
            return Err(PacketCommandError {
                kind: PacketCommandErrorKind::Full,
                command: PendingPacketCommand(command),
            });
        }
        self.data_commands += 1;
        self.command_bytes += command_bytes;
        self.command_usage.insert(
            flow_id,
            CommandUsage {
                count: usage.count + 1,
                bytes: usage.bytes + command_bytes,
            },
        );
        self.commands.push_back(command);
        Ok(())
    }

    pub(crate) fn pop_egress(&mut self) -> Option<Bytes> {
        self.device.pop_egress()
    }

    pub(crate) fn stats(&self) -> PacketEngineStats {
        self.stats
    }

    pub(crate) fn next_deadline(&mut self, now: Duration) -> Option<Duration> {
        let smoltcp_deadline = self
            .interface
            .poll_at(to_smoltcp_time(now), &self.sockets)
            .map(from_smoltcp_time);
        smoltcp_deadline
            .into_iter()
            .chain(self.fragments.next_expiry())
            .chain(self.tcp_by_id.values().filter_map(|flow| match flow.state {
                TcpFlowState::Opening | TcpFlowState::Handshaking => Some(flow.open_deadline),
                TcpFlowState::Established => Some(flow.idle_deadline),
                TcpFlowState::Draining { .. } | TcpFlowState::Terminating { .. } => None,
            }))
            .chain(self.udp_by_id.values().map(|flow| flow.idle_deadline))
            .min()
    }

    pub(crate) fn poll<T: PacketTransport>(
        &mut self,
        now: Duration,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        self.flush_controls(transport)?;
        self.apply_commands(now, transport)?;
        self.process_ingress(now, transport)?;
        self.advance_tcp_handshakes(now);
        self.expire_flows(now)
            .map_err(|_| PacketEngineError::ControlSchedulerExhausted)?;
        self.flush_udp(now, transport)?;
        self.forward_tcp(now, transport)?;
        self.interface
            .poll_egress(to_smoltcp_time(now), &mut self.device, &mut self.sockets);
        self.finish_tcp_lifecycle(transport)?;
        self.flush_controls(transport)
    }

    fn process_ingress<T: PacketTransport>(
        &mut self,
        now: Duration,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        let mut ingress_budget = self.limits.max_ingress_packets;
        while ingress_budget > 0 && self.device.has_ingress() {
            let Some(packet) = self.take_one_ingress() else {
                break;
            };
            self.handle_raw_packet(now, packet, transport)?;
            ingress_budget -= 1;
        }
        Ok(())
    }

    fn take_one_ingress(&mut self) -> Option<Bytes> {
        let mut capture = IngressCapture::default();
        let timestamp = Instant::ZERO;
        let (rx, _tx) = smoltcp::phy::Device::receive(&mut self.device, timestamp)?;
        smoltcp::phy::RxToken::consume(rx, |packet| {
            capture.packet = Some(Bytes::copy_from_slice(packet));
        });
        capture.packet
    }

    fn advance_tcp_handshakes(&mut self, now: Duration) {
        for flow in self.tcp_by_id.values_mut() {
            if flow.state != TcpFlowState::Handshaking {
                continue;
            }
            let socket = self.sockets.get::<TcpSocket>(flow.socket);
            if socket.state() != State::Established {
                continue;
            }
            flow.state = TcpFlowState::Established;
            flow.idle_deadline = now.saturating_add(self.limits.tcp_idle_timeout);
        }
    }

    fn handle_raw_packet<T: PacketTransport>(
        &mut self,
        now: Duration,
        packet: Bytes,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        let parsed = match parse_ip_packet(packet) {
            Ok(parsed) => parsed,
            Err(ParseError::UnsupportedExtension) => {
                self.stats.unsupported_packets += 1;
                return Ok(());
            }
            Err(ParseError::Malformed | ParseError::InvalidChecksum) => {
                self.stats.malformed_packets += 1;
                return Ok(());
            }
        };
        let packet = match parsed {
            ParsedIpPacket::Complete(packet) => packet,
            ParsedIpPacket::Unsupported => {
                self.stats.unsupported_packets += 1;
                return Ok(());
            }
            ParsedIpPacket::Fragment(fragment) => match self.fragments.ingest(now, fragment) {
                ReassemblyResult::Pending => return Ok(()),
                ReassemblyResult::Dropped(
                    FragmentDropReason::Capacity
                    | FragmentDropReason::ConflictingFinalLength
                    | FragmentDropReason::MissingFirstHeader
                    | FragmentDropReason::Overlap
                    | FragmentDropReason::TooManyFragments
                    | FragmentDropReason::TooLarge,
                ) => {
                    self.stats.fragment_drops += 1;
                    return Ok(());
                }
                ReassemblyResult::Complete(packet) => match parse_ip_packet(packet) {
                    Ok(ParsedIpPacket::Complete(packet)) => packet,
                    _ => {
                        self.stats.malformed_packets += 1;
                        return Ok(());
                    }
                },
            },
        };

        if packet.protocol == IP_PROTOCOL_TCP {
            if self.ensure_tcp_listener(now, &packet, transport)? == TcpIngressDisposition::Drop {
                return Ok(());
            }
            if self.device.push_ingress_front(packet.raw).is_err() {
                self.stats.ingress_overflow += 1;
                return Ok(());
            }
            self.interface.poll_ingress_single(
                to_smoltcp_time(now),
                &mut self.device,
                &mut self.sockets,
            );
            return Ok(());
        }

        match parse_udp(&packet) {
            Ok(Some(datagram)) => self.handle_udp(now, datagram, transport),
            Ok(None) => {
                self.stats.unsupported_packets += 1;
                Ok(())
            }
            Err(_) => {
                self.stats.malformed_packets += 1;
                Ok(())
            }
        }
    }

    fn ensure_tcp_listener<T: PacketTransport>(
        &mut self,
        now: Duration,
        packet: &super::ip::CompleteIpPacket,
        transport: &mut T,
    ) -> Result<TcpIngressDisposition, PacketEngineError<T::Error>> {
        let Some(tuple) = initial_tcp_syn(packet) else {
            return Ok(TcpIngressDisposition::Deliver);
        };
        if self.tcp_by_tuple.contains_key(&tuple) {
            return Ok(TcpIngressDisposition::Deliver);
        }
        if self.tcp_by_id.len() >= self.limits.max_tcp_flows
            || self.tcp_by_id.len() + self.udp_by_id.len() >= self.limits.max_flows
            || !self.control_capacity_available_for_new_flow()
        {
            self.stats.flow_limit_drops += 1;
            return Ok(TcpIngressDisposition::Drop);
        }

        let mut socket = TcpSocket::new(
            SocketBuffer::new(vec![0_u8; self.limits.tcp_receive_bytes_per_flow]),
            SocketBuffer::new(vec![0_u8; self.limits.tcp_send_bytes_per_flow]),
        );
        socket.pause_synack(true);
        socket.set_congestion_control(CongestionControl::Reno);
        socket
            .listen(tuple.target)
            .expect("validated destination endpoint must be listenable");
        let handle = self.sockets.add(socket);
        let Some(id) = self.allocate_flow_id() else {
            self.sockets.remove(handle);
            self.stats.flow_limit_drops += 1;
            return Ok(TcpIngressDisposition::Drop);
        };
        let request = TcpOpenRequest {
            flow_id: id,
            operator: tuple.operator,
            target: tuple.target,
        };
        match transport.try_open_tcp(&request) {
            Ok(()) => {}
            Err(TransportSendError::Full) => {
                self.queue_control(ControlMessage::OpenTcp(request))
                    .map_err(|_| PacketEngineError::ControlSchedulerExhausted)?
            }
            Err(TransportSendError::FlowClosed) => {
                self.sockets.remove(handle);
                return Ok(TcpIngressDisposition::Drop);
            }
            Err(TransportSendError::Closed(error)) => {
                self.sockets.remove(handle);
                return Err(PacketEngineError::TransportClosed(error));
            }
        }
        self.tcp_by_tuple.insert(tuple, id);
        self.tcp_by_id.insert(
            id,
            TcpFlow {
                id,
                tuple,
                socket: handle,
                state: TcpFlowState::Opening,
                open_deadline: now.saturating_add(self.limits.tcp_open_timeout),
                idle_deadline: now.saturating_add(self.limits.tcp_idle_timeout),
                operator_half_closed: false,
                session_half_closed: false,
                half_close_reported: false,
            },
        );
        Ok(TcpIngressDisposition::Deliver)
    }

    fn handle_udp<T: PacketTransport>(
        &mut self,
        now: Duration,
        datagram: UdpDatagram,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        if datagram.payload.len() > self.limits.max_udp_datagram_bytes {
            self.stats.oversized_udp_drops += 1;
            return Ok(());
        }
        let tuple = UdpTuple {
            operator: datagram.operator,
            target: datagram.target,
        };
        let flow_id = if let Some(flow_id) = self.udp_by_tuple.get(&tuple).copied() {
            flow_id
        } else {
            if self.udp_by_id.len() >= self.limits.max_udp_flows
                || self.tcp_by_id.len() + self.udp_by_id.len() >= self.limits.max_flows
                || !self.control_capacity_available_for_new_flow()
            {
                self.stats.flow_limit_drops += 1;
                return Ok(());
            }
            let Some(flow_id) = self.allocate_flow_id() else {
                self.stats.flow_limit_drops += 1;
                return Ok(());
            };
            let request = UdpOpenRequest {
                flow_id,
                operator: tuple.operator,
                target: tuple.target,
            };
            match transport.try_open_udp(&request) {
                Ok(()) => {}
                Err(TransportSendError::Full) => self
                    .queue_control(ControlMessage::OpenUdp(request))
                    .map_err(|_| PacketEngineError::ControlSchedulerExhausted)?,
                Err(TransportSendError::FlowClosed) => return Ok(()),
                Err(TransportSendError::Closed(error)) => {
                    return Err(PacketEngineError::TransportClosed(error));
                }
            }
            self.udp_by_tuple.insert(tuple, flow_id);
            self.udp_by_id.insert(
                flow_id,
                UdpFlow {
                    id: flow_id,
                    tuple,
                    state: UdpFlowState::Opening,
                    idle_deadline: now.saturating_add(self.limits.udp_idle_timeout),
                    pending_datagrams: VecDeque::new(),
                    pending_bytes: 0,
                },
            );
            flow_id
        };

        let flow = self
            .udp_by_id
            .get_mut(&flow_id)
            .expect("UDP tuple index must reference a flow");
        flow.idle_deadline = now.saturating_add(self.limits.udp_idle_timeout);
        let must_queue = flow.state == UdpFlowState::Opening || !flow.pending_datagrams.is_empty();
        if must_queue {
            self.queue_udp_datagram(flow_id, datagram.payload);
            return Ok(());
        }
        match transport.try_send_udp(flow_id, &datagram.payload) {
            Ok(()) => Ok(()),
            Err(TransportSendError::Full) => {
                self.queue_udp_datagram(flow_id, datagram.payload);
                Ok(())
            }
            Err(TransportSendError::FlowClosed) => {
                self.remove_udp(flow_id);
                Ok(())
            }
            Err(TransportSendError::Closed(error)) => {
                Err(PacketEngineError::TransportClosed(error))
            }
        }
    }

    fn queue_udp_datagram(&mut self, flow_id: FlowId, datagram: Bytes) {
        if self.pending_udp_datagrams >= self.limits.max_pending_udp_datagrams
            || self.pending_udp_bytes.saturating_add(datagram.len())
                > self.limits.max_pending_udp_bytes
        {
            return;
        }
        let flow = self
            .udp_by_id
            .get_mut(&flow_id)
            .expect("queued UDP datagram must reference a live flow");
        let datagram = Bytes::copy_from_slice(&datagram);
        flow.pending_bytes += datagram.len();
        flow.pending_datagrams.push_back(datagram);
        self.pending_udp_datagrams += 1;
        self.pending_udp_bytes += flow
            .pending_datagrams
            .back()
            .expect("the queued UDP datagram must be present")
            .len();
    }

    fn flush_udp<T: PacketTransport>(
        &mut self,
        now: Duration,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        let flow_ids: Vec<_> = self.udp_by_id.keys().copied().collect();
        for flow_id in flow_ids {
            let Some(flow) = self.udp_by_id.get_mut(&flow_id) else {
                continue;
            };
            if flow.state != UdpFlowState::Established {
                continue;
            }
            let Some(datagram) = flow.pending_datagrams.front() else {
                continue;
            };
            match transport.try_send_udp(flow_id, datagram) {
                Ok(()) => {
                    let sent = flow
                        .pending_datagrams
                        .pop_front()
                        .expect("the accepted UDP datagram must be present");
                    flow.pending_bytes -= sent.len();
                    self.pending_udp_datagrams -= 1;
                    self.pending_udp_bytes -= sent.len();
                    flow.idle_deadline = now.saturating_add(self.limits.udp_idle_timeout);
                }
                Err(TransportSendError::Full) => {}
                Err(TransportSendError::FlowClosed) => self.remove_udp(flow_id),
                Err(TransportSendError::Closed(error)) => {
                    return Err(PacketEngineError::TransportClosed(error));
                }
            }
        }
        Ok(())
    }

    fn apply_commands<T: PacketTransport>(
        &mut self,
        now: Duration,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        let command_budget = self.commands.len();
        let mut blocked_flows = HashSet::new();
        for _ in 0..command_budget {
            let Some(command) = self.pop_command() else {
                break;
            };
            let flow_id = command.flow_id();
            if blocked_flows.contains(&flow_id) {
                self.requeue_back(command);
                continue;
            }
            match command {
                PacketCommand::TcpOpened { flow_id } => {
                    let Some(flow) = self.tcp_by_id.get_mut(&flow_id) else {
                        self.stats.stale_commands += 1;
                        continue;
                    };
                    if flow.state != TcpFlowState::Opening {
                        self.stats.stale_commands += 1;
                        continue;
                    }
                    let socket = self.sockets.get_mut::<TcpSocket>(flow.socket);
                    if socket.state() != State::SynReceived {
                        self.terminate_tcp(flow_id, Some(TcpResetReason::OperatorReset));
                        continue;
                    }
                    socket.pause_synack(false);
                    flow.state = TcpFlowState::Handshaking;
                }
                PacketCommand::TcpOpenFailed { flow_id } => {
                    self.terminate_tcp(flow_id, None);
                }
                PacketCommand::TcpStopped {
                    flow_id,
                    reset_operator,
                } => {
                    let Some(flow) = self.tcp_by_id.get(&flow_id) else {
                        self.stats.stale_commands += 1;
                        continue;
                    };
                    if !reset_operator
                        && matches!(flow.state, TcpFlowState::Draining { close_sent: true })
                    {
                        self.remove_tcp(flow_id);
                    } else {
                        self.terminate_tcp(flow_id, None);
                    }
                }
                PacketCommand::TcpData {
                    flow_id,
                    data,
                    receive_bytes,
                } => {
                    let Some(flow) = self.tcp_by_id.get(&flow_id) else {
                        if receive_bytes > 0 {
                            transport
                                .release_tcp_receive(flow_id, receive_bytes)
                                .map_err(PacketEngineError::TransportClosed)?;
                        }
                        self.stats.stale_commands += 1;
                        continue;
                    };
                    if flow.state == TcpFlowState::Handshaking {
                        self.requeue_back(PacketCommand::TcpData {
                            flow_id,
                            data,
                            receive_bytes,
                        });
                        blocked_flows.insert(flow_id);
                        continue;
                    }
                    if flow.state != TcpFlowState::Established || flow.session_half_closed {
                        if receive_bytes > 0 {
                            transport
                                .release_tcp_receive(flow_id, receive_bytes)
                                .map_err(PacketEngineError::TransportClosed)?;
                        }
                        self.stats.stale_commands += 1;
                        continue;
                    }
                    let socket_handle = flow.socket;
                    let socket = self.sockets.get_mut::<TcpSocket>(socket_handle);
                    let available = socket.send_capacity().saturating_sub(socket.send_queue());
                    let accepted = available.min(data.len());
                    if accepted == 0 && !data.is_empty() {
                        self.requeue_back(PacketCommand::TcpData {
                            flow_id,
                            data,
                            receive_bytes,
                        });
                        blocked_flows.insert(flow_id);
                        continue;
                    }
                    let written = socket
                        .send_slice(&data[..accepted])
                        .expect("an established TCP socket with capacity must accept data");
                    assert_eq!(
                        written, accepted,
                        "smoltcp accepted fewer TCP bytes than its advertised capacity"
                    );
                    if receive_bytes > 0 {
                        transport
                            .release_tcp_receive(flow_id, accepted)
                            .map_err(PacketEngineError::TransportClosed)?;
                    }
                    if accepted > 0 {
                        self.tcp_by_id
                            .get_mut(&flow_id)
                            .expect("TCP flow must remain present while applying data")
                            .idle_deadline = now.saturating_add(self.limits.tcp_idle_timeout);
                    }
                    if accepted < data.len() {
                        self.requeue_back(PacketCommand::TcpData {
                            flow_id,
                            data: Bytes::copy_from_slice(&data[accepted..]),
                            receive_bytes: receive_bytes.saturating_sub(accepted),
                        });
                        blocked_flows.insert(flow_id);
                    }
                }
                PacketCommand::TcpHalfClose { flow_id } => {
                    let Some(flow) = self.tcp_by_id.get_mut(&flow_id) else {
                        self.stats.stale_commands += 1;
                        continue;
                    };
                    if flow.session_half_closed {
                        continue;
                    }
                    if flow.state == TcpFlowState::Handshaking {
                        self.requeue_back(PacketCommand::TcpHalfClose { flow_id });
                        blocked_flows.insert(flow_id);
                        continue;
                    }
                    if flow.state != TcpFlowState::Established {
                        self.stats.stale_commands += 1;
                        continue;
                    }
                    flow.session_half_closed = true;
                    self.sockets.get_mut::<TcpSocket>(flow.socket).close();
                }
                PacketCommand::UdpOpened { flow_id } => {
                    let Some(flow) = self.udp_by_id.get_mut(&flow_id) else {
                        self.stats.stale_commands += 1;
                        continue;
                    };
                    if flow.state != UdpFlowState::Opening {
                        self.stats.stale_commands += 1;
                        continue;
                    }
                    flow.state = UdpFlowState::Established;
                    flow.idle_deadline = now.saturating_add(self.limits.udp_idle_timeout);
                }
                PacketCommand::UdpOpenFailed { flow_id } | PacketCommand::UdpClose { flow_id } => {
                    self.remove_udp(flow_id);
                }
                PacketCommand::UdpDatagram {
                    flow_id,
                    data,
                    receive_bytes,
                } => {
                    let Some(flow) = self.udp_by_id.get(&flow_id) else {
                        if receive_bytes > 0 {
                            transport
                                .release_udp_receive(flow_id, receive_bytes)
                                .map_err(PacketEngineError::TransportClosed)?;
                        }
                        self.stats.stale_commands += 1;
                        continue;
                    };
                    if flow.state != UdpFlowState::Established {
                        if receive_bytes > 0 {
                            transport
                                .release_udp_receive(flow_id, receive_bytes)
                                .map_err(PacketEngineError::TransportClosed)?;
                        }
                        self.stats.stale_commands += 1;
                        continue;
                    }
                    let source = flow.tuple.target;
                    let target = flow.tuple.operator;
                    let packets = synthesize_udp_response(
                        source,
                        target,
                        &data,
                        self.limits.mtu,
                        self.next_ipv4_identification,
                        self.next_ipv6_identification,
                    );
                    self.next_ipv4_identification = self.next_ipv4_identification.wrapping_add(1);
                    self.next_ipv6_identification = self.next_ipv6_identification.wrapping_add(1);
                    match packets {
                        Ok(packets) => {
                            if !self.device.can_push_egress_batch(&packets) {
                                self.requeue_back(PacketCommand::UdpDatagram {
                                    flow_id,
                                    data,
                                    receive_bytes,
                                });
                                blocked_flows.insert(flow_id);
                                continue;
                            }
                            self.device
                                .push_egress_batch(packets)
                                .expect("preflighted UDP packet batch must fit in egress");
                            if receive_bytes > 0 {
                                transport
                                    .release_udp_receive(flow_id, receive_bytes)
                                    .map_err(PacketEngineError::TransportClosed)?;
                            }
                            self.udp_by_id
                                .get_mut(&flow_id)
                                .expect("UDP flow must remain present while applying a datagram")
                                .idle_deadline = now.saturating_add(self.limits.udp_idle_timeout);
                        }
                        Err(
                            UdpBuildError::AddressFamiliesDiffer
                            | UdpBuildError::DatagramTooLarge
                            | UdpBuildError::MtuTooSmall,
                        ) => {
                            if receive_bytes > 0 {
                                transport
                                    .release_udp_receive(flow_id, receive_bytes)
                                    .map_err(PacketEngineError::TransportClosed)?;
                            }
                            self.stats.malformed_packets += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn forward_tcp<T: PacketTransport>(
        &mut self,
        now: Duration,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        let flow_ids: Vec<_> = self.tcp_by_id.keys().copied().collect();
        for flow_id in flow_ids {
            let Some(flow) = self.tcp_by_id.get_mut(&flow_id) else {
                continue;
            };
            let socket = self.sockets.get_mut::<TcpSocket>(flow.socket);
            if flow.state == TcpFlowState::Established && socket.can_recv() {
                let chunk_bytes = socket
                    .recv_queue()
                    .min(self.limits.max_tcp_data_event_bytes);
                let data = socket.peek(chunk_bytes).unwrap_or_default();
                if !data.is_empty() {
                    match transport.try_send_tcp(flow_id, data) {
                        Ok(()) => {
                            let mut consumed = vec![0_u8; data.len()];
                            let read = socket.recv_slice(&mut consumed).unwrap_or(0);
                            debug_assert_eq!(read, consumed.len());
                            flow.idle_deadline = now.saturating_add(self.limits.tcp_idle_timeout);
                        }
                        Err(TransportSendError::Full) => {}
                        Err(TransportSendError::FlowClosed) => {
                            self.terminate_tcp(flow_id, None);
                            continue;
                        }
                        Err(TransportSendError::Closed(error)) => {
                            return Err(PacketEngineError::TransportClosed(error));
                        }
                    }
                }
            }
            if flow.state == TcpFlowState::Established
                && socket.recv_queue() == 0
                && matches!(
                    socket.state(),
                    State::CloseWait | State::LastAck | State::Closing | State::TimeWait
                )
                && !flow.half_close_reported
            {
                match transport.try_half_close_tcp(flow_id) {
                    Ok(()) => {
                        flow.operator_half_closed = true;
                        flow.half_close_reported = true;
                    }
                    Err(TransportSendError::Full) => {}
                    Err(TransportSendError::FlowClosed) => {
                        self.terminate_tcp(flow_id, None);
                    }
                    Err(TransportSendError::Closed(error)) => {
                        return Err(PacketEngineError::TransportClosed(error));
                    }
                }
            }
        }
        Ok(())
    }

    fn finish_tcp_lifecycle<T: PacketTransport>(
        &mut self,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        let mut completed = Vec::new();
        for flow in self.tcp_by_id.values_mut() {
            let socket = self.sockets.get_mut::<TcpSocket>(flow.socket);
            let graceful_end = flow.state == TcpFlowState::Established
                && flow.operator_half_closed
                && flow.session_half_closed
                && socket.state() == State::Closed
                && socket.local_endpoint().is_none()
                && socket.send_queue() == 0
                && socket.recv_queue() == 0;
            if graceful_end {
                completed.push((flow.id, None));
                continue;
            }
            match flow.state {
                TcpFlowState::Opening
                    if socket.state() != State::SynReceived && socket.state() != State::Listen =>
                {
                    completed.push((flow.id, Some(TcpResetReason::OperatorReset)));
                }
                TcpFlowState::Handshaking
                    if socket.state() != State::SynReceived
                        && socket.state() != State::Established =>
                {
                    completed.push((flow.id, Some(TcpResetReason::OperatorReset)));
                }
                TcpFlowState::Established
                    if socket.state() == State::Closed && socket.local_endpoint().is_none() =>
                {
                    completed.push((flow.id, Some(TcpResetReason::OperatorReset)));
                }
                TcpFlowState::Terminating { report } if socket.local_endpoint().is_none() => {
                    completed.push((flow.id, report));
                }
                _ => {}
            }
        }
        for (flow_id, report) in completed {
            match report {
                Some(reason) => match transport.try_reset_tcp(flow_id, reason) {
                    Ok(()) => {}
                    Err(TransportSendError::Full) => self
                        .queue_control(ControlMessage::ResetTcp(flow_id, reason))
                        .map_err(|_| PacketEngineError::ControlSchedulerExhausted)?,
                    Err(TransportSendError::FlowClosed) => {}
                    Err(TransportSendError::Closed(error)) => {
                        return Err(PacketEngineError::TransportClosed(error));
                    }
                },
                None => {
                    let Some(flow) = self.tcp_by_id.get_mut(&flow_id) else {
                        continue;
                    };
                    if flow.state == TcpFlowState::Established {
                        flow.state = TcpFlowState::Draining { close_sent: false };
                    } else {
                        self.remove_tcp(flow_id);
                        continue;
                    }
                    match transport.try_close_tcp(flow_id) {
                        Ok(()) => {
                            self.tcp_by_id
                                .get_mut(&flow_id)
                                .expect("draining TCP flow must remain present")
                                .state = TcpFlowState::Draining { close_sent: true };
                        }
                        Err(TransportSendError::Full) => self
                            .queue_control(ControlMessage::CloseTcp(flow_id))
                            .map_err(|_| PacketEngineError::ControlSchedulerExhausted)?,
                        Err(TransportSendError::FlowClosed) => self.remove_tcp(flow_id),
                        Err(TransportSendError::Closed(error)) => {
                            return Err(PacketEngineError::TransportClosed(error));
                        }
                    }
                    continue;
                }
            }
            self.remove_tcp(flow_id);
        }
        Ok(())
    }

    fn expire_flows(&mut self, now: Duration) -> Result<(), ControlSchedulerExhausted> {
        self.fragments.expire(now);
        let expired_tcp: Vec<_> = self
            .tcp_by_id
            .values()
            .filter_map(|flow| {
                let expired = match flow.state {
                    TcpFlowState::Opening | TcpFlowState::Handshaking => flow.open_deadline <= now,
                    TcpFlowState::Established => flow.idle_deadline <= now,
                    TcpFlowState::Draining { .. } | TcpFlowState::Terminating { .. } => false,
                };
                expired.then_some((flow.id, flow.state))
            })
            .collect();
        for (flow_id, state) in expired_tcp {
            let reason = match state {
                TcpFlowState::Opening | TcpFlowState::Handshaking => TcpResetReason::OpenTimedOut,
                TcpFlowState::Established => TcpResetReason::IdleTimedOut,
                TcpFlowState::Draining { .. } | TcpFlowState::Terminating { .. } => continue,
            };
            self.terminate_tcp(flow_id, Some(reason));
        }
        let expired_udp: Vec<_> = self
            .udp_by_id
            .values()
            .filter_map(|flow| (flow.idle_deadline <= now).then_some(flow.id))
            .collect();
        for flow_id in expired_udp {
            self.queue_control(ControlMessage::CloseUdp(flow_id))?;
            self.remove_udp(flow_id);
        }
        Ok(())
    }

    fn flush_controls<T: PacketTransport>(
        &mut self,
        transport: &mut T,
    ) -> Result<(), PacketEngineError<T::Error>> {
        let budget = self.control_messages.len();
        for _ in 0..budget {
            let Some(message) = self.control_messages.pop_front() else {
                break;
            };
            let result = match &message {
                ControlMessage::OpenTcp(request)
                    if matches!(
                        self.tcp_by_id.get(&request.flow_id),
                        Some(flow) if flow.state == TcpFlowState::Opening
                    ) =>
                {
                    transport.try_open_tcp(request)
                }
                ControlMessage::OpenTcp(_) => continue,
                ControlMessage::OpenUdp(request)
                    if matches!(
                        self.udp_by_id.get(&request.flow_id),
                        Some(flow) if flow.state == UdpFlowState::Opening
                    ) =>
                {
                    transport.try_open_udp(request)
                }
                ControlMessage::OpenUdp(_) => continue,
                ControlMessage::ResetTcp(flow_id, reason) => {
                    transport.try_reset_tcp(*flow_id, *reason)
                }
                ControlMessage::CloseTcp(flow_id)
                    if matches!(
                        self.tcp_by_id.get(flow_id),
                        Some(flow) if flow.state == TcpFlowState::Draining { close_sent: false }
                    ) =>
                {
                    transport.try_close_tcp(*flow_id)
                }
                ControlMessage::CloseTcp(_) => continue,
                ControlMessage::CloseUdp(flow_id) => transport.try_close_udp(*flow_id),
            };
            match result {
                Ok(()) => {
                    if let ControlMessage::CloseTcp(flow_id) = message
                        && let Some(flow) = self.tcp_by_id.get_mut(&flow_id)
                    {
                        flow.state = TcpFlowState::Draining { close_sent: true };
                    }
                }
                Err(TransportSendError::Full) => {
                    self.control_messages.push_back(message);
                }
                Err(TransportSendError::FlowClosed) => match message {
                    ControlMessage::OpenTcp(request) => {
                        self.terminate_tcp(request.flow_id, None);
                    }
                    ControlMessage::OpenUdp(request) => self.remove_udp(request.flow_id),
                    ControlMessage::CloseTcp(flow_id) => self.remove_tcp(flow_id),
                    ControlMessage::ResetTcp(..) | ControlMessage::CloseUdp(..) => {}
                },
                Err(TransportSendError::Closed(error)) => {
                    return Err(PacketEngineError::TransportClosed(error));
                }
            }
        }
        Ok(())
    }

    fn control_capacity_available_for_new_flow(&self) -> bool {
        let unrepresented_live_flows = self
            .tcp_by_id
            .keys()
            .chain(self.udp_by_id.keys())
            .filter(|flow_id| {
                !self
                    .control_messages
                    .iter()
                    .any(|message| message.flow_id() == **flow_id)
            })
            .count();
        self.control_messages
            .len()
            .saturating_add(unrepresented_live_flows)
            < self.limits.max_pending_controls
    }

    fn queue_control(&mut self, message: ControlMessage) -> Result<(), ControlSchedulerExhausted> {
        let flow_id = message.flow_id();
        if let Some(position) = self
            .control_messages
            .iter()
            .position(|pending| pending.flow_id() == flow_id)
        {
            self.control_messages.remove(position);
        }
        if self.control_messages.len() >= self.limits.max_pending_controls {
            return Err(ControlSchedulerExhausted);
        }
        self.control_messages.push_back(message);
        Ok(())
    }

    fn pop_command(&mut self) -> Option<PacketCommand> {
        let command = self.commands.pop_front()?;
        if !command.is_data() {
            return Some(command);
        }
        let flow_id = command.flow_id();
        let command_bytes = command.buffered_bytes();
        self.data_commands -= 1;
        self.command_bytes -= command_bytes;
        let usage = self
            .command_usage
            .get_mut(&flow_id)
            .expect("queued command must have per-flow accounting");
        usage.count -= 1;
        usage.bytes -= command_bytes;
        if usage.count == 0 {
            assert_eq!(usage.bytes, 0, "empty command usage must not retain bytes");
            self.command_usage.remove(&flow_id);
        }
        Some(command)
    }

    fn requeue_back(&mut self, command: PacketCommand) {
        if !command.is_data() {
            self.commands.push_back(command);
            return;
        }
        let flow_id = command.flow_id();
        let command_bytes = command.buffered_bytes();
        self.data_commands += 1;
        let usage = self.command_usage.entry(flow_id).or_default();
        usage.count += 1;
        usage.bytes += command_bytes;
        self.command_bytes += command_bytes;
        self.commands.push_back(command);
    }

    fn allocate_flow_id(&mut self) -> Option<FlowId> {
        let allocated = self.next_flow_id?;
        self.next_flow_id = allocated.get().checked_add(1).and_then(NonZeroU64::new);
        Some(FlowId::new(allocated))
    }

    fn terminate_tcp(&mut self, flow_id: FlowId, report: Option<TcpResetReason>) {
        let Some(flow) = self.tcp_by_id.get_mut(&flow_id) else {
            self.stats.stale_commands += 1;
            return;
        };
        self.sockets.get_mut::<TcpSocket>(flow.socket).abort();
        flow.state = TcpFlowState::Terminating { report };
    }

    fn remove_tcp(&mut self, flow_id: FlowId) {
        let Some(flow) = self.tcp_by_id.remove(&flow_id) else {
            return;
        };
        self.tcp_by_tuple.remove(&flow.tuple);
        self.sockets.remove(flow.socket);
    }

    fn remove_udp(&mut self, flow_id: FlowId) {
        let Some(flow) = self.udp_by_id.remove(&flow_id) else {
            return;
        };
        self.pending_udp_datagrams -= flow.pending_datagrams.len();
        self.pending_udp_bytes -= flow.pending_bytes;
        self.udp_by_tuple.remove(&flow.tuple);
    }
}

#[derive(Default)]
struct IngressCapture {
    packet: Option<Bytes>,
}

fn to_smoltcp_time(duration: Duration) -> Instant {
    Instant::from_micros(duration.as_micros().min(i64::MAX as u128) as i64)
}

fn from_smoltcp_time(instant: Instant) -> Duration {
    Duration::from_micros(instant.total_micros().max(0) as u64)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};
    use std::convert::Infallible;
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use bytes::{Bytes, BytesMut};
    use smoltcp::socket::tcp::{Socket as TcpSocket, State};

    use super::{
        ControlMessage, PacketCommand, PacketCommandErrorKind, PacketEngine, PacketEngineLimits,
        TcpFlowState,
    };
    use crate::MAX_NETWORK_UDP_DATAGRAM_BYTES;
    use crate::vpn::packet::ip::{
        IP_PROTOCOL_TCP, ParsedIpPacket, parse_ip_packet, parse_udp, synthesize_udp_response,
    };
    use crate::vpn::packet::transport::{
        FlowId, PacketTransport, TcpOpenRequest, TcpResetReason, TransportSendError, UdpOpenRequest,
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        OpenTcp(TcpOpenRequest),
        OpenUdp(UdpOpenRequest),
        Tcp(FlowId, Bytes),
        TcpHalfClose(FlowId),
        TcpReset(FlowId, TcpResetReason),
        TcpClose(FlowId),
        Udp(FlowId, Bytes),
        TcpReceiveReleased(FlowId, usize),
        UdpReceiveReleased(FlowId, usize),
        UdpClose(FlowId),
    }

    impl Event {
        fn flow_id(&self) -> FlowId {
            match self {
                Self::OpenTcp(request) => request.flow_id,
                Self::OpenUdp(request) => request.flow_id,
                Self::Tcp(flow_id, _)
                | Self::TcpHalfClose(flow_id)
                | Self::TcpReset(flow_id, _)
                | Self::TcpClose(flow_id)
                | Self::Udp(flow_id, _)
                | Self::TcpReceiveReleased(flow_id, _)
                | Self::UdpReceiveReleased(flow_id, _)
                | Self::UdpClose(flow_id) => *flow_id,
            }
        }
    }

    #[derive(Default)]
    struct TestTransport {
        capacity: usize,
        events: VecDeque<Event>,
        blocked_flows: HashSet<FlowId>,
        closed_flows: HashSet<FlowId>,
    }

    impl TestTransport {
        fn with_capacity(capacity: usize) -> Self {
            Self {
                capacity,
                events: VecDeque::new(),
                blocked_flows: HashSet::new(),
                closed_flows: HashSet::new(),
            }
        }

        fn push(&mut self, event: Event) -> Result<(), TransportSendError<Infallible>> {
            if self.closed_flows.contains(&event.flow_id()) {
                return Err(TransportSendError::FlowClosed);
            }
            if self.blocked_flows.contains(&event.flow_id()) {
                return Err(TransportSendError::Full);
            }
            if self.events.len() >= self.capacity {
                return Err(TransportSendError::Full);
            }
            self.events.push_back(event);
            Ok(())
        }
    }

    impl PacketTransport for TestTransport {
        type Error = Infallible;

        fn try_open_tcp(
            &mut self,
            request: &TcpOpenRequest,
        ) -> Result<(), TransportSendError<Self::Error>> {
            self.push(Event::OpenTcp(*request))
        }

        fn try_open_udp(
            &mut self,
            request: &UdpOpenRequest,
        ) -> Result<(), TransportSendError<Self::Error>> {
            self.push(Event::OpenUdp(*request))
        }

        fn try_send_tcp(
            &mut self,
            flow_id: FlowId,
            data: &[u8],
        ) -> Result<(), TransportSendError<Self::Error>> {
            self.push(Event::Tcp(flow_id, Bytes::copy_from_slice(data)))
        }

        fn try_half_close_tcp(
            &mut self,
            flow_id: FlowId,
        ) -> Result<(), TransportSendError<Self::Error>> {
            self.push(Event::TcpHalfClose(flow_id))
        }

        fn try_reset_tcp(
            &mut self,
            flow_id: FlowId,
            reason: TcpResetReason,
        ) -> Result<(), TransportSendError<Self::Error>> {
            self.push(Event::TcpReset(flow_id, reason))
        }

        fn try_close_tcp(
            &mut self,
            flow_id: FlowId,
        ) -> Result<(), TransportSendError<Self::Error>> {
            self.push(Event::TcpClose(flow_id))
        }

        fn try_send_udp(
            &mut self,
            flow_id: FlowId,
            data: &[u8],
        ) -> Result<(), TransportSendError<Self::Error>> {
            self.push(Event::Udp(flow_id, Bytes::copy_from_slice(data)))
        }

        fn release_tcp_receive(
            &mut self,
            flow_id: FlowId,
            bytes: usize,
        ) -> Result<(), Self::Error> {
            self.events
                .push_back(Event::TcpReceiveReleased(flow_id, bytes));
            Ok(())
        }

        fn release_udp_receive(
            &mut self,
            flow_id: FlowId,
            bytes: usize,
        ) -> Result<(), Self::Error> {
            self.events
                .push_back(Event::UdpReceiveReleased(flow_id, bytes));
            Ok(())
        }

        fn try_close_udp(
            &mut self,
            flow_id: FlowId,
        ) -> Result<(), TransportSendError<Self::Error>> {
            self.push(Event::UdpClose(flow_id))
        }
    }

    #[derive(Debug)]
    struct TestTcpPacket {
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        window: u16,
        payload: Bytes,
    }

    fn tcp_syn(source: SocketAddr, target: SocketAddr, sequence: u32) -> Bytes {
        tcp_segment(source, target, sequence, 0, 0x02, &[])
    }

    fn tcp_segment(
        source: SocketAddr,
        target: SocketAddr,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> Bytes {
        assert_eq!(source.is_ipv4(), target.is_ipv4());
        let ip_header_bytes = if source.is_ipv4() { 20 } else { 40 };
        let tcp_bytes = 20 + payload.len();
        let packet_bytes = ip_header_bytes + tcp_bytes;
        let mut packet = BytesMut::zeroed(packet_bytes);
        match (source.ip(), target.ip()) {
            (IpAddr::V4(source_ip), IpAddr::V4(target_ip)) => {
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&(packet_bytes as u16).to_be_bytes());
                packet[8] = 64;
                packet[9] = IP_PROTOCOL_TCP;
                packet[12..16].copy_from_slice(&source_ip.octets());
                packet[16..20].copy_from_slice(&target_ip.octets());
                let ip_checksum = checksum(&packet[..20]);
                packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
            }
            (IpAddr::V6(source_ip), IpAddr::V6(target_ip)) => {
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&(tcp_bytes as u16).to_be_bytes());
                packet[6] = IP_PROTOCOL_TCP;
                packet[7] = 64;
                packet[8..24].copy_from_slice(&source_ip.octets());
                packet[24..40].copy_from_slice(&target_ip.octets());
            }
            _ => unreachable!("address families were checked above"),
        }
        packet[ip_header_bytes..ip_header_bytes + 2].copy_from_slice(&source.port().to_be_bytes());
        packet[ip_header_bytes + 2..ip_header_bytes + 4]
            .copy_from_slice(&target.port().to_be_bytes());
        packet[ip_header_bytes + 4..ip_header_bytes + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[ip_header_bytes + 8..ip_header_bytes + 12]
            .copy_from_slice(&acknowledgement.to_be_bytes());
        packet[ip_header_bytes + 12] = 5 << 4;
        packet[ip_header_bytes + 13] = flags;
        packet[ip_header_bytes + 14..ip_header_bytes + 16]
            .copy_from_slice(&65_535_u16.to_be_bytes());
        packet[ip_header_bytes + 20..].copy_from_slice(payload);
        let tcp_checksum = tcp_checksum(source.ip(), target.ip(), &packet[ip_header_bytes..]);
        packet[ip_header_bytes + 16..ip_header_bytes + 18]
            .copy_from_slice(&tcp_checksum.to_be_bytes());
        packet.freeze()
    }

    fn parse_test_tcp(packet: Bytes) -> TestTcpPacket {
        let ip_header_bytes = match packet[0] >> 4 {
            4 => usize::from(packet[0] & 0x0f) * 4,
            6 => 40,
            version => panic!("unexpected test IP version {version}"),
        };
        let tcp_header_bytes = usize::from(packet[ip_header_bytes + 12] >> 4) * 4;
        TestTcpPacket {
            sequence: u32::from_be_bytes(
                packet[ip_header_bytes + 4..ip_header_bytes + 8]
                    .try_into()
                    .unwrap(),
            ),
            acknowledgement: u32::from_be_bytes(
                packet[ip_header_bytes + 8..ip_header_bytes + 12]
                    .try_into()
                    .unwrap(),
            ),
            flags: packet[ip_header_bytes + 13],
            window: u16::from_be_bytes(
                packet[ip_header_bytes + 14..ip_header_bytes + 16]
                    .try_into()
                    .unwrap(),
            ),
            payload: packet.slice(ip_header_bytes + tcp_header_bytes..),
        }
    }

    fn drain_egress(engine: &mut PacketEngine) -> Vec<TestTcpPacket> {
        let mut packets = Vec::new();
        while let Some(packet) = engine.pop_egress() {
            packets.push(parse_test_tcp(packet));
        }
        packets
    }

    fn establish_tcp(
        engine: &mut PacketEngine,
        transport: &mut TestTransport,
        operator: SocketAddr,
        target: SocketAddr,
        operator_sequence: u32,
    ) -> (FlowId, u32) {
        engine
            .push_ingress(tcp_syn(operator, target, operator_sequence))
            .unwrap();
        engine.poll(Duration::ZERO, transport).unwrap();
        let Event::OpenTcp(request) = transport.events.pop_front().unwrap() else {
            panic!("expected a TCP open request");
        };
        assert_eq!(request.operator, operator);
        assert_eq!(request.target, target);
        engine
            .push_command(PacketCommand::TcpOpened {
                flow_id: request.flow_id,
            })
            .unwrap();
        engine.poll(Duration::from_millis(1), transport).unwrap();
        let syn_ack = parse_test_tcp(engine.pop_egress().expect("expected SYN-ACK"));
        assert_eq!(syn_ack.flags & 0x12, 0x12);
        assert_eq!(syn_ack.acknowledgement, operator_sequence + 1);
        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                operator_sequence + 1,
                syn_ack.sequence + 1,
                0x10,
                &[],
            ))
            .unwrap();
        engine.poll(Duration::from_millis(2), transport).unwrap();
        drain_egress(engine);
        (request.flow_id, syn_ack.sequence)
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from(chunk[0]) << 8
            };
            sum += u32::from(word);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn tcp_checksum(source: IpAddr, target: IpAddr, tcp: &[u8]) -> u16 {
        let mut pseudo = Vec::new();
        match (source, target) {
            (IpAddr::V4(source), IpAddr::V4(target)) => {
                pseudo.extend_from_slice(&source.octets());
                pseudo.extend_from_slice(&target.octets());
                pseudo.extend_from_slice(&[0, IP_PROTOCOL_TCP]);
                pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
            }
            (IpAddr::V6(source), IpAddr::V6(target)) => {
                pseudo.extend_from_slice(&source.octets());
                pseudo.extend_from_slice(&target.octets());
                pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, IP_PROTOCOL_TCP]);
            }
            _ => unreachable!("address families were checked before checksum construction"),
        }
        pseudo.extend_from_slice(tcp);
        checksum(&pseudo)
    }

    #[test]
    fn tcp_syn_ack_waits_for_remote_open_success() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 7);
        let mut transport = TestTransport::with_capacity(16);
        engine
            .push_ingress(tcp_syn(
                "10.0.0.2:50123".parse().unwrap(),
                "203.0.113.9:443".parse().unwrap(),
                100,
            ))
            .unwrap();
        engine.poll(Duration::ZERO, &mut transport).unwrap();

        let Event::OpenTcp(request) = transport.events.pop_front().unwrap() else {
            panic!("expected an open request");
        };
        assert!(engine.pop_egress().is_none());

        engine
            .push_command(PacketCommand::TcpOpened {
                flow_id: request.flow_id,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(1), &mut transport)
            .unwrap();
        let syn_ack = engine.pop_egress().expect("expected SYN-ACK");
        assert_eq!(syn_ack[33] & 0x12, 0x12);
    }

    #[test]
    fn queued_tcp_syns_are_each_inspected_before_smoltcp_consumes_them() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 20);
        let mut transport = TestTransport::with_capacity(16);
        let first_operator = "10.0.0.2:50134".parse().unwrap();
        let second_operator = "10.0.0.2:50135".parse().unwrap();
        let target = "203.0.113.20:443".parse().unwrap();
        engine
            .push_ingress(tcp_syn(first_operator, target, 1_200))
            .unwrap();
        engine
            .push_ingress(tcp_syn(second_operator, target, 1_300))
            .unwrap();

        engine.poll(Duration::ZERO, &mut transport).unwrap();

        let Event::OpenTcp(first) = transport.events.pop_front().unwrap() else {
            panic!("expected the first TCP open request");
        };
        let Event::OpenTcp(second) = transport.events.pop_front().unwrap() else {
            panic!("expected the second TCP open request");
        };
        assert_eq!(first.operator, first_operator);
        assert_eq!(second.operator, second_operator);
        assert!(transport.events.is_empty());
    }

    #[test]
    fn flow_limit_drops_syn_until_a_slot_can_accept_its_retransmission() {
        let limits = PacketEngineLimits {
            max_flows: 1,
            max_tcp_flows: 1,
            max_udp_flows: 1,
            max_pending_controls: 2,
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 21);
        let mut transport = TestTransport::with_capacity(16);
        let target = "203.0.113.21:443".parse().unwrap();
        let first_operator = "10.0.0.2:50136".parse().unwrap();
        let waiting_operator = "10.0.0.2:50137".parse().unwrap();

        engine
            .push_ingress(tcp_syn(first_operator, target, 1_400))
            .unwrap();
        engine.poll(Duration::ZERO, &mut transport).unwrap();
        let Event::OpenTcp(first) = transport.events.pop_front().unwrap() else {
            panic!("expected the first TCP open request");
        };

        engine
            .push_ingress(tcp_syn(waiting_operator, target, 1_500))
            .unwrap();
        engine
            .poll(Duration::from_millis(1), &mut transport)
            .unwrap();
        assert!(engine.pop_egress().is_none());
        assert!(transport.events.is_empty());
        assert_eq!(engine.stats().flow_limit_drops, 1);

        engine
            .push_command(PacketCommand::TcpOpenFailed {
                flow_id: first.flow_id,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(2), &mut transport)
            .unwrap();
        drain_egress(&mut engine);
        assert!(transport.events.is_empty());

        engine
            .push_ingress(tcp_syn(waiting_operator, target, 1_500))
            .unwrap();
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        let Event::OpenTcp(retransmitted) = transport.events.pop_front().unwrap() else {
            panic!("expected the retransmitted SYN to open after capacity returned");
        };
        assert_eq!(retransmitted.operator, waiting_operator);
    }

    #[test]
    fn control_scheduler_stays_bounded_during_permanent_backpressure_and_churn() {
        let limits = PacketEngineLimits {
            max_flows: 1,
            max_tcp_flows: 1,
            max_udp_flows: 1,
            max_pending_controls: 2,
            tcp_open_timeout: Duration::from_millis(1),
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 22);
        let mut transport = TestTransport::with_capacity(0);
        let target = "203.0.113.22:443".parse().unwrap();

        for generation in 0_u16..1_000 {
            let operator = SocketAddr::from((
                [
                    10,
                    0,
                    u8::try_from(generation / 256).unwrap(),
                    generation as u8,
                ],
                50_000 + generation % 10_000,
            ));
            engine
                .push_ingress(tcp_syn(operator, target, u32::from(generation) + 1))
                .unwrap();
            let now = Duration::from_millis(u64::from(generation) * 3);
            engine.poll(now, &mut transport).unwrap();
            engine
                .poll(now + Duration::from_millis(2), &mut transport)
                .unwrap();
            while engine.pop_egress().is_some() {}
            assert!(engine.control_messages.len() <= limits.max_pending_controls);
        }

        assert_eq!(engine.control_messages.len(), limits.max_pending_controls);
        transport.capacity = 16;
        engine.poll(Duration::from_secs(4), &mut transport).unwrap();
        assert!(engine.control_messages.is_empty());
        let terminal_ids = transport
            .events
            .iter()
            .filter_map(|event| match event {
                Event::TcpReset(flow_id, _) => Some(*flow_id),
                _ => None,
            })
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(terminal_ids.len(), limits.max_pending_controls);
    }

    #[test]
    fn blocked_control_retry_does_not_hide_an_unrelated_ready_flow() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 28);
        let mut transport = TestTransport::with_capacity(16);
        let blocked = FlowId::from_test_value(100);
        let ready = FlowId::from_test_value(101);
        transport.blocked_flows.insert(blocked);
        engine
            .queue_control(ControlMessage::ResetTcp(
                blocked,
                TcpResetReason::IdleTimedOut,
            ))
            .unwrap();
        engine
            .queue_control(ControlMessage::ResetTcp(
                ready,
                TcpResetReason::IdleTimedOut,
            ))
            .unwrap();

        engine.flush_controls(&mut transport).unwrap();

        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReset(ready, TcpResetReason::IdleTimedOut))
        );
        assert!(transport.events.is_empty());
        assert!(matches!(
            engine.control_messages.front(),
            Some(ControlMessage::ResetTcp(flow_id, _)) if *flow_id == blocked
        ));
    }

    #[test]
    fn maximum_portable_udp_datagrams_reassemble_and_oversize_is_dropped() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 23);
        let mut transport = TestTransport::with_capacity(16);
        let payload = vec![0x5a; MAX_NETWORK_UDP_DATAGRAM_BYTES];
        for (operator, target) in [
            (
                "10.0.0.2:53003".parse().unwrap(),
                "203.0.113.23:53".parse().unwrap(),
            ),
            (
                "[fd00::2]:53004".parse().unwrap(),
                "[2001:db8::23]:53".parse().unwrap(),
            ),
        ] {
            let fragments = synthesize_udp_response(operator, target, &payload, 1_500, 7, 7)
                .expect("maximum portable UDP datagram must be representable");
            assert!(fragments.len() > 32);
            assert!(fragments.len() <= 64);
            for fragment in fragments {
                engine.push_ingress(fragment).unwrap();
            }
            engine.poll(Duration::ZERO, &mut transport).unwrap();
            let Event::OpenUdp(request) = transport.events.pop_front().unwrap() else {
                panic!("expected the reassembled UDP flow to open");
            };
            engine
                .push_command(PacketCommand::UdpOpened {
                    flow_id: request.flow_id,
                })
                .unwrap();
            engine
                .poll(Duration::from_millis(1), &mut transport)
                .unwrap();
            let Event::Udp(_, forwarded) = transport.events.pop_front().unwrap() else {
                panic!("expected the maximum UDP datagram to be forwarded");
            };
            assert_eq!(forwarded.len(), MAX_NETWORK_UDP_DATAGRAM_BYTES);
        }

        let oversized = vec![0xa5; MAX_NETWORK_UDP_DATAGRAM_BYTES + 1];
        let fragments = synthesize_udp_response(
            "[fd00::3]:53005".parse().unwrap(),
            "[2001:db8::24]:53".parse().unwrap(),
            &oversized,
            1_500,
            8,
            8,
        )
        .expect("IPv6 can represent one byte beyond the portable contract");
        for fragment in fragments {
            engine.push_ingress(fragment).unwrap();
        }
        engine
            .poll(Duration::from_millis(2), &mut transport)
            .unwrap();
        assert!(transport.events.is_empty());
        assert_eq!(engine.stats().oversized_udp_drops, 1);
    }

    #[test]
    fn refused_tcp_open_emits_reset_without_successful_handshake() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 8);
        let mut transport = TestTransport::with_capacity(16);
        engine
            .push_ingress(tcp_syn(
                "10.0.0.2:50124".parse().unwrap(),
                "203.0.113.10:443".parse().unwrap(),
                200,
            ))
            .unwrap();
        engine.poll(Duration::ZERO, &mut transport).unwrap();
        let Event::OpenTcp(request) = transport.events.pop_front().unwrap() else {
            panic!("expected an open request");
        };
        engine
            .push_command(PacketCommand::TcpOpenFailed {
                flow_id: request.flow_id,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(1), &mut transport)
            .unwrap();
        let reset = engine.pop_egress().expect("expected reset");
        assert_ne!(reset[33] & 0x04, 0);
        assert_eq!(reset[33] & 0x02, 0);
    }

    #[test]
    fn full_transport_does_not_consume_tcp_receive_bytes() {
        let limits = PacketEngineLimits {
            max_tcp_data_event_bytes: 4,
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 9);
        let mut transport = TestTransport::with_capacity(0);
        engine
            .push_ingress(tcp_syn(
                "10.0.0.2:50125".parse().unwrap(),
                "203.0.113.11:443".parse().unwrap(),
                300,
            ))
            .unwrap();
        engine.poll(Duration::ZERO, &mut transport).unwrap();
        assert!(engine.pop_egress().is_none());
        assert_eq!(engine.tcp_by_id.len(), 1);
    }

    #[test]
    fn closed_flow_output_terminates_instead_of_retrying_forever() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 30);
        let mut transport = TestTransport::with_capacity(16);
        let operator: SocketAddr = "10.0.0.2:50144".parse().unwrap();
        let target: SocketAddr = "203.0.113.44:443".parse().unwrap();
        let operator_sequence = 2_000;
        let (flow_id, server_sequence) = establish_tcp(
            &mut engine,
            &mut transport,
            operator,
            target,
            operator_sequence,
        );
        transport.closed_flows.insert(flow_id);
        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                operator_sequence + 1,
                server_sequence + 1,
                0x18,
                b"cannot be delivered",
            ))
            .unwrap();

        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();

        assert!(!engine.tcp_by_id.contains_key(&flow_id));
        assert!(engine.control_messages.is_empty());
        assert!(transport.events.is_empty());
    }

    #[test]
    fn udp_flow_is_per_remote_tuple_and_flushes_after_open() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 10);
        let mut transport = TestTransport::with_capacity(16);
        let operator: SocketAddr = "10.0.0.2:53000".parse().unwrap();
        let target: SocketAddr = "203.0.113.53:53".parse().unwrap();
        let packet = synthesize_udp_response(operator, target, b"query", 1500, 1, 1)
            .unwrap()
            .pop()
            .unwrap();

        engine.push_ingress(packet).unwrap();
        engine.poll(Duration::ZERO, &mut transport).unwrap();
        let Event::OpenUdp(request) = transport.events.pop_front().unwrap() else {
            panic!("expected a UDP open request");
        };
        assert_eq!(request.operator, operator);
        assert_eq!(request.target, target);
        assert!(transport.events.is_empty());

        engine
            .push_command(PacketCommand::UdpOpened {
                flow_id: request.flow_id,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(1), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Udp(request.flow_id, Bytes::from_static(b"query")))
        );

        engine
            .push_command(PacketCommand::UdpDatagram {
                flow_id: request.flow_id,
                data: Bytes::from_static(b"answer"),
                receive_bytes: 9,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(2), &mut transport)
            .unwrap();
        let response = engine.pop_egress().expect("expected a UDP response");
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::UdpReceiveReleased(request.flow_id, 9))
        );
        let ParsedIpPacket::Complete(response) = parse_ip_packet(response).unwrap() else {
            panic!("expected a complete UDP response");
        };
        let datagram = parse_udp(&response).unwrap().unwrap();
        assert_eq!(datagram.operator, target);
        assert_eq!(datagram.target, operator);
        assert_eq!(datagram.payload, Bytes::from_static(b"answer"));
    }

    #[test]
    fn ipv6_udp_flow_opens_and_exchanges_datagrams() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 25);
        let mut transport = TestTransport::with_capacity(16);
        let operator: SocketAddr = "[fd00::2]:53006".parse().unwrap();
        let target: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
        let packet = synthesize_udp_response(operator, target, b"query-ipv6", 1_500, 1, 1)
            .unwrap()
            .pop()
            .unwrap();

        engine.push_ingress(packet).unwrap();
        engine.poll(Duration::ZERO, &mut transport).unwrap();
        let Event::OpenUdp(request) = transport.events.pop_front().unwrap() else {
            panic!("expected an IPv6 UDP open request");
        };
        assert_eq!(request.operator, operator);
        assert_eq!(request.target, target);

        engine
            .push_command(PacketCommand::UdpOpened {
                flow_id: request.flow_id,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(1), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Udp(
                request.flow_id,
                Bytes::from_static(b"query-ipv6")
            ))
        );

        engine
            .push_command(PacketCommand::UdpDatagram {
                flow_id: request.flow_id,
                data: Bytes::from_static(b"answer-ipv6"),
                receive_bytes: 11,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(2), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::UdpReceiveReleased(request.flow_id, 11))
        );
        let response = engine.pop_egress().expect("expected an IPv6 UDP response");
        let ParsedIpPacket::Complete(response) = parse_ip_packet(response).unwrap() else {
            panic!("expected a complete IPv6 UDP response");
        };
        let datagram = parse_udp(&response).unwrap().unwrap();
        assert_eq!(datagram.operator, target);
        assert_eq!(datagram.target, operator);
        assert_eq!(datagram.payload, Bytes::from_static(b"answer-ipv6"));
    }

    #[test]
    fn ipv6_tcp_flow_opens_and_exchanges_data() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 24);
        let mut transport = TestTransport::with_capacity(32);
        let operator: SocketAddr = "[fd00::2]:50130".parse().unwrap();
        let target: SocketAddr = "[2001:db8::12]:443".parse().unwrap();
        let operator_sequence = 600_u32;
        let (flow_id, server_sequence) = establish_tcp(
            &mut engine,
            &mut transport,
            operator,
            target,
            operator_sequence,
        );

        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                operator_sequence + 1,
                server_sequence + 1,
                0x18,
                b"hello-ipv6",
            ))
            .unwrap();
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Tcp(flow_id, Bytes::from_static(b"hello-ipv6")))
        );
        drain_egress(&mut engine);

        engine
            .push_command(PacketCommand::TcpData {
                flow_id,
                data: Bytes::from_static(b"response-ipv6"),
                receive_bytes: 13,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(4), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReceiveReleased(flow_id, 13))
        );
        let packets = drain_egress(&mut engine);
        let payload = packets
            .iter()
            .flat_map(|packet| packet.payload.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(payload, b"response-ipv6");
    }

    #[test]
    fn tcp_stream_preserves_data_and_both_half_closes() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 11);
        let mut transport = TestTransport::with_capacity(32);
        let operator: SocketAddr = "10.0.0.2:50126".parse().unwrap();
        let target: SocketAddr = "203.0.113.12:443".parse().unwrap();
        let operator_sequence = 400_u32;
        let (flow_id, server_sequence) = establish_tcp(
            &mut engine,
            &mut transport,
            operator,
            target,
            operator_sequence,
        );

        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                operator_sequence + 1,
                server_sequence + 1,
                0x19,
                b"hello",
            ))
            .unwrap();
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Tcp(flow_id, Bytes::from_static(b"hello")))
        );
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpHalfClose(flow_id))
        );
        assert!(transport.events.is_empty());
        drain_egress(&mut engine);

        engine
            .push_command(PacketCommand::TcpData {
                flow_id,
                data: Bytes::from_static(b"world"),
                receive_bytes: 5,
            })
            .unwrap();
        engine
            .push_command(PacketCommand::TcpHalfClose { flow_id })
            .unwrap();
        engine
            .poll(Duration::from_millis(4), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReceiveReleased(flow_id, 5))
        );
        assert!(transport.events.is_empty());
        let packets = drain_egress(&mut engine);
        assert_eq!(
            packets
                .iter()
                .flat_map(|packet| packet.payload.iter().copied())
                .collect::<Vec<_>>(),
            b"world"
        );
        let fin = packets
            .iter()
            .find(|packet| packet.flags & 0x01 != 0)
            .expect("session half-close must emit FIN");
        let server_acknowledgement = fin.sequence + fin.payload.len() as u32 + 1;
        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                operator_sequence + 7,
                server_acknowledgement,
                0x10,
                &[],
            ))
            .unwrap();
        engine
            .poll(Duration::from_millis(5), &mut transport)
            .unwrap();
        assert!(matches!(
            engine.tcp_by_id.get(&flow_id).map(|flow| flow.state),
            Some(TcpFlowState::Draining { close_sent: true })
        ));
        assert_eq!(transport.events.pop_front(), Some(Event::TcpClose(flow_id)));
        assert!(transport.events.is_empty());
        engine
            .push_command(PacketCommand::TcpStopped {
                flow_id,
                reset_operator: false,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(6), &mut transport)
            .unwrap();
        assert!(!engine.tcp_by_id.contains_key(&flow_id));
    }

    #[test]
    fn tcp_fin_is_forwarded_only_after_all_preceding_data() {
        let limits = PacketEngineLimits {
            max_tcp_data_event_bytes: 4,
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 19);
        let mut transport = TestTransport::with_capacity(32);
        let operator: SocketAddr = "10.0.0.2:50133".parse().unwrap();
        let target: SocketAddr = "203.0.113.19:443".parse().unwrap();
        let operator_sequence = 1_100_u32;
        let (flow_id, server_sequence) = establish_tcp(
            &mut engine,
            &mut transport,
            operator,
            target,
            operator_sequence,
        );

        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                operator_sequence + 1,
                server_sequence + 1,
                0x19,
                b"12345678",
            ))
            .unwrap();
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();

        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Tcp(flow_id, Bytes::from_static(b"1234")))
        );
        assert!(transport.events.is_empty());

        engine
            .poll(Duration::from_millis(4), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Tcp(flow_id, Bytes::from_static(b"5678")))
        );
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpHalfClose(flow_id))
        );
        assert!(transport.events.is_empty());
    }

    #[test]
    fn operator_reset_is_reported_and_removes_the_flow() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 12);
        let mut transport = TestTransport::with_capacity(16);
        let operator: SocketAddr = "10.0.0.2:50127".parse().unwrap();
        let target: SocketAddr = "203.0.113.13:443".parse().unwrap();
        let (flow_id, server_sequence) =
            establish_tcp(&mut engine, &mut transport, operator, target, 500);
        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                501,
                server_sequence + 1,
                0x14,
                &[],
            ))
            .unwrap();
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();

        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReset(flow_id, TcpResetReason::OperatorReset))
        );
        assert!(!engine.tcp_by_id.contains_key(&flow_id));
    }

    #[test]
    fn tcp_open_timeout_resets_both_sides() {
        let limits = PacketEngineLimits {
            tcp_open_timeout: Duration::from_millis(10),
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 13);
        let mut transport = TestTransport::with_capacity(16);
        engine
            .push_ingress(tcp_syn(
                "10.0.0.2:50128".parse().unwrap(),
                "203.0.113.14:443".parse().unwrap(),
                600,
            ))
            .unwrap();
        engine.poll(Duration::ZERO, &mut transport).unwrap();
        let Event::OpenTcp(request) = transport.events.pop_front().unwrap() else {
            panic!("expected a TCP open request");
        };
        engine
            .poll(Duration::from_millis(10), &mut transport)
            .unwrap();

        assert_ne!(
            engine.pop_egress().expect("timeout must emit RST")[33] & 0x04,
            0
        );
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReset(
                request.flow_id,
                TcpResetReason::OpenTimedOut
            ))
        );
        assert!(!engine.tcp_by_id.contains_key(&request.flow_id));
    }

    #[test]
    fn blocked_transport_closes_the_operator_receive_window() {
        let limits = PacketEngineLimits {
            tcp_receive_bytes_per_flow: 8,
            max_tcp_data_event_bytes: 4,
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 14);
        let mut transport = TestTransport::with_capacity(16);
        let operator: SocketAddr = "10.0.0.2:50129".parse().unwrap();
        let target: SocketAddr = "203.0.113.15:443".parse().unwrap();
        let (flow_id, server_sequence) =
            establish_tcp(&mut engine, &mut transport, operator, target, 700);
        transport.capacity = 0;
        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                701,
                server_sequence + 1,
                0x18,
                b"12345678",
            ))
            .unwrap();
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        engine
            .poll(Duration::from_millis(200), &mut transport)
            .unwrap();
        let acknowledgements = drain_egress(&mut engine);
        assert!(
            acknowledgements
                .iter()
                .any(|packet| packet.acknowledgement == 709 && packet.window == 0),
            "unexpected acknowledgements: {acknowledgements:?}"
        );
        let flow = engine.tcp_by_id.get(&flow_id).unwrap();
        assert_eq!(engine.sockets.get::<TcpSocket>(flow.socket).recv_queue(), 8);

        transport.capacity = 1;
        engine
            .poll(Duration::from_millis(201), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Tcp(flow_id, Bytes::from_static(b"1234")))
        );
        let flow = engine.tcp_by_id.get(&flow_id).unwrap();
        assert_eq!(engine.sockets.get::<TcpSocket>(flow.socket).recv_queue(), 4);
    }

    #[test]
    fn active_close_retains_time_wait_before_reusing_the_tuple() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 15);
        let mut transport = TestTransport::with_capacity(16);
        let operator: SocketAddr = "10.0.0.2:50130".parse().unwrap();
        let target: SocketAddr = "203.0.113.16:443".parse().unwrap();
        let (flow_id, _server_sequence) =
            establish_tcp(&mut engine, &mut transport, operator, target, 800);
        engine
            .push_command(PacketCommand::TcpHalfClose { flow_id })
            .unwrap();
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        let packets = drain_egress(&mut engine);
        let fin = packets
            .iter()
            .find(|packet| packet.flags & 0x01 != 0)
            .expect("active close must emit FIN");
        let server_acknowledgement = fin.sequence + fin.payload.len() as u32 + 1;
        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                801,
                server_acknowledgement,
                0x10,
                &[],
            ))
            .unwrap();
        engine
            .poll(Duration::from_millis(4), &mut transport)
            .unwrap();
        drain_egress(&mut engine);
        engine
            .push_ingress(tcp_segment(
                operator,
                target,
                801,
                server_acknowledgement,
                0x11,
                &[],
            ))
            .unwrap();
        engine
            .poll(Duration::from_millis(5), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpHalfClose(flow_id))
        );
        let flow = engine.tcp_by_id.get(&flow_id).unwrap();
        assert_eq!(
            engine.sockets.get::<TcpSocket>(flow.socket).state(),
            State::TimeWait
        );

        engine.poll(Duration::from_secs(9), &mut transport).unwrap();
        assert!(engine.tcp_by_id.contains_key(&flow_id));
        engine
            .poll(Duration::from_secs(11), &mut transport)
            .unwrap();
        assert!(matches!(
            engine.tcp_by_id.get(&flow_id).map(|flow| flow.state),
            Some(TcpFlowState::Draining { close_sent: true })
        ));
        assert_eq!(transport.events.pop_front(), Some(Event::TcpClose(flow_id)));
        engine
            .push_command(PacketCommand::TcpStopped {
                flow_id,
                reset_operator: false,
            })
            .unwrap();
        engine
            .poll(Duration::from_secs(12), &mut transport)
            .unwrap();
        assert!(!engine.tcp_by_id.contains_key(&flow_id));
    }

    #[test]
    fn established_tcp_idle_timeout_resets_both_sides() {
        let limits = PacketEngineLimits {
            tcp_idle_timeout: Duration::from_millis(10),
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 16);
        let mut transport = TestTransport::with_capacity(16);
        let (flow_id, _) = establish_tcp(
            &mut engine,
            &mut transport,
            "10.0.0.2:50131".parse().unwrap(),
            "203.0.113.17:443".parse().unwrap(),
            900,
        );

        engine
            .poll(Duration::from_millis(12), &mut transport)
            .unwrap();
        assert_ne!(
            engine.pop_egress().expect("idle timeout must emit RST")[33] & 0x04,
            0
        );
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReset(flow_id, TcpResetReason::IdleTimedOut))
        );
        assert!(!engine.tcp_by_id.contains_key(&flow_id));
    }

    #[test]
    fn blocked_flow_does_not_block_commands_for_another_flow() {
        let limits = PacketEngineLimits {
            tcp_send_bytes_per_flow: 4,
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 17);
        let mut transport = TestTransport::with_capacity(32);
        let (tcp_flow_id, _) = establish_tcp(
            &mut engine,
            &mut transport,
            "10.0.0.2:50132".parse().unwrap(),
            "203.0.113.18:443".parse().unwrap(),
            1_000,
        );
        let operator: SocketAddr = "10.0.0.2:53002".parse().unwrap();
        let target: SocketAddr = "203.0.113.53:53".parse().unwrap();
        let query = synthesize_udp_response(operator, target, b"query", 1500, 3, 3)
            .unwrap()
            .pop()
            .unwrap();
        engine.push_ingress(query).unwrap();
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        let Event::OpenUdp(request) = transport.events.pop_front().unwrap() else {
            panic!("expected a UDP open request");
        };
        engine
            .push_command(PacketCommand::UdpOpened {
                flow_id: request.flow_id,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(4), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Udp(request.flow_id, Bytes::from_static(b"query")))
        );

        engine
            .push_command(PacketCommand::TcpData {
                flow_id: tcp_flow_id,
                data: Bytes::from_static(b"12345678"),
                receive_bytes: 8,
            })
            .unwrap();
        engine
            .push_command(PacketCommand::UdpDatagram {
                flow_id: request.flow_id,
                data: Bytes::from_static(b"answer"),
                receive_bytes: 9,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(5), &mut transport)
            .unwrap();

        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReceiveReleased(tcp_flow_id, 4))
        );
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::UdpReceiveReleased(request.flow_id, 9))
        );
        assert!(transport.events.is_empty());
        assert_eq!(
            engine
                .command_usage
                .get(&tcp_flow_id)
                .expect("the remainder must stay queued")
                .bytes,
            4
        );
    }

    #[test]
    fn lifecycle_commands_bypass_full_data_capacity_for_another_flow() {
        let limits = PacketEngineLimits {
            max_commands: 1,
            max_command_bytes: 4,
            max_commands_per_flow: 1,
            max_command_bytes_per_flow: 4,
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 26);
        let mut transport = TestTransport::with_capacity(32);
        let (blocked_flow, _) = establish_tcp(
            &mut engine,
            &mut transport,
            "10.0.0.2:50140".parse().unwrap(),
            "203.0.113.40:443".parse().unwrap(),
            1_600,
        );
        let (healthy_flow, _) = establish_tcp(
            &mut engine,
            &mut transport,
            "10.0.0.2:50141".parse().unwrap(),
            "203.0.113.41:443".parse().unwrap(),
            1_700,
        );

        engine
            .push_command(PacketCommand::TcpData {
                flow_id: blocked_flow,
                data: Bytes::from_static(b"full"),
                receive_bytes: 4,
            })
            .unwrap();
        let error = engine
            .push_command(PacketCommand::TcpData {
                flow_id: blocked_flow,
                data: Bytes::from_static(b"more"),
                receive_bytes: 4,
            })
            .unwrap_err();
        assert_eq!(error.kind, PacketCommandErrorKind::Full);
        let retained_pointer = match error.command.as_command() {
            PacketCommand::TcpData { data, .. } => data.as_ptr(),
            _ => panic!("full data admission returned the wrong command"),
        };
        let error = engine.admit_command(error.command).unwrap_err();
        assert_eq!(error.kind, PacketCommandErrorKind::Full);
        let retried_pointer = match error.command.as_command() {
            PacketCommand::TcpData { data, .. } => data.as_ptr(),
            _ => panic!("retried data admission returned the wrong command"),
        };
        assert_eq!(retained_pointer, retried_pointer);
        engine
            .push_command(PacketCommand::TcpHalfClose {
                flow_id: healthy_flow,
            })
            .expect("lifecycle transitions must not consume data-command capacity");

        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        assert!(
            engine
                .tcp_by_id
                .get(&healthy_flow)
                .expect("healthy flow must remain present")
                .session_half_closed
        );
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReceiveReleased(blocked_flow, 4))
        );
    }

    #[test]
    fn stopped_flow_under_its_data_cap_releases_preceding_credit_exactly() {
        let limits = PacketEngineLimits {
            max_commands: 1,
            max_command_bytes: 4,
            max_commands_per_flow: 1,
            max_command_bytes_per_flow: 4,
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 27);
        let mut transport = TestTransport::with_capacity(32);
        let (flow_id, _) = establish_tcp(
            &mut engine,
            &mut transport,
            "10.0.0.2:50142".parse().unwrap(),
            "203.0.113.42:443".parse().unwrap(),
            1_800,
        );
        engine
            .push_command(PacketCommand::TcpData {
                flow_id,
                data: Bytes::from_static(b"data"),
                receive_bytes: 4,
            })
            .unwrap();
        engine
            .push_command(PacketCommand::TcpStopped {
                flow_id,
                reset_operator: true,
            })
            .expect("stop acknowledgement must bypass the per-flow data cap");

        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReceiveReleased(flow_id, 4))
        );
        assert!(transport.events.is_empty());
        assert!(!engine.tcp_by_id.contains_key(&flow_id));
    }

    #[test]
    fn one_byte_tcp_remainder_owns_only_its_compact_allocation() {
        let limits = PacketEngineLimits {
            tcp_send_bytes_per_flow: 4,
            max_tcp_data_event_bytes: 5,
            ..PacketEngineLimits::default()
        };
        let mut engine = PacketEngine::new(limits, 29);
        let mut transport = TestTransport::with_capacity(16);
        let (flow_id, _) = establish_tcp(
            &mut engine,
            &mut transport,
            "10.0.0.2:50143".parse().unwrap(),
            "203.0.113.43:443".parse().unwrap(),
            1_900,
        );
        let mut oversized_backing = BytesMut::with_capacity(64 * 1024);
        oversized_backing.extend_from_slice(b"12345");
        let data = oversized_backing.freeze();
        let allocation_guard = data.clone();
        engine
            .push_command(PacketCommand::TcpData {
                flow_id,
                data,
                receive_bytes: 5,
            })
            .unwrap();

        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();

        let remainder = engine
            .commands
            .iter()
            .find_map(|command| match command {
                PacketCommand::TcpData { data, .. } => Some(data),
                _ => None,
            })
            .expect("one byte must remain behind the full smoltcp send buffer");
        assert_eq!(remainder.as_ref(), b"5");
        assert_ne!(
            remainder.as_ptr(),
            allocation_guard.as_ptr().wrapping_add(4),
            "the logical remainder must not retain the original 64 KiB allocation"
        );
        assert_eq!(engine.command_bytes, 1);
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::TcpReceiveReleased(flow_id, 4))
        );
    }

    #[test]
    fn queued_udp_datagrams_cannot_be_overtaken() {
        let mut engine = PacketEngine::new(PacketEngineLimits::default(), 18);
        let mut transport = TestTransport::with_capacity(16);
        let operator: SocketAddr = "10.0.0.2:53001".parse().unwrap();
        let target: SocketAddr = "203.0.113.53:53".parse().unwrap();
        let first = synthesize_udp_response(operator, target, b"first", 1500, 1, 1)
            .unwrap()
            .pop()
            .unwrap();
        let second = synthesize_udp_response(operator, target, b"second", 1500, 2, 2)
            .unwrap()
            .pop()
            .unwrap();
        engine.push_ingress(first).unwrap();
        engine.poll(Duration::ZERO, &mut transport).unwrap();
        let Event::OpenUdp(request) = transport.events.pop_front().unwrap() else {
            panic!("expected a UDP open request");
        };
        transport.capacity = 0;
        engine
            .push_command(PacketCommand::UdpOpened {
                flow_id: request.flow_id,
            })
            .unwrap();
        engine
            .poll(Duration::from_millis(1), &mut transport)
            .unwrap();

        transport.capacity = 1;
        engine.push_ingress(second).unwrap();
        engine
            .poll(Duration::from_millis(2), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Udp(request.flow_id, Bytes::from_static(b"first")))
        );
        engine
            .poll(Duration::from_millis(3), &mut transport)
            .unwrap();
        assert_eq!(
            transport.events.pop_front(),
            Some(Event::Udp(request.flow_id, Bytes::from_static(b"second")))
        );
    }
}
