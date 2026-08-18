use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::NETWORK_SESSION_FLOW_LIMIT;
use crate::debug::debug_log;
use crate::network::{
    NetworkError, NetworkErrorKind, NetworkTarget, OperatorNetworkSession, ResolutionFamily,
    ResolveOutcome, ResolveRequest, TcpReceiveCredit, TcpTunnelReceiver, TcpTunnelSender,
    UdpReceiveCredit, UdpTunnelReceiver, UdpTunnelSender,
};

use super::configuration::{SyntheticNetworkConfiguration, VpnNetworkConfiguration};
use super::dns::{
    DnsQuery, Ipv4Pool, Ipv6Pool, Resolution, ResponseCode, SyntheticAddressMap,
    synthesize_response,
};
use super::packet::{
    FlowId, PacketCommand, PacketCommandError, PacketCommandErrorKind, PacketEngine,
    PacketEngineAddresses, PacketEngineError, PacketEngineLimits, PacketTransport,
    PendingPacketCommand, TcpOpenRequest, TcpResetReason, TransportSendError, UdpOpenRequest,
};
use super::policy::SystemVpnPolicy;

const FLOW_OUTPUT_MESSAGES: usize = 32;
const OPEN_REQUESTS: usize = NETWORK_SESSION_FLOW_LIMIT;
const RUNTIME_EVENTS: usize = 512;
const SESSION_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SYNTHETIC_ADDRESSES_PER_FAMILY: usize = 65_000;
const MAX_DNS_QUERIES_PER_FLOW: usize = 16;
const MAX_DNS_TCP_BUFFER_BYTES: usize = 256 * 1024;
const DNS_TIMEOUT_MILLIS: u32 = 10_000;
const DNS_UDP_RESPONSE_BYTES: usize = 1_232;
const DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(30);

pub(super) struct VpnRuntime {
    task: Option<AbortOnDropHandle<Result<()>>>,
}

impl VpnRuntime {
    pub(super) fn start<R, W>(
        reader: R,
        writer: W,
        session: OperatorNetworkSession,
        network: VpnNetworkConfiguration,
        policy: SystemVpnPolicy,
    ) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let transport = SessionPacketTransport::new(session, network, policy)?;
        let limits = PacketEngineLimits {
            mtu: super::VPN_MTU as usize,
            ..PacketEngineLimits::default()
        };
        let engine = PacketEngine::new_with_addresses(
            limits,
            rand::random(),
            PacketEngineAddresses {
                gateway_ipv4: network.gateway_ipv4,
                gateway_ipv6: network.gateway_ipv6,
            },
        );
        let task = AbortOnDropHandle::new(tokio::spawn(run_packet_loop(
            reader, writer, engine, transport,
        )));
        Ok(Self { task: Some(task) })
    }

    pub(super) async fn wait(&mut self) -> Result<()> {
        let result = self
            .task
            .as_mut()
            .context("VPN packet runtime has already stopped")?
            .await;
        self.task = None;
        result.context("VPN packet runtime task failed to join")?
    }

    pub(super) async fn shutdown(mut self) -> Result<()> {
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        task.abort();
        match task.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error).context("VPN packet runtime task failed to join"),
        }
    }
}

struct BufferedBytes {
    data: Bytes,
    permit: Option<OwnedSemaphorePermit>,
    output_ready: Arc<Notify>,
}

impl BufferedBytes {
    fn new(data: Bytes, permit: OwnedSemaphorePermit, output_ready: Arc<Notify>) -> Self {
        Self {
            data,
            permit: Some(permit),
            output_ready,
        }
    }
}

impl Drop for BufferedBytes {
    fn drop(&mut self) {
        self.permit.take();
        self.output_ready.notify_one();
    }
}

enum TcpOutput {
    Data(BufferedBytes),
    HalfClose,
    Close,
}

enum UdpOutput {
    Datagram(BufferedBytes),
}

struct FlowOutputHandle<T> {
    messages: mpsc::Sender<T>,
    cancellation: CancellationToken,
}

struct FlowOutputStream<T> {
    messages: mpsc::Receiver<T>,
    cancellation: CancellationToken,
    output_ready: Arc<Notify>,
}

struct TcpFlowOutput {
    handle: FlowOutputHandle<TcpOutput>,
    // A draining handle deliberately remains in the map. Dropping it before
    // TcpStopped would abandon data already admitted ahead of the close marker.
    draining: bool,
}

impl TcpFlowOutput {
    fn new(handle: FlowOutputHandle<TcpOutput>) -> Self {
        Self {
            handle,
            draining: false,
        }
    }

    fn active_handle(
        &self,
    ) -> Result<&FlowOutputHandle<TcpOutput>, TransportSendError<NetworkError>> {
        if self.draining {
            return Err(TransportSendError::FlowClosed);
        }
        Ok(&self.handle)
    }

    fn begin_draining(&mut self) -> Result<(), TransportSendError<NetworkError>> {
        if self.draining {
            return Ok(());
        }
        match self.handle.messages.try_send(TcpOutput::Close) {
            Ok(()) => {
                self.draining = true;
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => Err(TransportSendError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportSendError::FlowClosed),
        }
    }

    fn abort(self) {
        self.handle.abort();
    }
}

enum FlowOutputEvent<T> {
    Message(T),
    Aborted,
    Closed,
}

impl<T> FlowOutputHandle<T> {
    fn new(output_ready: Arc<Notify>) -> (Self, FlowOutputStream<T>) {
        let (messages, receiver) = mpsc::channel(FLOW_OUTPUT_MESSAGES);
        let cancellation = CancellationToken::new();
        (
            Self {
                messages,
                cancellation: cancellation.clone(),
            },
            FlowOutputStream {
                messages: receiver,
                cancellation,
                output_ready,
            },
        )
    }

    fn abort(self) {
        self.cancellation.cancel();
    }
}

impl<T> FlowOutputStream<T> {
    fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    async fn receive(&mut self) -> FlowOutputEvent<T> {
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => FlowOutputEvent::Aborted,
            message = self.messages.recv() => {
                self.output_ready.notify_one();
                match message {
                    Some(message) => FlowOutputEvent::Message(message),
                    None => FlowOutputEvent::Closed,
                }
            }
        }
    }
}

impl<T> Drop for FlowOutputStream<T> {
    fn drop(&mut self) {
        self.output_ready.notify_one();
    }
}

enum OpenRequest {
    Tcp {
        request: TcpOpenRequest,
        target: Result<NetworkTarget, NetworkError>,
        output: FlowOutputStream<TcpOutput>,
    },
    Udp {
        request: UdpOpenRequest,
        target: Result<NetworkTarget, NetworkError>,
        output: FlowOutputStream<UdpOutput>,
    },
    DnsTcp {
        request: TcpOpenRequest,
        output: FlowOutputStream<TcpOutput>,
    },
    DnsUdp {
        request: UdpOpenRequest,
        output: FlowOutputStream<UdpOutput>,
    },
    HealthUdp {
        request: UdpOpenRequest,
        output: FlowOutputStream<UdpOutput>,
    },
}

enum LifecycleRuntimeEvent {
    TcpOpened {
        flow_id: FlowId,
        credit: Option<TcpReceiveCredit>,
    },
    UdpOpened {
        flow_id: FlowId,
        credit: Option<UdpReceiveCredit>,
    },
    TcpHalfClosed(FlowId),
    TcpOpenFailed(FlowId),
    UdpOpenFailed(FlowId),
    TcpStopped {
        flow_id: FlowId,
        reset_operator: bool,
    },
    UdpStopped(FlowId),
}

enum DataRuntimeEvent {
    TcpReceived {
        flow_id: FlowId,
        data: Bytes,
        receive_bytes: usize,
    },
    UdpReceived {
        flow_id: FlowId,
        data: Bytes,
        receive_bytes: usize,
    },
    LocalUdpDatagram {
        flow_id: FlowId,
        data: Bytes,
    },
    DnsResolved {
        flow_id: FlowId,
        query: DnsQuery,
        outcome: ResolveOutcome,
        transport: DnsTransport,
    },
}

impl DataRuntimeEvent {
    fn flow_id(&self) -> FlowId {
        match self {
            Self::TcpReceived { flow_id, .. }
            | Self::UdpReceived { flow_id, .. }
            | Self::LocalUdpDatagram { flow_id, .. }
            | Self::DnsResolved { flow_id, .. } => *flow_id,
        }
    }
}

struct RuntimeEventEnvelope<E> {
    event: E,
    acknowledgement: oneshot::Sender<()>,
}

#[derive(Clone)]
struct RuntimeEventSenders {
    lifecycle: mpsc::Sender<RuntimeEventEnvelope<LifecycleRuntimeEvent>>,
    data: mpsc::Sender<RuntimeEventEnvelope<DataRuntimeEvent>>,
}

#[derive(Clone, Copy)]
enum DnsTransport {
    Tcp,
    Udp,
}

struct CreditEntry<C> {
    credit: C,
    outstanding: usize,
    reader_closed: bool,
}

trait ReceiveCredit {
    fn release_capacity(&mut self, bytes: usize) -> Result<(), NetworkError>;
}

impl ReceiveCredit for TcpReceiveCredit {
    fn release_capacity(&mut self, bytes: usize) -> Result<(), NetworkError> {
        self.release_receive_capacity(bytes)
    }
}

impl ReceiveCredit for UdpReceiveCredit {
    fn release_capacity(&mut self, bytes: usize) -> Result<(), NetworkError> {
        self.release_receive_capacity(bytes)
    }
}

impl<C> CreditEntry<C> {
    fn note_receive(&mut self, bytes: usize) -> Result<()> {
        self.outstanding = self
            .outstanding
            .checked_add(bytes)
            .context("receive-credit accounting overflowed")?;
        Ok(())
    }

    fn close_reader(&mut self) -> bool {
        self.reader_closed = true;
        self.outstanding == 0
    }
}

impl<C: ReceiveCredit> CreditEntry<C> {
    fn release(&mut self, bytes: usize) -> Result<(), NetworkError> {
        if bytes > self.outstanding {
            return Err(NetworkError::new(
                NetworkErrorKind::Protocol,
                format!(
                    "released {bytes} receive bytes with only {} outstanding",
                    self.outstanding
                ),
            ));
        }
        self.credit.release_capacity(bytes)?;
        self.outstanding -= bytes;
        Ok(())
    }

    fn is_finished(&self) -> bool {
        self.reader_closed && self.outstanding == 0
    }
}

struct SessionPacketTransport {
    open_sender: mpsc::Sender<OpenRequest>,
    lifecycle_events: mpsc::Receiver<RuntimeEventEnvelope<LifecycleRuntimeEvent>>,
    data_events: mpsc::Receiver<RuntimeEventEnvelope<DataRuntimeEvent>>,
    dispatcher: AbortOnDropHandle<Result<()>>,
    tcp_outputs: HashMap<FlowId, TcpFlowOutput>,
    udp_outputs: HashMap<FlowId, FlowOutputHandle<UdpOutput>>,
    tcp_credits: HashMap<FlowId, CreditEntry<TcpReceiveCredit>>,
    udp_credits: HashMap<FlowId, CreditEntry<UdpReceiveCredit>>,
    output_bytes: Arc<Semaphore>,
    output_ready: Arc<Notify>,
    mappings: SyntheticAddressMap,
    synthetic: Option<SyntheticNetworkConfiguration>,
    health_servers: [SocketAddr; 2],
}

impl SessionPacketTransport {
    fn new(
        session: OperatorNetworkSession,
        network: VpnNetworkConfiguration,
        policy: SystemVpnPolicy,
    ) -> Result<Self> {
        let synthetic = network.synthetic;
        let mappings = synthetic_address_map(synthetic)?;
        let (open_sender, open_receiver) = mpsc::channel(OPEN_REQUESTS);
        let (lifecycle_sender, lifecycle_events) = mpsc::channel(RUNTIME_EVENTS);
        let (data_sender, data_events) = mpsc::channel(RUNTIME_EVENTS);
        let event_senders = RuntimeEventSenders {
            lifecycle: lifecycle_sender,
            data: data_sender,
        };
        let output_ready = Arc::new(Notify::new());
        let dispatcher = AbortOnDropHandle::new(tokio::spawn(run_open_dispatcher(
            session,
            policy,
            open_receiver,
            event_senders,
        )));
        Ok(Self {
            open_sender,
            lifecycle_events,
            data_events,
            dispatcher,
            tcp_outputs: HashMap::new(),
            udp_outputs: HashMap::new(),
            tcp_credits: HashMap::new(),
            udp_credits: HashMap::new(),
            output_bytes: Arc::new(Semaphore::new(SESSION_OUTPUT_BYTES)),
            output_ready,
            mappings,
            synthetic,
            health_servers: [
                SocketAddr::from((network.gateway_ipv4, super::DATA_PLANE_HEALTH_PORT)),
                SocketAddr::from((network.gateway_ipv6, super::DATA_PLANE_HEALTH_PORT)),
            ],
        })
    }

    fn target_for(&self, address: SocketAddr) -> Result<NetworkTarget, NetworkError> {
        network_target_for(&self.mappings, self.synthetic, address)
    }

    fn is_dns_server(&self, address: SocketAddr) -> bool {
        address.port() == 53
            && self.synthetic.is_some_and(|synthetic| {
                address.ip() == IpAddr::V4(synthetic.ipv4_dns)
                    || address.ip() == IpAddr::V6(synthetic.ipv6_dns)
            })
    }

    fn is_health_server(&self, address: SocketAddr) -> bool {
        self.health_servers.contains(&address)
    }

    fn install_tcp_credit(&mut self, flow_id: FlowId, credit: TcpReceiveCredit) -> Result<()> {
        if self
            .tcp_credits
            .insert(
                flow_id,
                CreditEntry {
                    credit,
                    outstanding: 0,
                    reader_closed: false,
                },
            )
            .is_some()
        {
            bail!("TCP flow {flow_id} installed receive credit twice");
        }
        Ok(())
    }

    fn install_udp_credit(&mut self, flow_id: FlowId, credit: UdpReceiveCredit) -> Result<()> {
        if self
            .udp_credits
            .insert(
                flow_id,
                CreditEntry {
                    credit,
                    outstanding: 0,
                    reader_closed: false,
                },
            )
            .is_some()
        {
            bail!("UDP flow {flow_id} installed receive credit twice");
        }
        Ok(())
    }

    fn note_tcp_receive(&mut self, flow_id: FlowId, bytes: usize) -> Result<()> {
        let entry = self.tcp_credits.get_mut(&flow_id).with_context(|| {
            format!("TCP flow {flow_id} received data before credit was installed")
        })?;
        entry
            .note_receive(bytes)
            .context("TCP receive-credit accounting failed")
    }

    fn note_udp_receive(&mut self, flow_id: FlowId, bytes: usize) -> Result<()> {
        let entry = self.udp_credits.get_mut(&flow_id).with_context(|| {
            format!("UDP flow {flow_id} received data before credit was installed")
        })?;
        entry
            .note_receive(bytes)
            .context("UDP receive-credit accounting failed")
    }

    fn close_tcp_reader(&mut self, flow_id: FlowId) {
        if self
            .tcp_credits
            .get_mut(&flow_id)
            .is_some_and(CreditEntry::close_reader)
        {
            self.tcp_credits.remove(&flow_id);
        }
    }

    fn close_udp_reader(&mut self, flow_id: FlowId) {
        if self
            .udp_credits
            .get_mut(&flow_id)
            .is_some_and(CreditEntry::close_reader)
        {
            self.udp_credits.remove(&flow_id);
        }
    }

    fn finish_tcp_flow(&mut self, flow_id: FlowId) {
        if let Some(output) = self.tcp_outputs.remove(&flow_id) {
            output.abort();
        }
        self.close_tcp_reader(flow_id);
    }

    fn finish_udp_flow(&mut self, flow_id: FlowId) {
        if let Some(output) = self.udp_outputs.remove(&flow_id) {
            output.abort();
        }
        self.close_udp_reader(flow_id);
    }

    fn dns_flow_is_active(&self, flow_id: FlowId, transport: DnsTransport) -> bool {
        match transport {
            DnsTransport::Tcp => self.tcp_outputs.contains_key(&flow_id),
            DnsTransport::Udp => self.udp_outputs.contains_key(&flow_id),
        }
    }

    fn synthesize_dns(
        &mut self,
        flow_id: FlowId,
        query: DnsQuery,
        outcome: ResolveOutcome,
        transport: DnsTransport,
    ) -> Result<PacketCommand> {
        synthesize_dns_command(flow_id, query, outcome, transport, &mut self.mappings)
    }

    fn discard_command(&mut self, command: &PacketCommand) -> Result<()> {
        match command {
            PacketCommand::TcpData {
                flow_id,
                receive_bytes,
                ..
            } if *receive_bytes > 0 => self
                .release_tcp_receive(*flow_id, *receive_bytes)
                .map_err(anyhow::Error::from),
            PacketCommand::UdpDatagram {
                flow_id,
                receive_bytes,
                ..
            } if *receive_bytes > 0 => self
                .release_udp_receive(*flow_id, *receive_bytes)
                .map_err(anyhow::Error::from),
            PacketCommand::TcpOpened { flow_id } => {
                self.force_reset_tcp(*flow_id);
                Ok(())
            }
            PacketCommand::UdpOpened { flow_id } => {
                self.force_close_udp(*flow_id);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn force_reset_tcp(&mut self, flow_id: FlowId) {
        if let Some(output) = self.tcp_outputs.remove(&flow_id) {
            output.abort();
        }
    }

    fn force_close_udp(&mut self, flow_id: FlowId) {
        if let Some(output) = self.udp_outputs.remove(&flow_id) {
            output.abort();
        }
    }
}

fn network_target_for(
    mappings: &SyntheticAddressMap,
    synthetic: Option<SyntheticNetworkConfiguration>,
    address: SocketAddr,
) -> Result<NetworkTarget, NetworkError> {
    if let Some(name) = mappings.name_for_address(address.ip()) {
        let name = name
            .to_ascii()
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        let resolution_family = match address.ip() {
            IpAddr::V4(_) => ResolutionFamily::Ipv4,
            IpAddr::V6(_) => ResolutionFamily::Ipv6,
        };
        return NetworkTarget::new_with_resolution_family(name, address.port(), resolution_family)
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()));
    }
    if synthetic.is_some_and(|synthetic| {
        synthetic
            .routes()
            .iter()
            .any(|route| route.contains(&address.ip()))
    }) {
        return Err(NetworkError::new(
            NetworkErrorKind::HostUnreachable,
            "synthetic VPN address has no DNS mapping in this session",
        ));
    }
    Ok(NetworkTarget::from(address))
}

fn synthesize_dns_command(
    flow_id: FlowId,
    query: DnsQuery,
    outcome: ResolveOutcome,
    transport: DnsTransport,
    mappings: &mut SyntheticAddressMap,
) -> Result<PacketCommand> {
    let resolution = dns_resolution(outcome)?;
    let response = synthesize_response(&query, resolution, mappings)
        .context("failed to synthesize a VPN DNS response")?;
    let data = match transport {
        DnsTransport::Tcp => response.to_tcp(),
        DnsTransport::Udp => response.to_udp(DNS_UDP_RESPONSE_BYTES),
    }
    .context("failed to encode a VPN DNS response")?;
    Ok(match transport {
        DnsTransport::Tcp => PacketCommand::TcpData {
            flow_id,
            data: Bytes::from(data),
            receive_bytes: 0,
        },
        DnsTransport::Udp => PacketCommand::UdpDatagram {
            flow_id,
            data: Bytes::from(data),
            receive_bytes: 0,
        },
    })
}

fn synthetic_address_map(
    synthetic: Option<SyntheticNetworkConfiguration>,
) -> Result<SyntheticAddressMap> {
    let Some(synthetic) = synthetic else {
        return Ok(SyntheticAddressMap::new(None, None));
    };
    let ipv4 = Ipv4Pool::new(
        synthetic.ipv4_first,
        synthetic.ipv4_last,
        MAX_SYNTHETIC_ADDRESSES_PER_FAMILY,
        [],
    )?;
    let ipv6 = Ipv6Pool::new(
        synthetic.ipv6_first,
        synthetic.ipv6_last,
        MAX_SYNTHETIC_ADDRESSES_PER_FAMILY,
        [],
    )?;
    Ok(SyntheticAddressMap::new(Some(ipv4), Some(ipv6)))
}

impl PacketTransport for SessionPacketTransport {
    type Error = NetworkError;

    fn try_open_tcp(
        &mut self,
        request: &TcpOpenRequest,
    ) -> Result<(), TransportSendError<Self::Error>> {
        let open_slot = self
            .open_sender
            .try_reserve()
            .map_err(map_open_send_error)?;
        let (output_handle, output) = FlowOutputHandle::new(Arc::clone(&self.output_ready));
        let open = if self.is_dns_server(request.target) {
            OpenRequest::DnsTcp {
                request: *request,
                output,
            }
        } else {
            OpenRequest::Tcp {
                request: *request,
                target: self.target_for(request.target),
                output,
            }
        };
        open_slot.send(open);
        self.tcp_outputs
            .insert(request.flow_id, TcpFlowOutput::new(output_handle));
        Ok(())
    }

    fn try_open_udp(
        &mut self,
        request: &UdpOpenRequest,
    ) -> Result<(), TransportSendError<Self::Error>> {
        let open_slot = self
            .open_sender
            .try_reserve()
            .map_err(map_open_send_error)?;
        let (output_handle, output) = FlowOutputHandle::new(Arc::clone(&self.output_ready));
        let open = if self.is_health_server(request.target) {
            OpenRequest::HealthUdp {
                request: *request,
                output,
            }
        } else if self.is_dns_server(request.target) {
            OpenRequest::DnsUdp {
                request: *request,
                output,
            }
        } else {
            OpenRequest::Udp {
                request: *request,
                target: self.target_for(request.target),
                output,
            }
        };
        open_slot.send(open);
        self.udp_outputs.insert(request.flow_id, output_handle);
        Ok(())
    }

    fn try_send_tcp(
        &mut self,
        flow_id: FlowId,
        data: &[u8],
    ) -> Result<(), TransportSendError<Self::Error>> {
        let output = flow_output(&self.tcp_outputs, flow_id)?;
        let output = output.active_handle()?;
        let slot = match output.messages.try_reserve() {
            Ok(slot) => slot,
            Err(mpsc::error::TrySendError::Full(_)) => return Err(TransportSendError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(TransportSendError::FlowClosed);
            }
        };
        let bytes = u32::try_from(data.len()).map_err(|_| TransportSendError::Full)?;
        let permit = Arc::clone(&self.output_bytes)
            .try_acquire_many_owned(bytes)
            .map_err(|_| TransportSendError::Full)?;
        slot.send(TcpOutput::Data(BufferedBytes::new(
            Bytes::copy_from_slice(data),
            permit,
            Arc::clone(&self.output_ready),
        )));
        Ok(())
    }

    fn try_half_close_tcp(
        &mut self,
        flow_id: FlowId,
    ) -> Result<(), TransportSendError<Self::Error>> {
        let output = flow_output(&self.tcp_outputs, flow_id)?;
        let output = output.active_handle()?;
        match output.messages.try_send(TcpOutput::HalfClose) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(TransportSendError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportSendError::FlowClosed),
        }
    }

    fn try_reset_tcp(
        &mut self,
        flow_id: FlowId,
        _reason: TcpResetReason,
    ) -> Result<(), TransportSendError<Self::Error>> {
        if let Some(output) = self.tcp_outputs.remove(&flow_id) {
            output.abort();
        }
        Ok(())
    }

    fn try_close_tcp(&mut self, flow_id: FlowId) -> Result<(), TransportSendError<Self::Error>> {
        let output = flow_output_mut(&mut self.tcp_outputs, flow_id)?;
        output.begin_draining()
    }

    fn try_send_udp(
        &mut self,
        flow_id: FlowId,
        data: &[u8],
    ) -> Result<(), TransportSendError<Self::Error>> {
        let output = flow_output(&self.udp_outputs, flow_id)?;
        let slot = match output.messages.try_reserve() {
            Ok(slot) => slot,
            Err(mpsc::error::TrySendError::Full(_)) => return Err(TransportSendError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(TransportSendError::FlowClosed);
            }
        };
        let bytes = u32::try_from(data.len()).map_err(|_| TransportSendError::Full)?;
        let permit = Arc::clone(&self.output_bytes)
            .try_acquire_many_owned(bytes)
            .map_err(|_| TransportSendError::Full)?;
        slot.send(UdpOutput::Datagram(BufferedBytes::new(
            Bytes::copy_from_slice(data),
            permit,
            Arc::clone(&self.output_ready),
        )));
        Ok(())
    }

    fn release_tcp_receive(&mut self, flow_id: FlowId, bytes: usize) -> Result<(), Self::Error> {
        let entry = self.tcp_credits.get_mut(&flow_id).ok_or_else(|| {
            NetworkError::new(
                NetworkErrorKind::Protocol,
                format!("TCP flow {flow_id} has no receive-credit ledger"),
            )
        })?;
        entry.release(bytes).map_err(|error| {
            NetworkError::new(
                error.kind,
                format!(
                    "TCP flow {flow_id} receive-credit release failed: {}",
                    error.message
                ),
            )
        })?;
        if entry.is_finished() {
            self.tcp_credits.remove(&flow_id);
        }
        Ok(())
    }

    fn release_udp_receive(&mut self, flow_id: FlowId, bytes: usize) -> Result<(), Self::Error> {
        let entry = self.udp_credits.get_mut(&flow_id).ok_or_else(|| {
            NetworkError::new(
                NetworkErrorKind::Protocol,
                format!("UDP flow {flow_id} has no receive-credit ledger"),
            )
        })?;
        entry.release(bytes).map_err(|error| {
            NetworkError::new(
                error.kind,
                format!(
                    "UDP flow {flow_id} receive-credit release failed: {}",
                    error.message
                ),
            )
        })?;
        if entry.is_finished() {
            self.udp_credits.remove(&flow_id);
        }
        Ok(())
    }

    fn try_close_udp(&mut self, flow_id: FlowId) -> Result<(), TransportSendError<Self::Error>> {
        if let Some(output) = self.udp_outputs.remove(&flow_id) {
            output.abort();
        }
        Ok(())
    }
}

fn flow_output<T>(
    outputs: &HashMap<FlowId, T>,
    flow_id: FlowId,
) -> Result<&T, TransportSendError<NetworkError>> {
    outputs.get(&flow_id).ok_or(TransportSendError::FlowClosed)
}

fn flow_output_mut<T>(
    outputs: &mut HashMap<FlowId, T>,
    flow_id: FlowId,
) -> Result<&mut T, TransportSendError<NetworkError>> {
    outputs
        .get_mut(&flow_id)
        .ok_or(TransportSendError::FlowClosed)
}

fn map_open_send_error<T>(error: mpsc::error::TrySendError<T>) -> TransportSendError<NetworkError> {
    match error {
        mpsc::error::TrySendError::Full(_) => TransportSendError::Full,
        mpsc::error::TrySendError::Closed(_) => TransportSendError::Closed(
            NetworkError::session_closed("VPN transport dispatcher stopped"),
        ),
    }
}

struct PendingDataCommand {
    command: PendingPacketCommand,
    acknowledgement: oneshot::Sender<()>,
}

#[derive(Default)]
struct PendingDataCommands {
    by_flow: HashMap<FlowId, VecDeque<PendingDataCommand>>,
    ready_flows: VecDeque<FlowId>,
    len: usize,
}

impl PendingDataCommands {
    fn is_full(&self) -> bool {
        self.len >= RUNTIME_EVENTS
    }

    fn contains_flow(&self, flow_id: FlowId) -> bool {
        self.by_flow.contains_key(&flow_id)
    }

    fn push(&mut self, pending: PendingDataCommand) {
        let flow_id = pending.command.flow_id();
        let queue = self.by_flow.entry(flow_id).or_default();
        if queue.is_empty() {
            self.ready_flows.push_back(flow_id);
        }
        queue.push_back(pending);
        self.len += 1;
    }

    fn retry(
        &mut self,
        engine: &mut PacketEngine,
        transport: &mut SessionPacketTransport,
    ) -> Result<()> {
        let budget = self.ready_flows.len();
        for _ in 0..budget {
            let flow_id = self
                .ready_flows
                .pop_front()
                .expect("pending data schedule must contain its budgeted flow");
            let mut pending = self
                .by_flow
                .get_mut(&flow_id)
                .and_then(VecDeque::pop_front)
                .expect("scheduled data flow must contain a command");
            match admit_prepared_packet_command(engine, transport, pending.command)? {
                Some(command) => {
                    pending.command = command;
                    self.by_flow
                        .get_mut(&flow_id)
                        .expect("blocked data flow must remain scheduled")
                        .push_front(pending);
                }
                None => {
                    self.len -= 1;
                    let _ = pending.acknowledgement.send(());
                }
            }
            let queue = self
                .by_flow
                .get(&flow_id)
                .expect("scheduled data flow must remain present until cleanup");
            if queue.is_empty() {
                self.by_flow.remove(&flow_id);
            } else {
                self.ready_flows.push_back(flow_id);
            }
        }
        Ok(())
    }
}

async fn run_packet_loop<R, W>(
    mut reader: R,
    mut writer: W,
    mut engine: PacketEngine,
    mut transport: SessionPacketTransport,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let started = tokio::time::Instant::now();
    let mut ingress_buffer = vec![0_u8; u16::MAX as usize];
    let mut pending_ingress = None;
    let mut pending_data = PendingDataCommands::default();
    let mut diagnostic = tokio::time::interval(DIAGNOSTIC_INTERVAL);
    diagnostic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    diagnostic.tick().await;

    loop {
        if let Some(packet) = pending_ingress.take() {
            match engine.push_ingress(packet) {
                Ok(()) => {}
                Err(super::packet::IngressError::Full(packet)) => pending_ingress = Some(packet),
                Err(super::packet::IngressError::PacketTooLarge(_)) => {
                    bail!("TUN delivered a packet larger than the packet-engine limit")
                }
            }
        }
        pending_data.retry(&mut engine, &mut transport)?;

        let now = started.elapsed();
        engine
            .poll(now, &mut transport)
            .map_err(map_packet_engine_error)?;
        while let Some(packet) = engine.pop_egress() {
            write_tun_packet(&mut writer, &packet).await?;
        }

        pending_data.retry(&mut engine, &mut transport)?;
        let deadline = engine
            .next_deadline(started.elapsed())
            .map(|deadline| started + deadline)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(60));

        tokio::select! {
            biased;
            envelope = transport.lifecycle_events.recv() => {
                let envelope = envelope.context("VPN lifecycle event channel closed unexpectedly")?;
                if let Some(command) = prepare_lifecycle_event(&mut transport, envelope.event)? {
                    match admit_packet_command(&mut engine, &mut transport, command)? {
                        None => {}
                        Some(_) => bail!("VPN lifecycle command competed with bounded data capacity"),
                    }
                }
                let _ = envelope.acknowledgement.send(());
            }
            result = reader.read(&mut ingress_buffer), if pending_ingress.is_none() => {
                let size = result.context("failed to read a packet from the VPN interface")?;
                if size == 0 {
                    bail!("VPN interface closed while the session was active");
                }
                pending_ingress = Some(Bytes::copy_from_slice(&ingress_buffer[..size]));
            }
            envelope = transport.data_events.recv(), if !pending_data.is_full() => {
                let envelope = envelope.context("VPN data event channel closed unexpectedly")?;
                let flow_id = envelope.event.flow_id();
                let Some(command) = prepare_data_event(&mut transport, envelope.event)? else {
                    let _ = envelope.acknowledgement.send(());
                    continue;
                };
                let mut pending = PendingDataCommand {
                    command: PacketEngine::prepare_command(command),
                    acknowledgement: envelope.acknowledgement,
                };
                if pending_data.contains_flow(flow_id) {
                    pending_data.push(pending);
                } else {
                    match admit_prepared_packet_command(
                        &mut engine,
                        &mut transport,
                        pending.command,
                    )? {
                        Some(command) => {
                            pending.command = command;
                            pending_data.push(pending);
                        }
                        None => {
                            let _ = pending.acknowledgement.send(());
                        }
                    }
                }
            }
            result = &mut transport.dispatcher => {
                return result
                    .context("VPN transport dispatcher task failed to join")?
                    .context("VPN transport dispatcher stopped unexpectedly");
            }
            _ = transport.output_ready.notified() => {}
            _ = tokio::time::sleep_until(deadline) => {}
            _ = diagnostic.tick() => {
                let stats = engine.stats();
                debug_log(format!(
                    "VPN packets: malformed={}, unsupported={}, ingress_overflow={}, fragment_drops={}, flow_limit_drops={}, oversized_udp_drops={}, command_limit_drops={}, stale_commands={}",
                    stats.malformed_packets,
                    stats.unsupported_packets,
                    stats.ingress_overflow,
                    stats.fragment_drops,
                    stats.flow_limit_drops,
                    stats.oversized_udp_drops,
                    stats.command_limit_drops,
                    stats.stale_commands,
                ));
            }
        }
    }
}

fn prepare_lifecycle_event(
    transport: &mut SessionPacketTransport,
    event: LifecycleRuntimeEvent,
) -> Result<Option<PacketCommand>> {
    match event {
        LifecycleRuntimeEvent::TcpOpened { flow_id, credit } => {
            if let Some(credit) = credit {
                transport.install_tcp_credit(flow_id, credit)?;
            }
            Ok(Some(PacketCommand::TcpOpened { flow_id }))
        }
        LifecycleRuntimeEvent::UdpOpened { flow_id, credit } => {
            if let Some(credit) = credit {
                transport.install_udp_credit(flow_id, credit)?;
            }
            Ok(Some(PacketCommand::UdpOpened { flow_id }))
        }
        LifecycleRuntimeEvent::TcpHalfClosed(flow_id) => {
            Ok(Some(PacketCommand::TcpHalfClose { flow_id }))
        }
        LifecycleRuntimeEvent::TcpOpenFailed(flow_id) => {
            transport.finish_tcp_flow(flow_id);
            Ok(Some(PacketCommand::TcpOpenFailed { flow_id }))
        }
        LifecycleRuntimeEvent::UdpOpenFailed(flow_id) => {
            transport.finish_udp_flow(flow_id);
            Ok(Some(PacketCommand::UdpOpenFailed { flow_id }))
        }
        LifecycleRuntimeEvent::TcpStopped {
            flow_id,
            reset_operator,
        } => {
            transport.finish_tcp_flow(flow_id);
            Ok(Some(PacketCommand::TcpStopped {
                flow_id,
                reset_operator,
            }))
        }
        LifecycleRuntimeEvent::UdpStopped(flow_id) => {
            transport.finish_udp_flow(flow_id);
            Ok(Some(PacketCommand::UdpClose { flow_id }))
        }
    }
}

fn prepare_data_event(
    transport: &mut SessionPacketTransport,
    event: DataRuntimeEvent,
) -> Result<Option<PacketCommand>> {
    match event {
        DataRuntimeEvent::TcpReceived {
            flow_id,
            data,
            receive_bytes,
        } => {
            transport.note_tcp_receive(flow_id, receive_bytes)?;
            Ok(Some(PacketCommand::TcpData {
                flow_id,
                data,
                receive_bytes,
            }))
        }
        DataRuntimeEvent::UdpReceived {
            flow_id,
            data,
            receive_bytes,
        } => {
            transport.note_udp_receive(flow_id, receive_bytes)?;
            Ok(Some(PacketCommand::UdpDatagram {
                flow_id,
                data,
                receive_bytes,
            }))
        }
        DataRuntimeEvent::LocalUdpDatagram { flow_id, data } => {
            Ok(Some(PacketCommand::UdpDatagram {
                flow_id,
                data,
                receive_bytes: 0,
            }))
        }
        DataRuntimeEvent::DnsResolved {
            flow_id,
            query,
            outcome,
            transport: dns_transport,
        } => {
            if !transport.dns_flow_is_active(flow_id, dns_transport) {
                return Ok(None);
            }
            Ok(Some(transport.synthesize_dns(
                flow_id,
                query,
                outcome,
                dns_transport,
            )?))
        }
    }
}

fn admit_packet_command(
    engine: &mut PacketEngine,
    transport: &mut SessionPacketTransport,
    command: PacketCommand,
) -> Result<Option<PendingPacketCommand>> {
    admit_prepared_packet_command(engine, transport, PacketEngine::prepare_command(command))
}

fn admit_prepared_packet_command(
    engine: &mut PacketEngine,
    transport: &mut SessionPacketTransport,
    command: PendingPacketCommand,
) -> Result<Option<PendingPacketCommand>> {
    resolve_packet_command_admission(transport, engine.admit_command(command))
}

fn resolve_packet_command_admission(
    transport: &mut SessionPacketTransport,
    result: Result<(), PacketCommandError>,
) -> Result<Option<PendingPacketCommand>> {
    match result {
        Ok(()) => Ok(None),
        Err(PacketCommandError {
            kind: PacketCommandErrorKind::Full,
            command,
        }) => Ok(Some(command)),
        Err(PacketCommandError {
            kind: PacketCommandErrorKind::UnknownFlow,
            command,
        }) => {
            transport.discard_command(command.as_command())?;
            Ok(None)
        }
        Err(PacketCommandError {
            kind: PacketCommandErrorKind::DataTooLarge,
            command,
        }) => {
            transport.discard_command(command.as_command())?;
            bail!("VPN transport produced a packet-engine command larger than its negotiated limit")
        }
        Err(PacketCommandError {
            kind: PacketCommandErrorKind::InvalidReceiveCredit,
            command,
        }) => {
            transport.discard_command(command.as_command())?;
            bail!("VPN transport produced invalid receive-credit accounting")
        }
    }
}

fn map_packet_engine_error(error: PacketEngineError<NetworkError>) -> anyhow::Error {
    match error {
        PacketEngineError::TransportClosed(error) => anyhow!(error),
        PacketEngineError::ControlSchedulerExhausted => {
            anyhow!("VPN packet-engine control scheduler exhausted its bounded capacity")
        }
    }
}

async fn write_tun_packet<W>(writer: &mut W, packet: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let written = writer
        .write(packet)
        .await
        .context("failed to write a packet to the VPN interface")?;
    if written != packet.len() {
        bail!(
            "VPN interface accepted a partial packet ({written} of {} bytes)",
            packet.len()
        );
    }
    Ok(())
}

async fn run_open_dispatcher(
    session: OperatorNetworkSession,
    policy: SystemVpnPolicy,
    mut requests: mpsc::Receiver<OpenRequest>,
    events: RuntimeEventSenders,
) -> Result<()> {
    let mut flows = JoinSet::new();
    let result = 'dispatcher: loop {
        while let Some(result) = flows.try_join_next() {
            if let Err(error) = result {
                break 'dispatcher Err(anyhow!(error).context("VPN flow task panicked"));
            }
        }
        tokio::select! {
            request = requests.recv() => {
                let Some(request) = request else {
                    break 'dispatcher Ok(());
                };
                let session = session.clone();
                let policy = policy.clone();
                let events = events.clone();
                flows.spawn(async move {
                    let result = match request {
                        OpenRequest::Tcp { request, target, output } => {
                            run_network_tcp_flow(session, request, target, output, events).await
                        }
                        OpenRequest::Udp { request, target, output } => {
                            run_network_udp_flow(session, request, target, output, events).await
                        }
                        OpenRequest::DnsTcp { request, output } => {
                            run_dns_tcp_flow(session, policy, request, output, events).await
                        }
                        OpenRequest::DnsUdp { request, output } => {
                            run_dns_udp_flow(session, policy, request, output, events).await
                        }
                        OpenRequest::HealthUdp { request, output } => {
                            run_health_udp_flow(request, output, events).await
                        }
                    };
                    if let Err(error) = result {
                        debug_log(format!("VPN flow task ended with an error: {error:#}"));
                    }
                });
            }
            result = flows.join_next(), if !flows.is_empty() => {
                if let Some(Err(error)) = result {
                    break 'dispatcher Err(anyhow!(error).context("VPN flow task panicked"));
                }
            }
        }
    };
    flows.abort_all();
    while flows.join_next().await.is_some() {}
    result
}

async fn run_health_udp_flow(
    request: UdpOpenRequest,
    mut output: FlowOutputStream<UdpOutput>,
    events: RuntimeEventSenders,
) -> Result<()> {
    send_lifecycle_event(
        &events,
        LifecycleRuntimeEvent::UdpOpened {
            flow_id: request.flow_id,
            credit: None,
        },
    )
    .await?;
    while let FlowOutputEvent::Message(UdpOutput::Datagram(data)) = output.receive().await {
        send_data_event(
            &events,
            DataRuntimeEvent::LocalUdpDatagram {
                flow_id: request.flow_id,
                data: data.data.clone(),
            },
        )
        .await?;
    }
    send_lifecycle_event(&events, LifecycleRuntimeEvent::UdpStopped(request.flow_id)).await
}

async fn run_network_tcp_flow(
    session: OperatorNetworkSession,
    request: TcpOpenRequest,
    target: Result<NetworkTarget, NetworkError>,
    output: FlowOutputStream<TcpOutput>,
    events: RuntimeEventSenders,
) -> Result<()> {
    let cancellation = output.cancellation();
    let target = match target {
        Ok(target) => target,
        Err(error) => {
            debug_log(format!("rejected TCP flow {}: {error}", request.flow_id));
            send_lifecycle_event(
                &events,
                LifecycleRuntimeEvent::TcpOpenFailed(request.flow_id),
            )
            .await?;
            return Ok(());
        }
    };
    let tunnel = match tokio::select! {
        _ = cancellation.cancelled() => return Ok(()),
        result = session.connect_tcp(target) => result,
    } {
        Ok(tunnel) => tunnel,
        Err(error) => {
            debug_log(format!(
                "failed to open TCP flow {}: {error}",
                request.flow_id
            ));
            send_lifecycle_event(
                &events,
                LifecycleRuntimeEvent::TcpOpenFailed(request.flow_id),
            )
            .await?;
            return Ok(());
        }
    };
    let (sender, receiver) = tunnel.split();
    let credit = receiver.receive_credit();
    send_lifecycle_event(
        &events,
        LifecycleRuntimeEvent::TcpOpened {
            flow_id: request.flow_id,
            credit: Some(credit),
        },
    )
    .await?;
    run_network_tcp_halves(request.flow_id, sender, receiver, output, events).await
}

async fn run_network_tcp_halves(
    flow_id: FlowId,
    sender: TcpTunnelSender,
    receiver: TcpTunnelReceiver,
    output: FlowOutputStream<TcpOutput>,
    events: RuntimeEventSenders,
) -> Result<()> {
    let cancellation = output.cancellation();
    let reader_cancellation = cancellation.clone();
    let reader = async {
        let result = read_network_tcp(
            flow_id,
            receiver,
            events.clone(),
            reader_cancellation.clone(),
        )
        .await;
        if result.is_err() {
            reader_cancellation.cancel();
        }
        result
    };
    let writer_cancellation = cancellation.clone();
    let writer = async {
        let result = write_network_tcp(sender, output, writer_cancellation.clone()).await;
        if result.is_err() {
            writer_cancellation.cancel();
        }
        result
    };
    let (reader_result, writer_result) = tokio::join!(reader, writer);
    let reset_operator = reader_result.is_err() || writer_result.is_err();
    send_lifecycle_event(
        &events,
        LifecycleRuntimeEvent::TcpStopped {
            flow_id,
            reset_operator,
        },
    )
    .await?;
    match (reader_result, writer_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(reader_error), Err(writer_error)) => {
            Err(reader_error.context(format!("TCP send direction also failed: {writer_error:#}")))
        }
    }
}

async fn read_network_tcp(
    flow_id: FlowId,
    mut receiver: TcpTunnelReceiver,
    events: RuntimeEventSenders,
    cancellation: CancellationToken,
) -> Result<()> {
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            result = receiver.receive_data() => result?,
        };
        let Some(received) = received else {
            send_lifecycle_event(&events, LifecycleRuntimeEvent::TcpHalfClosed(flow_id)).await?;
            return Ok(());
        };
        send_data_event(
            &events,
            DataRuntimeEvent::TcpReceived {
                flow_id,
                data: received.data,
                receive_bytes: received.receive_bytes,
            },
        )
        .await?;
    }
}

async fn write_network_tcp(
    mut sender: TcpTunnelSender,
    mut output: FlowOutputStream<TcpOutput>,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut half_closed = false;
    loop {
        let message = match output.receive().await {
            FlowOutputEvent::Aborted => {
                sender.cancel();
                return Ok(());
            }
            FlowOutputEvent::Closed => {
                sender.cancel();
                bail!("TCP flow output control closed without a terminal signal");
            }
            FlowOutputEvent::Message(message) => message,
        };
        match message {
            TcpOutput::Data(data) if !half_closed => {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        sender.cancel();
                        return Ok(());
                    }
                    result = sender.write_all(&data.data) => {
                        result.context("failed to send TCP data into the network session")?;
                    }
                }
            }
            TcpOutput::Data(_) => bail!("packet engine sent TCP data after a half-close"),
            TcpOutput::HalfClose if !half_closed => {
                sender
                    .shutdown()
                    .await
                    .context("failed to half-close the network-session TCP stream")?;
                half_closed = true;
            }
            TcpOutput::HalfClose => {}
            TcpOutput::Close => {
                if !half_closed {
                    sender
                        .shutdown()
                        .await
                        .context("failed to close the network-session TCP stream")?;
                }
                cancellation.cancel();
                return Ok(());
            }
        }
    }
}

async fn run_network_udp_flow(
    session: OperatorNetworkSession,
    request: UdpOpenRequest,
    target: Result<NetworkTarget, NetworkError>,
    output: FlowOutputStream<UdpOutput>,
    events: RuntimeEventSenders,
) -> Result<()> {
    let cancellation = output.cancellation();
    let target = match target {
        Ok(target) => target,
        Err(error) => {
            debug_log(format!("rejected UDP flow {}: {error}", request.flow_id));
            send_lifecycle_event(
                &events,
                LifecycleRuntimeEvent::UdpOpenFailed(request.flow_id),
            )
            .await?;
            return Ok(());
        }
    };
    let tunnel = match tokio::select! {
        _ = cancellation.cancelled() => return Ok(()),
        result = session.open_udp(target) => result,
    } {
        Ok(tunnel) => tunnel,
        Err(error) => {
            debug_log(format!(
                "failed to open UDP flow {}: {error}",
                request.flow_id
            ));
            send_lifecycle_event(
                &events,
                LifecycleRuntimeEvent::UdpOpenFailed(request.flow_id),
            )
            .await?;
            return Ok(());
        }
    };
    let (sender, receiver) = tunnel.split();
    let credit = receiver.receive_credit();
    send_lifecycle_event(
        &events,
        LifecycleRuntimeEvent::UdpOpened {
            flow_id: request.flow_id,
            credit: Some(credit),
        },
    )
    .await?;
    run_network_udp_halves(request.flow_id, sender, receiver, output, events).await
}

async fn run_network_udp_halves(
    flow_id: FlowId,
    sender: UdpTunnelSender,
    receiver: UdpTunnelReceiver,
    output: FlowOutputStream<UdpOutput>,
    events: RuntimeEventSenders,
) -> Result<()> {
    let cancellation = output.cancellation();
    let reader_cancellation = cancellation.clone();
    let reader = async {
        let result = read_network_udp(
            flow_id,
            receiver,
            events.clone(),
            reader_cancellation.clone(),
        )
        .await;
        reader_cancellation.cancel();
        result
    };
    let writer_cancellation = cancellation.clone();
    let writer = async {
        let result = write_network_udp(sender, output, writer_cancellation.clone()).await;
        writer_cancellation.cancel();
        result
    };
    let (reader_result, writer_result) = tokio::join!(reader, writer);
    send_lifecycle_event(&events, LifecycleRuntimeEvent::UdpStopped(flow_id)).await?;
    match (reader_result, writer_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(reader_error), Err(writer_error)) => {
            Err(reader_error.context(format!("UDP send direction also failed: {writer_error:#}")))
        }
    }
}

async fn read_network_udp(
    flow_id: FlowId,
    mut receiver: UdpTunnelReceiver,
    events: RuntimeEventSenders,
    cancellation: CancellationToken,
) -> Result<()> {
    loop {
        let received = tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            result = receiver.receive_datagram() => result?,
        };
        let Some(received) = received else {
            cancellation.cancel();
            return Ok(());
        };
        send_data_event(
            &events,
            DataRuntimeEvent::UdpReceived {
                flow_id,
                data: received.data,
                receive_bytes: received.wire_bytes,
            },
        )
        .await?;
    }
}

async fn write_network_udp(
    mut sender: UdpTunnelSender,
    mut output: FlowOutputStream<UdpOutput>,
    cancellation: CancellationToken,
) -> Result<()> {
    loop {
        let message = match output.receive().await {
            FlowOutputEvent::Aborted => {
                sender.cancel();
                return Ok(());
            }
            FlowOutputEvent::Closed => {
                sender.cancel();
                bail!("UDP flow output control closed without a terminal signal");
            }
            FlowOutputEvent::Message(message) => message,
        };
        match message {
            UdpOutput::Datagram(data) => {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        sender.cancel();
                        return Ok(());
                    }
                    result = sender.send_datagram(data.data.clone()) => {
                        result.context("failed to send a UDP datagram into the network session")?;
                    }
                }
            }
        }
    }
}

async fn send_runtime_event<E>(
    events: &mpsc::Sender<RuntimeEventEnvelope<E>>,
    event: E,
) -> Result<()> {
    let (acknowledgement, acknowledged) = oneshot::channel();
    events
        .send(RuntimeEventEnvelope {
            event,
            acknowledgement,
        })
        .await
        .map_err(|_| anyhow!("VPN packet runtime stopped"))?;
    acknowledged
        .await
        .map_err(|_| anyhow!("VPN packet runtime stopped before acknowledging an event"))
}

async fn send_lifecycle_event(
    events: &RuntimeEventSenders,
    event: LifecycleRuntimeEvent,
) -> Result<()> {
    send_runtime_event(&events.lifecycle, event).await
}

async fn send_data_event(events: &RuntimeEventSenders, event: DataRuntimeEvent) -> Result<()> {
    send_runtime_event(&events.data, event).await
}

async fn run_dns_udp_flow(
    session: OperatorNetworkSession,
    policy: SystemVpnPolicy,
    request: UdpOpenRequest,
    mut output: FlowOutputStream<UdpOutput>,
    events: RuntimeEventSenders,
) -> Result<()> {
    send_lifecycle_event(
        &events,
        LifecycleRuntimeEvent::UdpOpened {
            flow_id: request.flow_id,
            credit: None,
        },
    )
    .await?;
    let result: Result<()> = async {
        let permits = Arc::new(Semaphore::new(MAX_DNS_QUERIES_PER_FLOW));
        let mut queries = JoinSet::new();
        loop {
            match output.receive().await {
                FlowOutputEvent::Message(UdpOutput::Datagram(data)) => {
                    let query = match DnsQuery::parse_udp(&data.data) {
                        Ok(query) => query,
                        Err(error) => {
                            debug_log(format!("discarded malformed UDP DNS query: {error}"));
                            continue;
                        }
                    };
                    if !dns_query_allowed(&policy, &query) {
                        emit_dns_refused(request.flow_id, query, DnsTransport::Udp, &events)
                            .await?;
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        emit_dns_failure(request.flow_id, query, DnsTransport::Udp, &events)
                            .await?;
                        continue;
                    };
                    let session = session.clone();
                    let events = events.clone();
                    queries.spawn(async move {
                        let _permit = permit;
                        resolve_dns_query(
                            session,
                            request.flow_id,
                            query,
                            DnsTransport::Udp,
                            events,
                        )
                        .await
                    });
                }
                FlowOutputEvent::Aborted | FlowOutputEvent::Closed => break,
            }
            while let Some(result) = queries.try_join_next() {
                result.context("UDP DNS resolver task panicked")??;
            }
        }
        queries.abort_all();
        while queries.join_next().await.is_some() {}
        Ok(())
    }
    .await;
    send_lifecycle_event(&events, LifecycleRuntimeEvent::UdpStopped(request.flow_id)).await?;
    result
}

async fn run_dns_tcp_flow(
    session: OperatorNetworkSession,
    policy: SystemVpnPolicy,
    request: TcpOpenRequest,
    mut output: FlowOutputStream<TcpOutput>,
    events: RuntimeEventSenders,
) -> Result<()> {
    send_lifecycle_event(
        &events,
        LifecycleRuntimeEvent::TcpOpened {
            flow_id: request.flow_id,
            credit: None,
        },
    )
    .await?;
    let cancellation = output.cancellation();
    let result: Result<()> = async {
        let permits = Arc::new(Semaphore::new(MAX_DNS_QUERIES_PER_FLOW));
        let mut queries = JoinSet::new();
        let mut buffer = BytesMut::new();
        let mut input_closed = false;
        loop {
            let message = match output.receive().await {
                FlowOutputEvent::Message(message) => message,
                FlowOutputEvent::Aborted | FlowOutputEvent::Closed => break,
            };
            match message {
                TcpOutput::Data(data) if !input_closed => {
                    if buffer.len().saturating_add(data.data.len()) > MAX_DNS_TCP_BUFFER_BYTES {
                        bail!("TCP DNS flow exceeded its bounded input buffer");
                    }
                    buffer.extend_from_slice(&data.data);
                    while let Some(frame) = take_dns_tcp_frame(&mut buffer)? {
                        let query = match DnsQuery::parse_tcp_frame(&frame) {
                            Ok(query) => query,
                            Err(error) => {
                                debug_log(format!("discarded malformed TCP DNS query: {error}"));
                                continue;
                            }
                        };
                        if !dns_query_allowed(&policy, &query) {
                            emit_dns_refused(request.flow_id, query, DnsTransport::Tcp, &events)
                                .await?;
                            continue;
                        }
                        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                            emit_dns_failure(request.flow_id, query, DnsTransport::Tcp, &events)
                                .await?;
                            continue;
                        };
                        let session = session.clone();
                        let events = events.clone();
                        queries.spawn(async move {
                            let _permit = permit;
                            resolve_dns_query(
                                session,
                                request.flow_id,
                                query,
                                DnsTransport::Tcp,
                                events,
                            )
                            .await
                        });
                    }
                }
                TcpOutput::Data(_) => bail!("TCP DNS flow received data after a half-close"),
                TcpOutput::HalfClose => {
                    input_closed = true;
                    if !buffer.is_empty() {
                        bail!("TCP DNS flow ended in the middle of a framed query");
                    }
                    loop {
                        tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => {
                                queries.abort_all();
                                while queries.join_next().await.is_some() {}
                                return Ok(());
                            }
                            result = queries.join_next(), if !queries.is_empty() => {
                                let Some(result) = result else {
                                    break;
                                };
                                result.context("TCP DNS resolver task panicked")??;
                            }
                            else => break,
                        }
                    }
                    send_lifecycle_event(
                        &events,
                        LifecycleRuntimeEvent::TcpHalfClosed(request.flow_id),
                    )
                    .await?;
                }
                TcpOutput::Close => break,
            }
            while let Some(result) = queries.try_join_next() {
                result.context("TCP DNS resolver task panicked")??;
            }
        }
        queries.abort_all();
        while queries.join_next().await.is_some() {}
        Ok(())
    }
    .await;
    send_lifecycle_event(
        &events,
        LifecycleRuntimeEvent::TcpStopped {
            flow_id: request.flow_id,
            reset_operator: result.is_err(),
        },
    )
    .await?;
    result
}

fn take_dns_tcp_frame(buffer: &mut BytesMut) -> Result<Option<Bytes>> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let message_len = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
    let frame_len = message_len
        .checked_add(2)
        .context("TCP DNS frame length overflowed")?;
    if frame_len > MAX_DNS_TCP_BUFFER_BYTES {
        bail!("TCP DNS query exceeds the supported frame size");
    }
    if buffer.len() < frame_len {
        return Ok(None);
    }
    Ok(Some(buffer.split_to(frame_len).freeze()))
}

async fn resolve_dns_query(
    session: OperatorNetworkSession,
    flow_id: FlowId,
    query: DnsQuery,
    transport: DnsTransport,
    events: RuntimeEventSenders,
) -> Result<()> {
    let request = ResolveRequest::new(
        query.question().name().to_ascii()?,
        query.question().record_type().to_u16(),
        query.question().record_class().to_u16(),
        DNS_TIMEOUT_MILLIS,
    )?;
    let outcome = match session.resolve(request).await {
        Ok(outcome) => outcome,
        Err(error) => {
            debug_log(format!("client-side DNS resolution failed: {error}"));
            ResolveOutcome::Failure { response_code: 2 }
        }
    };
    send_data_event(
        &events,
        DataRuntimeEvent::DnsResolved {
            flow_id,
            query,
            outcome,
            transport,
        },
    )
    .await
}

async fn emit_dns_failure(
    flow_id: FlowId,
    query: DnsQuery,
    transport: DnsTransport,
    events: &RuntimeEventSenders,
) -> Result<()> {
    send_data_event(
        events,
        DataRuntimeEvent::DnsResolved {
            flow_id,
            query,
            outcome: ResolveOutcome::Failure { response_code: 2 },
            transport,
        },
    )
    .await
}

fn dns_query_allowed(policy: &SystemVpnPolicy, query: &DnsQuery) -> bool {
    policy.is_full_tunnel() || policy.matches_dns_name(query.question().name())
}

async fn emit_dns_refused(
    flow_id: FlowId,
    query: DnsQuery,
    transport: DnsTransport,
    events: &RuntimeEventSenders,
) -> Result<()> {
    send_data_event(
        events,
        DataRuntimeEvent::DnsResolved {
            flow_id,
            query,
            outcome: ResolveOutcome::Failure { response_code: 5 },
            transport,
        },
    )
    .await
}

fn dns_resolution(outcome: ResolveOutcome) -> Result<Resolution> {
    match outcome {
        ResolveOutcome::Positive { answer_ttl } => Ok(Resolution::Positive {
            synthetic_ttl: answer_ttl,
        }),
        ResolveOutcome::NoData => Ok(Resolution::NoData),
        ResolveOutcome::Failure { response_code } => Ok(Resolution::Failure(
            ResponseCode::from_u8(response_code).unwrap_or(ResponseCode::SERVER_FAILURE),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::BytesMut;
    use ipnet::{Ipv4Net, Ipv6Net};
    use tokio::sync::{Notify, Semaphore, mpsc};
    use tokio_util::task::AbortOnDropHandle;

    use super::{
        BufferedBytes, CreditEntry, DataRuntimeEvent, DnsQuery, DnsTransport, FLOW_OUTPUT_MESSAGES,
        FlowOutputEvent, FlowOutputHandle, LifecycleRuntimeEvent, NetworkError, NetworkErrorKind,
        PacketCommand, ReceiveCredit, Resolution, ResolutionFamily, ResolveOutcome,
        RuntimeEventSenders, SyntheticAddressMap, SyntheticNetworkConfiguration, SystemVpnPolicy,
        TcpFlowOutput, TcpOutput, TransportSendError, UdpOutput, VpnRuntime, dns_query_allowed,
        emit_dns_refused, flow_output, network_target_for, run_health_udp_flow,
        synthesize_dns_command, take_dns_tcp_frame,
    };
    use crate::vpn::dns::{DnsName, Ipv4Pool, Ipv6Pool};
    use crate::vpn::packet::{FlowId, UdpOpenRequest};

    #[derive(Clone)]
    struct TestCredit {
        released: Arc<AtomicUsize>,
        remaining: usize,
    }

    impl ReceiveCredit for TestCredit {
        fn release_capacity(&mut self, bytes: usize) -> Result<(), NetworkError> {
            if bytes > self.remaining {
                return Err(NetworkError::new(
                    NetworkErrorKind::Protocol,
                    "test receive-credit over-release",
                ));
            }
            self.remaining -= bytes;
            self.released.fetch_add(bytes, Ordering::SeqCst);
            Ok(())
        }
    }

    fn dns_query(id: u16, name: &str, record_type: u16) -> DnsQuery {
        let mut message = Vec::new();
        message.extend_from_slice(&id.to_be_bytes());
        message.extend_from_slice(&0x0100_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        for label in name.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        DnsQuery::parse_udp(&message).unwrap()
    }

    fn synthetic_configuration() -> SyntheticNetworkConfiguration {
        SyntheticNetworkConfiguration {
            ipv4: Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 16),
            ipv4_dns: Ipv4Addr::new(198, 18, 0, 1),
            ipv4_first: Ipv4Addr::new(198, 18, 0, 2),
            ipv4_last: Ipv4Addr::new(198, 18, 255, 254),
            ipv6: Ipv6Net::new_assert("fd00:1234::".parse().unwrap(), 96),
            ipv6_dns: "fd00:1234::1".parse().unwrap(),
            ipv6_first: "fd00:1234::2".parse().unwrap(),
            ipv6_last: "fd00:1234::ffff:ffff".parse().unwrap(),
        }
    }

    fn synthetic_mappings(configuration: SyntheticNetworkConfiguration) -> SyntheticAddressMap {
        SyntheticAddressMap::new(
            Some(
                Ipv4Pool::new(configuration.ipv4_first, configuration.ipv4_last, 128, []).unwrap(),
            ),
            Some(
                Ipv6Pool::new(configuration.ipv6_first, configuration.ipv6_last, 128, []).unwrap(),
            ),
        )
    }

    #[test]
    fn receive_credit_survives_reader_close_until_every_admitted_byte_is_released() {
        let released = Arc::new(AtomicUsize::new(0));
        let mut entry = CreditEntry {
            credit: TestCredit {
                released: Arc::clone(&released),
                remaining: 23,
            },
            outstanding: 0,
            reader_closed: false,
        };

        entry.note_receive(23).unwrap();
        assert!(!entry.close_reader());
        entry.release(7).unwrap();
        assert!(!entry.is_finished());
        entry.release(16).unwrap();

        assert!(entry.is_finished());
        assert_eq!(released.load(Ordering::SeqCst), 23);
        assert!(entry.release(1).is_err());
    }

    #[tokio::test]
    async fn abort_bypasses_a_full_flow_queue_and_closed_queues_terminate() {
        let output_ready = Arc::new(Notify::new());
        let (handle, mut output) = FlowOutputHandle::new(Arc::clone(&output_ready));
        for byte in 0..FLOW_OUTPUT_MESSAGES {
            handle.messages.try_send(byte).unwrap();
        }
        assert!(handle.messages.try_send(255).is_err());

        handle.abort();
        assert!(matches!(output.receive().await, FlowOutputEvent::Aborted));

        let (handle, mut output) = FlowOutputHandle::<u8>::new(output_ready);
        drop(handle);
        assert!(matches!(output.receive().await, FlowOutputEvent::Closed));
    }

    #[test]
    fn absent_flow_output_is_terminal_instead_of_retryable_backpressure() {
        let outputs = HashMap::<FlowId, TcpFlowOutput>::new();
        assert!(matches!(
            flow_output(&outputs, FlowId::from_test_value(91)),
            Err(TransportSendError::FlowClosed)
        ));
    }

    #[tokio::test]
    async fn tcp_output_owner_remains_draining_behind_queued_data() {
        let output_ready = Arc::new(Notify::new());
        let (handle, stream) = FlowOutputHandle::new(Arc::clone(&output_ready));
        let permit = Arc::new(Semaphore::new(4))
            .try_acquire_many_owned(4)
            .unwrap();
        assert!(
            handle
                .messages
                .try_send(TcpOutput::Data(BufferedBytes::new(
                    bytes::Bytes::from_static(b"data"),
                    permit,
                    output_ready,
                )))
                .is_ok()
        );
        let flow_id = FlowId::from_test_value(92);
        let mut outputs = HashMap::from([(flow_id, TcpFlowOutput::new(handle))]);

        outputs.get_mut(&flow_id).unwrap().begin_draining().unwrap();

        let output = outputs.get(&flow_id).unwrap();
        assert!(output.draining);
        assert!(matches!(
            output.active_handle(),
            Err(TransportSendError::FlowClosed)
        ));
        assert_eq!(stream.messages.len(), 2);
        assert_eq!(outputs.len(), 1);
    }

    #[tokio::test]
    async fn releasing_buffered_bytes_wakes_aggregate_backpressure() {
        let bytes = Arc::new(Semaphore::new(1));
        let output_ready = Arc::new(Notify::new());
        let permit = Arc::clone(&bytes).try_acquire_owned().unwrap();
        let buffered = BufferedBytes::new(
            bytes::Bytes::from_static(b"x"),
            permit,
            Arc::clone(&output_ready),
        );
        assert_eq!(bytes.available_permits(), 0);

        drop(buffered);
        output_ready.notified().await;

        assert_eq!(bytes.available_permits(), 1);
    }

    #[tokio::test]
    async fn completed_runtime_shutdown_does_not_repoll_its_join_handle() {
        let mut runtime = VpnRuntime {
            task: Some(AbortOnDropHandle::new(tokio::spawn(async { Ok(()) }))),
        };

        runtime.wait().await.unwrap();
        runtime.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn health_echo_emits_uncredited_local_datagrams() {
        let flow_id = FlowId::from_test_value(93);
        let request = UdpOpenRequest {
            flow_id,
            operator: "192.0.2.2:49153".parse().unwrap(),
            target: "192.0.2.1:49152".parse().unwrap(),
        };
        let (lifecycle, mut lifecycle_events) = mpsc::channel(2);
        let (data, mut data_events) = mpsc::channel(1);
        let events = RuntimeEventSenders { lifecycle, data };
        let output_ready = Arc::new(Notify::new());
        let (handle, output) = FlowOutputHandle::new(Arc::clone(&output_ready));
        let task = tokio::spawn(run_health_udp_flow(request, output, events));

        let opened = lifecycle_events.recv().await.unwrap();
        assert!(matches!(
            opened.event,
            LifecycleRuntimeEvent::UdpOpened {
                flow_id: opened_flow,
                credit: None,
            } if opened_flow == flow_id
        ));
        let _ = opened.acknowledgement.send(());

        let payload = bytes::Bytes::from_static(b"health");
        let permit = Arc::new(Semaphore::new(payload.len()))
            .try_acquire_many_owned(payload.len() as u32)
            .unwrap();
        handle
            .messages
            .send(UdpOutput::Datagram(BufferedBytes::new(
                payload.clone(),
                permit,
                output_ready,
            )))
            .await
            .unwrap();
        let echoed = data_events.recv().await.unwrap();
        assert!(matches!(
            echoed.event,
            DataRuntimeEvent::LocalUdpDatagram {
                flow_id: echoed_flow,
                data,
            } if echoed_flow == flow_id && data == payload
        ));
        let _ = echoed.acknowledgement.send(());

        handle.abort();
        let stopped = lifecycle_events.recv().await.unwrap();
        assert!(matches!(
            stopped.event,
            LifecycleRuntimeEvent::UdpStopped(stopped_flow) if stopped_flow == flow_id
        ));
        let _ = stopped.acknowledgement.send(());
        task.await.unwrap().unwrap();
    }

    #[test]
    fn synthetic_hostname_reversal_preserves_the_original_address_family() {
        let configuration = synthetic_configuration();
        let mut mappings = synthetic_mappings(configuration);
        let hostname = DnsName::from_ascii("jira.elevancehealth.com").unwrap();
        let ipv4 = mappings.get_or_allocate_ipv4(&hostname).unwrap();
        let ipv6 = mappings.get_or_allocate_ipv6(&hostname).unwrap();

        for target in [
            (
                SocketAddr::new(IpAddr::V4(ipv4), 443),
                ResolutionFamily::Ipv4,
            ),
            (
                SocketAddr::new(IpAddr::V6(ipv6), 8443),
                ResolutionFamily::Ipv6,
            ),
        ] {
            let reversed = network_target_for(&mappings, Some(configuration), target.0).unwrap();
            assert_eq!(reversed.host, "jira.elevancehealth.com");
            assert_eq!(reversed.port, target.0.port());
            assert_eq!(reversed.resolution_family, target.1);
        }

        let unmapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 99)), 443);
        assert_eq!(
            network_target_for(&mappings, Some(configuration), unmapped)
                .unwrap_err()
                .kind,
            NetworkErrorKind::HostUnreachable
        );
        let direct = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 53);
        let direct_target = network_target_for(&mappings, Some(configuration), direct).unwrap();
        assert_eq!(direct_target.host, "192.0.2.9");
        assert_eq!(direct_target.port, 53);
        assert_eq!(direct_target.resolution_family, ResolutionFamily::Any);
    }

    #[test]
    fn local_dns_commands_never_claim_h2_receive_credit() {
        let query_id = 0x4a31;
        let query = dns_query(query_id, "jira.elevancehealth.com", 1);
        let flow_id = FlowId::from_test_value(9);

        for transport in [DnsTransport::Tcp, DnsTransport::Udp] {
            let mut mappings = SyntheticAddressMap::new(None, None);
            let command = synthesize_dns_command(
                flow_id,
                query.clone(),
                ResolveOutcome::Failure { response_code: 5 },
                transport,
                &mut mappings,
            )
            .unwrap();
            let (data, receive_bytes, message_offset) = match command {
                PacketCommand::TcpData {
                    data,
                    receive_bytes,
                    ..
                } => (data, receive_bytes, 2),
                PacketCommand::UdpDatagram {
                    data,
                    receive_bytes,
                    ..
                } => (data, receive_bytes, 0),
                _ => panic!("DNS synthesis produced a non-data packet command"),
            };
            assert_eq!(receive_bytes, 0);
            assert_eq!(
                u16::from_be_bytes([data[message_offset], data[message_offset + 1]]),
                query_id
            );
            assert_eq!(data[message_offset + 3] & 0x0f, 5);
        }
    }

    #[test]
    fn positive_a_and_aaaa_use_both_dns_transports_with_family_fidelity() {
        let configuration = synthetic_configuration();
        let hostname = DnsName::from_ascii("jira.elevancehealth.com").unwrap();
        let flow_id = FlowId::from_test_value(10);

        for (record_type, synthetic_address, resolution_family) in [
            (
                1,
                IpAddr::V4(configuration.ipv4_first),
                ResolutionFamily::Ipv4,
            ),
            (
                28,
                IpAddr::V6(configuration.ipv6_first),
                ResolutionFamily::Ipv6,
            ),
        ] {
            let query_id = 0x5a00 + record_type;
            let query = dns_query(query_id, "jira.elevancehealth.com", record_type);
            for transport in [DnsTransport::Tcp, DnsTransport::Udp] {
                let mut mappings = synthetic_mappings(configuration);
                let command = synthesize_dns_command(
                    flow_id,
                    query.clone(),
                    ResolveOutcome::Positive { answer_ttl: 30 },
                    transport,
                    &mut mappings,
                )
                .unwrap();
                let (data, message_offset) = match (transport, command) {
                    (
                        DnsTransport::Tcp,
                        PacketCommand::TcpData {
                            data,
                            receive_bytes: 0,
                            ..
                        },
                    ) => {
                        assert_eq!(
                            usize::from(u16::from_be_bytes([data[0], data[1]])),
                            data.len() - 2
                        );
                        (data, 2)
                    }
                    (
                        DnsTransport::Udp,
                        PacketCommand::UdpDatagram {
                            data,
                            receive_bytes: 0,
                            ..
                        },
                    ) => (data, 0),
                    _ => panic!("DNS synthesis produced the wrong packet command"),
                };
                assert_eq!(
                    u16::from_be_bytes([data[message_offset], data[message_offset + 1]]),
                    query_id
                );
                assert_eq!(
                    u16::from_be_bytes([data[message_offset + 6], data[message_offset + 7]]),
                    1
                );
                assert_eq!(
                    mappings.name_for_address(synthetic_address),
                    Some(&hostname)
                );

                let target = network_target_for(
                    &mappings,
                    Some(configuration),
                    SocketAddr::new(synthetic_address, 443),
                )
                .unwrap();
                assert_eq!(target.host, "jira.elevancehealth.com");
                assert_eq!(target.resolution_family, resolution_family);
            }
        }
    }

    #[tokio::test]
    async fn scoped_dns_policy_rejects_misses_without_waiting_for_resolution() {
        let policy =
            SystemVpnPolicy::new(Vec::new(), vec!["elevancehealth.com".to_string()]).unwrap();
        let allowed = dns_query(1, "jira.elevancehealth.com", 1);
        let disallowed = dns_query(2, "public.example", 1);
        assert!(dns_query_allowed(&policy, &allowed));
        assert!(!dns_query_allowed(&policy, &disallowed));

        let flow_id = FlowId::from_test_value(11);
        let (lifecycle, _lifecycle_events) = mpsc::channel(1);
        let (data, mut received) = mpsc::channel(1);
        let events = RuntimeEventSenders { lifecycle, data };
        let emission = tokio::spawn(async move {
            emit_dns_refused(flow_id, disallowed, DnsTransport::Udp, &events).await
        });
        let envelope = received.recv().await.unwrap();
        match envelope.event {
            DataRuntimeEvent::DnsResolved {
                flow_id: actual_flow_id,
                outcome: ResolveOutcome::Failure { response_code },
                transport: DnsTransport::Udp,
                ..
            } => {
                assert_eq!(actual_flow_id, flow_id);
                assert_eq!(response_code, 5);
            }
            _ => panic!("policy miss did not emit a UDP REFUSED response"),
        }
        let _ = envelope.acknowledgement.send(());
        emission.await.unwrap().unwrap();
    }

    #[test]
    fn tcp_dns_framing_preserves_pipelined_query_boundaries() {
        let first = dns_query(21, "first.example", 1);
        let second = dns_query(22, "second.example", 28);
        let mut bytes = BytesMut::new();
        for query in [first, second] {
            let response = super::synthesize_response(
                &query,
                Resolution::Failure(super::ResponseCode::SERVER_FAILURE),
                &mut SyntheticAddressMap::new(None, None),
            )
            .unwrap()
            .to_tcp()
            .unwrap();
            bytes.extend_from_slice(&response);
        }
        let first_frame = take_dns_tcp_frame(&mut bytes).unwrap().unwrap();
        let second_frame = take_dns_tcp_frame(&mut bytes).unwrap().unwrap();
        assert_eq!(u16::from_be_bytes([first_frame[2], first_frame[3]]), 21);
        assert_eq!(u16::from_be_bytes([second_frame[2], second_frame[3]]), 22);
        assert!(take_dns_tcp_frame(&mut bytes).unwrap().is_none());
        assert!(bytes.is_empty());
    }
}
