use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU64;

/// Stable identity for one TCP or UDP flow owned by the packet engine.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct FlowId(NonZeroU64);

impl FlowId {
    #[cfg(test)]
    pub(crate) fn from_test_value(value: u64) -> Self {
        Self(NonZeroU64::new(value).expect("test flow ID must not be zero"))
    }

    pub(super) fn new(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Request to establish the client-side socket for a pending TCP flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TcpOpenRequest {
    pub(crate) flow_id: FlowId,
    pub(crate) operator: SocketAddr,
    pub(crate) target: SocketAddr,
}

/// Request to establish the client-side socket for a pending UDP flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UdpOpenRequest {
    pub(crate) flow_id: FlowId,
    pub(crate) operator: SocketAddr,
    pub(crate) target: SocketAddr,
}

/// Why the packet engine is terminating a remotely represented TCP flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TcpResetReason {
    OperatorReset,
    OpenTimedOut,
    IdleTimedOut,
}

/// Result of trying to hand work to the network session without waiting.
#[derive(Debug)]
pub(crate) enum TransportSendError<E> {
    Full,
    FlowClosed,
    Closed(E),
}

/// Non-blocking boundary between packet termination and the multiplexed session.
///
/// An implementation must retain or copy every borrowed argument before returning
/// `Ok(())`. Returning [`TransportSendError::Full`] leaves ownership with the
/// packet engine, which will retry control messages and will not consume TCP bytes.
/// [`TransportSendError::FlowClosed`] is terminal for only the named flow, while
/// [`TransportSendError::Closed`] is terminal for the complete transport. This
/// contract carries TCP receive-window backpressure all the way to the operator
/// kernel without an intermediate unbounded queue.
pub(crate) trait PacketTransport {
    type Error;

    fn try_open_tcp(
        &mut self,
        request: &TcpOpenRequest,
    ) -> Result<(), TransportSendError<Self::Error>>;

    fn try_open_udp(
        &mut self,
        request: &UdpOpenRequest,
    ) -> Result<(), TransportSendError<Self::Error>>;

    fn try_send_tcp(
        &mut self,
        flow_id: FlowId,
        data: &[u8],
    ) -> Result<(), TransportSendError<Self::Error>>;

    fn try_half_close_tcp(
        &mut self,
        flow_id: FlowId,
    ) -> Result<(), TransportSendError<Self::Error>>;

    fn try_reset_tcp(
        &mut self,
        flow_id: FlowId,
        reason: TcpResetReason,
    ) -> Result<(), TransportSendError<Self::Error>>;

    fn try_close_tcp(&mut self, flow_id: FlowId) -> Result<(), TransportSendError<Self::Error>>;

    fn try_send_udp(
        &mut self,
        flow_id: FlowId,
        data: &[u8],
    ) -> Result<(), TransportSendError<Self::Error>>;

    /// Returns HTTP/2 receive capacity after bytes enter the TCP send buffer.
    /// Implementations must treat each accepted byte exactly once.
    fn release_tcp_receive(&mut self, flow_id: FlowId, bytes: usize) -> Result<(), Self::Error>;

    /// Returns HTTP/2 receive capacity after a complete UDP capsule has either
    /// entered the packet egress queue or been intentionally discarded.
    fn release_udp_receive(&mut self, flow_id: FlowId, bytes: usize) -> Result<(), Self::Error>;

    fn try_close_udp(&mut self, flow_id: FlowId) -> Result<(), TransportSendError<Self::Error>>;
}
