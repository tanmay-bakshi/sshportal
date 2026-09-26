mod client_resolver;
mod egress;
mod policy;
mod protocol;
mod resolver_protocol;
mod resolver_session;
mod session;
mod socks_frontend;

pub(crate) use protocol::{NetworkError, NetworkErrorKind, NetworkTarget, ResolutionFamily};
pub(crate) use resolver_protocol::{ResolveOutcome, ResolveRequest};
pub use session::run_client_network_session as run_client_network_proxy;
pub(crate) use session::{
    OperatorNetworkSession, TCP_DESTINATION_OPEN_TIMEOUT, TcpReceiveCredit, TcpTunnelReceiver,
    TcpTunnelSender, UdpReceiveCredit, UdpTunnelReceiver, UdpTunnelSender,
    start_operator_network_session,
};
pub use socks_frontend::run_operator_socks_proxy;
