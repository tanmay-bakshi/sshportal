use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

use crate::network::client_resolver::{ClientResolver, MAX_RESOLVED_ADDRESSES};
use crate::network::protocol::{NetworkError, NetworkErrorKind, NetworkTarget};

const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const TCP_CONNECT_WINDOW: Duration = CONNECT_TIMEOUT
    .saturating_add(HAPPY_EYEBALLS_DELAY.saturating_mul(MAX_RESOLVED_ADDRESSES as u32));
pub(super) const TCP_DIAL_BUDGET: Duration = RESOLUTION_TIMEOUT.saturating_add(TCP_CONNECT_WINDOW);

pub(super) struct ConnectedUdpSocket {
    pub(super) socket: UdpSocket,
    pub(super) peer: SocketAddr,
}

async fn resolve_target(
    target: &NetworkTarget,
    resolver: &ClientResolver,
) -> Result<Vec<SocketAddr>, NetworkError> {
    tokio::time::timeout(
        RESOLUTION_TIMEOUT,
        resolver.resolve_socket_addresses(target),
    )
    .await
    .map_err(|_| {
        NetworkError::new(
            NetworkErrorKind::TimedOut,
            format!("timed out resolving {}", target.host),
        )
    })?
}

pub(crate) async fn dial_tcp(
    target: &NetworkTarget,
    resolver: &ClientResolver,
) -> Result<TcpStream, NetworkError> {
    let addresses = resolve_target(target, resolver).await?;
    let mut attempts = JoinSet::new();
    for (index, address) in addresses.into_iter().enumerate() {
        attempts.spawn(async move {
            let delay = HAPPY_EYEBALLS_DELAY.saturating_mul(index as u32);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("timed out connecting to {address}"),
                    )
                })?
                .map(|socket| (socket, address))
        });
    }

    let dial = async {
        let mut last_error = None;
        while let Some(result) = attempts.join_next().await {
            match result {
                Ok(Ok((socket, _address))) => {
                    attempts.abort_all();
                    socket.set_nodelay(true).map_err(|error| {
                        NetworkError::new(
                            NetworkErrorKind::from_io(&error),
                            format!("failed to configure TCP destination: {error}"),
                        )
                    })?;
                    return Ok(socket);
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(error) => {
                    return Err(NetworkError::new(
                        NetworkErrorKind::General,
                        format!("TCP connection attempt failed to join: {error}"),
                    ));
                }
            }
        }
        let error = last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::HostUnreachable,
                "destination resolved to no connection candidates",
            )
        });
        Err(NetworkError::new(
            NetworkErrorKind::from_io(&error),
            format!(
                "failed to connect to {}:{}: {error}",
                target.host, target.port
            ),
        ))
    };

    tokio::time::timeout(TCP_CONNECT_WINDOW, dial)
        .await
        .map_err(|_| {
            attempts.abort_all();
            NetworkError::new(
                NetworkErrorKind::TimedOut,
                format!("timed out connecting to {}:{}", target.host, target.port),
            )
        })?
}

pub(super) async fn connect_udp(
    target: &NetworkTarget,
    resolver: &ClientResolver,
) -> Result<ConnectedUdpSocket, NetworkError> {
    let addresses = resolve_target(target, resolver).await?;
    let mut last_error = None;
    for address in addresses {
        let bind_address = if address.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = match UdpSocket::bind(bind_address).await {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match socket.connect(address).await {
            Ok(()) => match socket.peer_addr() {
                Ok(peer) => return Ok(ConnectedUdpSocket { socket, peer }),
                Err(error) => last_error = Some(error),
            },
            Err(error) => last_error = Some(error),
        }
    }
    let error = last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::HostUnreachable,
            "destination resolved to no UDP candidates",
        )
    });
    Err(NetworkError::new(
        NetworkErrorKind::from_io(&error),
        format!(
            "failed to open UDP destination {}:{}: {error}",
            target.host, target.port
        ),
    ))
}
