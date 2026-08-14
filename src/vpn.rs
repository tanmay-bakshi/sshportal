mod configuration;
mod dns;
mod packet;
mod policy;
mod routes;
mod runtime;

pub use policy::SystemVpnPolicy;

use std::net::{IpAddr, SocketAddr};

#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use anyhow::anyhow;
use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_util::task::AbortOnDropHandle;
use tun::AbstractDevice;
#[cfg(target_os = "windows")]
use wintun_security::VerifiedWintun;

use crate::network::start_operator_network_session;

pub(super) const VPN_MTU: u16 = 1_500;
const NETWORK_RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

struct TunDevice {
    device: tun::AsyncDevice,
    name: String,
    index: i32,
    #[cfg(target_os = "windows")]
    _verified_wintun: VerifiedWintun,
}

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn new() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("failed to listen for SIGINT")?,
            terminate: signal(SignalKind::terminate()).context("failed to listen for SIGTERM")?,
            hangup: signal(SignalKind::hangup()).context("failed to listen for SIGHUP")?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
            _ = self.hangup.recv() => {}
        }
    }
}

#[cfg(windows)]
struct ShutdownSignals {
    ctrl_c: tokio::signal::windows::CtrlC,
    ctrl_break: tokio::signal::windows::CtrlBreak,
}

#[cfg(windows)]
impl ShutdownSignals {
    fn new() -> Result<Self> {
        use tokio::signal::windows::{ctrl_break, ctrl_c};

        Ok(Self {
            ctrl_c: ctrl_c().context("failed to listen for Ctrl-C")?,
            ctrl_break: ctrl_break().context("failed to listen for Ctrl-Break")?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.ctrl_c.recv() => {}
            _ = self.ctrl_break.recv() => {}
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct ShutdownSignals;

#[cfg(not(any(unix, windows)))]
impl ShutdownSignals {
    fn new() -> Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn run_operator_vpn<S>(
    websocket: WebSocketStream<S>,
    transport_local: SocketAddr,
    transport_peer: SocketAddr,
    policy: SystemVpnPolicy,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let transport_peer_ip = normalize_ip(transport_peer.ip());
    validate_transport_peer(&policy, transport_peer_ip)?;
    let mut shutdown_signals = ShutdownSignals::new()?;
    let mut entropy = [0_u8; 16];
    rand::fill(&mut entropy);
    let prepared_network = routes::prepare(&policy, entropy, transport_peer_ip)
        .context("failed to prepare collision-free VPN network settings")?;
    let network = prepared_network.network_configuration();
    let (session, session_runtime) = tokio::select! {
        result = start_operator_network_session(websocket) => result?,
        _ = shutdown_signals.recv() => return Ok(()),
    };
    let tun = create_tun_device(network).context(
        "failed to create the VPN interface; run sshportal-server with administrator/root privileges",
    )?;
    let mut network_guard = prepared_network
        .install(&tun.name, tun.index, transport_local, transport_peer)
        .with_context(|| {
            format!(
                "failed to configure VPN routes on interface {}; administrator/root privileges are required",
                tun.name
            )
        })?;
    let (tun_writer, tun_reader) = tun
        .device
        .split()
        .context("failed to split the VPN interface for asynchronous I/O")?;
    let mut packet_runtime =
        runtime::VpnRuntime::start(tun_reader, tun_writer, session, network, policy.clone())?;
    let mut session_runtime = AbortOnDropHandle::new(tokio::spawn(session_runtime.wait()));
    let mut network_reconcile = tokio::time::interval(NETWORK_RECONCILE_INTERVAL);
    network_reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    network_reconcile.tick().await;

    if policy.is_full_tunnel() {
        println!("full-tunnel VPN active on interface {}", tun.name);
    } else {
        println!("selective VPN active on interface {}", tun.name);
    }
    println!("press Ctrl-C to disconnect and restore the original routes");

    let mut session_runtime_finished = false;
    let operation_result = loop {
        tokio::select! {
            result = packet_runtime.wait() => break result,
            result = &mut session_runtime => {
                session_runtime_finished = true;
                break result
                    .context("VPN network session task failed to join")
                    .and_then(|result| result);
            }
            _ = network_reconcile.tick() => {
                if let Err(error) = network_guard.reconcile() {
                    break Err(error).context(
                        "failed to reconcile VPN network settings after a host network change",
                    );
                }
            }
            _ = shutdown_signals.recv() => break Ok(()),
        }
    };
    let packet_shutdown_result = packet_runtime.shutdown().await;
    let session_shutdown_result = if session_runtime_finished {
        Ok(())
    } else {
        session_runtime.abort();
        match session_runtime.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error).context("VPN network session task failed to join"),
        }
    };
    let restore_result = network_guard.restore();

    combine_results(
        combine_results(
            combine_results(
                operation_result,
                packet_shutdown_result,
                "VPN packet runtime shutdown also failed",
            ),
            session_shutdown_result,
            "VPN network session shutdown also failed",
        ),
        restore_result,
        "VPN host-network restoration also failed",
    )
}

fn combine_results(primary: Result<()>, secondary: Result<()>, context: &str) -> Result<()> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error).context(context.to_string()),
        (Err(primary), Err(secondary)) => Err(primary).context(format!("{context}: {secondary:#}")),
    }
}

fn create_tun_device(network: configuration::VpnNetworkConfiguration) -> Result<TunDevice> {
    let mut configuration = tun::Configuration::default();
    configuration
        .address(network.interface_ipv4)
        .destination(network.gateway_ipv4)
        .netmask(network.point_to_point_ipv4.netmask())
        .mtu(VPN_MTU)
        .up();

    #[cfg(target_os = "macos")]
    configuration.platform_config(|platform| {
        platform.packet_information(false);
    });

    #[cfg(target_os = "windows")]
    let verified_wintun = {
        configuration.tun_name("sshportal");
        let bundled_wintun = wintun_path()?;
        let verified_wintun = VerifiedWintun::prepare(&bundled_wintun)
            .context("failed to stage and verify the bundled Wintun DLL")?;
        configuration.platform_config(|platform| {
            platform.device_guid(0x8973_6870_6f72_7461_6c00_0000_0000_0001);
            platform.wintun_file(verified_wintun.path());
        });
        verified_wintun
    };

    let device = tun::create_as_async(&configuration).context("TUN device creation failed")?;
    let name = device
        .tun_name()
        .context("failed to read TUN interface name")?;
    let index = device
        .tun_index()
        .context("failed to read TUN interface index")?;
    Ok(TunDevice {
        device,
        name,
        index,
        #[cfg(target_os = "windows")]
        _verified_wintun: verified_wintun,
    })
}

#[cfg(target_os = "windows")]
fn wintun_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("failed to locate sshportal-server.exe")?;
    let directory = executable
        .parent()
        .context("sshportal-server.exe has no parent directory")?;
    let path = directory.join("wintun.dll");
    if !path.is_file() {
        return Err(anyhow!(
            "{} is missing; place the signed Wintun DLL beside sshportal-server.exe",
            path.display()
        ));
    }
    Ok(path)
}

fn validate_transport_peer(policy: &SystemVpnPolicy, peer: IpAddr) -> Result<()> {
    if policy.contains_exact_ip(peer) {
        bail!(
            "VPN include CIDR selects the WebSocket transport peer {peer} exactly; use a broader CIDR or remove that host selector so SSHPortal can keep its control connection on the physical network"
        );
    }
    Ok(())
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

#[cfg(test)]
mod tests {
    use super::{SystemVpnPolicy, validate_transport_peer};

    #[test]
    fn exact_transport_peer_selector_is_rejected() {
        let policy =
            SystemVpnPolicy::new(vec!["203.0.113.8/32".parse().unwrap()], Vec::new()).unwrap();

        assert!(validate_transport_peer(&policy, "203.0.113.8".parse().unwrap()).is_err());
    }

    #[test]
    fn broader_transport_peer_selector_is_safe() {
        let policy =
            SystemVpnPolicy::new(vec!["203.0.113.0/24".parse().unwrap()], Vec::new()).unwrap();

        validate_transport_peer(&policy, "203.0.113.8".parse().unwrap()).unwrap();
    }
}
