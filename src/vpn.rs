mod policy;
mod routes;

pub use policy::SystemVpnPolicy;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::net::Ipv6Addr;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tun::AbstractDevice;
use tun2proxy::{ArgDns, ArgProxy, Args, CancellationToken, ProxyType};

use crate::proxy::run_operator_network_proxy_with_listener;
use crate::socks::SocksAuthentication;

const VPN_MTU: u16 = 1500;
const VPN_INTERFACE_IPV4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 2);
const VPN_GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 1);
const VPN_NETMASK_IPV4: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
pub(super) const VIRTUAL_DNS_POOL: &str = "198.18.0.0/15";
pub(super) const VIRTUAL_DNS_SERVER: &str = "198.18.0.1";
#[cfg(target_os = "windows")]
const VPN_INTERFACE_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd73, 0x6870, 0x6f72, 0x7461, 0x6c00, 0, 0, 2);
const TUN_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct TunDevice {
    device: tun::AsyncDevice,
    name: String,
    index: i32,
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
    transport_peers: Vec<IpAddr>,
    policy: SystemVpnPolicy,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    validate_transport_peers(&policy, &transport_peers)?;
    let mut shutdown_signals = ShutdownSignals::new()?;
    let socks_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("failed to bind the VPN's internal SOCKS5 listener")?;
    let socks_addr = socks_listener
        .local_addr()
        .context("failed to read the VPN's internal SOCKS5 address")?;
    let tun = create_tun_device().context(
        "failed to create the VPN interface; run sshportal-server with administrator/root privileges",
    )?;
    let mut route_guard = routes::configure(&tun.name, tun.index, &transport_peers, &policy)
        .with_context(|| {
            format!(
                "failed to configure VPN routes on interface {}; administrator/root privileges are required",
                tun.name
            )
        })?;

    if policy.is_full_tunnel() {
        println!("full-tunnel VPN active on interface {}", tun.name);
    } else {
        println!("selective VPN active on interface {}", tun.name);
    }
    println!("press Ctrl-C to disconnect and restore the original routes");

    let cancellation = CancellationToken::new();
    let tun_cancellation = cancellation.clone();
    let tun_args = tun2proxy_args(socks_addr, &policy);
    let mut proxy_task = tokio::spawn(run_operator_network_proxy_with_listener(
        websocket,
        socks_listener,
        SocksAuthentication::None,
    ));
    let mut tun_task = tokio::spawn(async move {
        tun2proxy::run(tun.device, VPN_MTU, tun_args, tun_cancellation)
            .await
            .map_err(|error| anyhow!("tun2proxy stopped: {error}"))
    });

    let mut proxy_finished = false;
    let mut tun_finished = false;
    let session_result = tokio::select! {
        proxy_result = &mut proxy_task => {
            proxy_finished = true;
            proxy_result
                .context("VPN network proxy task failed to join")
                .and_then(|result| result)
        }
        tun_result = &mut tun_task => {
            tun_finished = true;
            tun_result
                .context("VPN packet engine task failed to join")
                .and_then(|result| result.map(|_| ()))
        }
        _ = shutdown_signals.recv() => Ok(()),
    };

    let restore_result = route_guard.restore();
    cancellation.cancel();
    if !proxy_finished {
        proxy_task.abort();
        let _ = proxy_task.await;
    }
    if !tun_finished {
        finish_tun_task(tun_task).await;
    }

    match (session_result, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(session_error), Err(restore_error)) => {
            Err(session_error.context(format!("VPN route cleanup also failed: {restore_error:#}")))
        }
    }
}

fn create_tun_device() -> Result<TunDevice> {
    let mut configuration = tun::Configuration::default();
    configuration
        .address(VPN_INTERFACE_IPV4)
        .netmask(VPN_NETMASK_IPV4)
        .mtu(VPN_MTU)
        .up();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    configuration.destination(VPN_GATEWAY_IPV4);

    #[cfg(target_os = "windows")]
    {
        configuration.tun_name("sshportal");
        let wintun_path = wintun_path()?;
        configuration.platform_config(|platform| {
            platform.device_guid(0x8973_6870_6f72_7461_6c00_0000_0000_0001);
            platform.wintun_file(wintun_path);
        });
    }

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

fn tun2proxy_args(socks_addr: SocketAddr, policy: &SystemVpnPolicy) -> Args {
    Args {
        proxy: ArgProxy {
            proxy_type: ProxyType::Socks5,
            addr: socks_addr,
            credentials: None,
        },
        dns: if policy.uses_virtual_dns() {
            ArgDns::Virtual
        } else {
            ArgDns::Direct
        },
        virtual_dns_pool: VIRTUAL_DNS_POOL
            .parse()
            .expect("the built-in virtual DNS pool must be valid"),
        ipv6_enabled: true,
        setup: false,
        mtu: VPN_MTU,
        tcp_mss: Some(VPN_MTU - 40),
        ..Args::default()
    }
}

fn validate_transport_peers(policy: &SystemVpnPolicy, transport_peers: &[IpAddr]) -> Result<()> {
    for peer in transport_peers {
        let peer = match peer {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(*address)),
            address => *address,
        };
        if policy.contains_exact_ip(peer) {
            bail!(
                "VPN include CIDR selects the WebSocket transport peer {peer} exactly; use a broader CIDR or remove that host selector so SSHPortal can keep its control connection on the physical network"
            );
        }
    }
    Ok(())
}

async fn finish_tun_task(mut task: JoinHandle<Result<usize>>) {
    if task.is_finished() {
        let _ = task.await;
        return;
    }
    if tokio::time::timeout(TUN_SHUTDOWN_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tun2proxy::ArgDns;

    use super::{SystemVpnPolicy, tun2proxy_args, validate_transport_peers};

    #[test]
    fn cidr_only_policy_leaves_dns_in_direct_mode() {
        let policy =
            SystemVpnPolicy::new(vec!["10.20.0.0/16".parse().unwrap()], Vec::new()).unwrap();

        let args = tun2proxy_args(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)), &policy);

        assert_eq!(args.dns, ArgDns::Direct);
    }

    #[test]
    fn full_and_domain_policies_use_virtual_dns() {
        let domain_policy =
            SystemVpnPolicy::new(Vec::new(), vec!["anthem.com".to_string()]).unwrap();

        for policy in [SystemVpnPolicy::default(), domain_policy] {
            let args = tun2proxy_args(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)), &policy);
            assert_eq!(args.dns, ArgDns::Virtual);
            assert_eq!(args.virtual_dns_pool.to_string(), "198.18.0.0/15");
        }
    }

    #[test]
    fn exact_transport_peer_selector_is_rejected() {
        let policy =
            SystemVpnPolicy::new(vec!["203.0.113.8/32".parse().unwrap()], Vec::new()).unwrap();

        let result = validate_transport_peers(&policy, &["203.0.113.8".parse().unwrap()]);

        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("WebSocket transport peer"));
    }

    #[test]
    fn broader_transport_peer_selector_is_safe() {
        let policy =
            SystemVpnPolicy::new(vec!["203.0.113.0/24".parse().unwrap()], Vec::new()).unwrap();

        validate_transport_peers(&policy, &["203.0.113.8".parse().unwrap()]).unwrap();
    }
}
