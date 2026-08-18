use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    dictionary::CFDictionary,
    number::CFNumber,
    string::CFString,
};
#[cfg(target_os = "macos")]
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};

use crate::debug::debug_log;

use super::configuration::{SyntheticNetworkConfiguration, VpnNetworkConfiguration};
use super::policy::SystemVpnPolicy;

const JOURNAL_VERSION: u8 = 2;
const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JOURNALED_RESOURCES: usize = 4_096;
const ROUTE_METRIC: u32 = 4;
// Darwin requires a host prefix when an IFF_POINTOPOINT IPv6 address has an
// explicit destination. The /126 allocation remains the collision boundary.
const MACOS_POINT_TO_POINT_IPV6_PREFIX: u8 = 128;
const LINUX_TCP_PROTOCOL: u8 = 6;
const LINUX_MAIN_ROUTE_TABLE: u32 = 254;
const LINUX_LOCAL_ROUTE_TABLE: u32 = 255;
const SPLIT_DEFAULT_ROUTES: [IpNet; 4] = [
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 1)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(128, 0, 0, 0), 1)),
    IpNet::V6(Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 1)),
    IpNet::V6(Ipv6Net::new_assert(
        Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
        1,
    )),
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Platform {
    Linux,
    Macos,
    Windows,
}

impl Platform {
    fn current() -> Result<Self> {
        #[cfg(target_os = "linux")]
        return Ok(Self::Linux);
        #[cfg(target_os = "macos")]
        return Ok(Self::Macos);
        #[cfg(target_os = "windows")]
        return Ok(Self::Windows);
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        bail!("VPN routing is supported only on Linux, macOS, and Windows");
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommandSpec {
    program: String,
    arguments: Vec<String>,
}

impl CommandSpec {
    fn new(
        program: impl Into<String>,
        arguments: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            arguments: arguments.into_iter().map(Into::into).collect(),
        }
    }

    fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.arguments.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

impl CommandOutput {
    #[cfg(test)]
    fn success(stdout: impl Into<String>) -> Self {
        Self {
            success: true,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
}

pub(super) trait CommandExecutor {
    fn execute(&self, command: &CommandSpec) -> Result<CommandOutput>;
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn execute(&self, command: &CommandSpec) -> Result<CommandOutput> {
        let output = Command::new(&command.program)
            .args(&command.arguments)
            .output()
            .with_context(|| format!("failed to start `{}`", command.display()))?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8(output.stdout)
                .with_context(|| format!("`{}` returned non-UTF-8 output", command.display()))?,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn run_required<E: CommandExecutor>(executor: &E, command: &CommandSpec) -> Result<String> {
    let output = executor.execute(command)?;
    if output.success {
        return Ok(output.stdout);
    }
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    bail!("`{}` failed: {detail}", command.display())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RoutePlan {
    tunnel_prefixes: Vec<IpNet>,
    dns: Option<DnsPlan>,
    requires_ipv6: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnsPlan {
    servers: [IpAddr; 2],
    match_domains: DnsMatchDomains,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DnsMatchDomains {
    All,
    Selected(Vec<String>),
}

impl RoutePlan {
    fn for_policy(policy: &SystemVpnPolicy, network: VpnNetworkConfiguration) -> Result<Self> {
        if policy.is_full_tunnel() {
            let synthetic = require_synthetic(network.synthetic)?;
            return Ok(Self {
                tunnel_prefixes: SPLIT_DEFAULT_ROUTES.to_vec(),
                dns: Some(DnsPlan {
                    servers: synthetic.dns_servers(),
                    match_domains: DnsMatchDomains::All,
                }),
                requires_ipv6: true,
            });
        }

        let mut tunnel_prefixes = Vec::new();
        for network in policy.include_cidrs() {
            if network.prefix_len() == 0 {
                let defaults = if network.addr().is_ipv4() {
                    &SPLIT_DEFAULT_ROUTES[..2]
                } else {
                    &SPLIT_DEFAULT_ROUTES[2..]
                };
                append_unique_networks(&mut tunnel_prefixes, defaults.iter().copied());
                continue;
            }
            append_unique_networks(&mut tunnel_prefixes, [*network]);
        }

        let dns = if policy.include_domains().is_empty() {
            None
        } else {
            let synthetic = require_synthetic(network.synthetic)?;
            append_unique_networks(&mut tunnel_prefixes, synthetic.routes());
            Some(DnsPlan {
                servers: synthetic.dns_servers(),
                match_domains: DnsMatchDomains::Selected(policy.include_domains().to_vec()),
            })
        };
        Ok(Self {
            tunnel_prefixes,
            dns,
            requires_ipv6: policy.requires_ipv6_tunnel(),
        })
    }

    fn requires_ipv6(&self) -> bool {
        self.requires_ipv6
    }
}

fn require_synthetic(
    synthetic: Option<SyntheticNetworkConfiguration>,
) -> Result<SyntheticNetworkConfiguration> {
    synthetic.context(
        "the VPN policy requires synthetic DNS, but no synthetic address pool was selected",
    )
}

fn append_unique_networks(networks: &mut Vec<IpNet>, additions: impl IntoIterator<Item = IpNet>) {
    for addition in additions {
        if !networks.contains(&addition) {
            networks.push(addition);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransportSocket {
    local: SocketAddr,
    peer: SocketAddr,
}

impl TransportSocket {
    fn new(local: SocketAddr, peer: SocketAddr) -> Result<Self> {
        let local = SocketAddr::new(normalize_ip(local.ip()), local.port());
        let peer = SocketAddr::new(normalize_ip(peer.ip()), peer.port());
        if local.ip().is_unspecified() || peer.ip().is_unspecified() {
            bail!("the WebSocket transport socket reported an unspecified address");
        }
        if local.is_ipv4() != peer.is_ipv4() {
            bail!("the WebSocket transport socket reported mismatched address families");
        }
        Ok(Self { local, peer })
    }
}

#[derive(Clone, Debug)]
pub(super) struct PreparedHostNetwork<E: CommandExecutor = SystemCommandExecutor> {
    executor: E,
    platform: Platform,
    journal_store: JournalStore,
    policy: SystemVpnPolicy,
    network: VpnNetworkConfiguration,
}

impl<E: CommandExecutor> PreparedHostNetwork<E> {
    pub(super) fn network_configuration(&self) -> VpnNetworkConfiguration {
        self.network
    }

    pub(super) fn install(
        self,
        tun_name: &str,
        tun_index: i32,
        transport_local: SocketAddr,
        transport_peer: SocketAddr,
    ) -> Result<HostNetworkGuard<E>> {
        validate_interface_name(tun_name)?;
        let tun_index = u32::try_from(tun_index).context("the VPN interface index is negative")?;
        let transport = TransportSocket::new(transport_local, transport_peer)?;
        let route_plan = RoutePlan::for_policy(&self.policy, self.network)?;
        let session = SessionIdentity::new(self.platform)?;
        let tunnel = TunnelIdentity {
            name: tun_name.to_string(),
            index: tun_index,
        };
        let mut bypass = initial_bypass_state(self.platform, &self.executor, &tunnel, transport)?;
        let static_resources = static_resources(self.platform, &tunnel, self.network, &route_plan);

        let mut resources = Vec::new();
        if let Some(state) = &mut bypass
            && let Some(resource) = &state.resource
        {
            state.owned = !resource_is_present(self.platform, &self.executor, resource)?;
            if state.owned {
                resources.push(resource.clone());
            }
        }
        for resource in &static_resources {
            if !resource_is_present(self.platform, &self.executor, resource)? {
                resources.push(resource.clone());
            }
        }
        if let Some(dns) = &route_plan.dns {
            resources.push(dns_resource(self.platform, &tunnel, session.id, dns));
        }

        let journal = SessionJournal {
            header: JournalHeader {
                version: JOURNAL_VERSION,
                platform: self.platform,
                owner_pid: std::process::id(),
                owner_identity: session.process_identity,
                session_id: session.id,
            },
            resources,
        };
        validate_journal(self.platform, &journal)
            .context("refusing to create an unrecoverable VPN host-network transaction")?;
        self.journal_store.begin(&journal.header)?;
        for resource in &journal.resources {
            if let Err(error) = self.journal_store.arm(resource) {
                let remove_result = self.journal_store.remove();
                return match remove_result {
                    Ok(()) => Err(error).context("failed to prepare VPN recovery journal"),
                    Err(remove_error) => Err(error).context(format!(
                        "failed to prepare VPN recovery journal; removing the incomplete journal also failed: {remove_error:#}"
                    )),
                };
            }
        }

        let mut guard = HostNetworkGuard {
            executor: self.executor,
            platform: self.platform,
            journal_store: self.journal_store,
            session_id: session.id,
            tunnel,
            route_plan,
            network: self.network,
            transport,
            bypass: bypass.take(),
            static_resources,
            resources: journal.resources,
            #[cfg(target_os = "macos")]
            macos_dns: None,
            active: true,
        };

        if let Err(error) = guard.apply_initial_state() {
            let cleanup = guard.restore();
            return match cleanup {
                Ok(()) => Err(error).context("failed to install VPN host-network state"),
                Err(cleanup_error) => Err(error).context(format!(
                    "failed to install VPN host-network state; cleanup also failed: {cleanup_error:#}"
                )),
            };
        }
        Ok(guard)
    }
}

pub(super) fn prepare(
    policy: &SystemVpnPolicy,
    entropy: [u8; 16],
    transport_peer: IpAddr,
) -> Result<PreparedHostNetwork> {
    prepare_with(
        policy,
        entropy,
        transport_peer,
        Platform::current()?,
        SystemCommandExecutor,
        JournalStore::production()?,
    )
}

fn prepare_with<E: CommandExecutor>(
    policy: &SystemVpnPolicy,
    entropy: [u8; 16],
    transport_peer: IpAddr,
    platform: Platform,
    executor: E,
    journal_store: JournalStore,
) -> Result<PreparedHostNetwork<E>> {
    recover_stale_journal(platform, &executor, &journal_store)?;
    let mut address_conflicts = inventory_routes(platform, &executor)
        .context("failed to inventory host routes before selecting VPN address ranges")?;
    append_unique_networks(
        &mut address_conflicts,
        policy.include_cidrs().iter().copied(),
    );
    let transport_peer = normalize_ip(transport_peer);
    append_unique_networks(
        &mut address_conflicts,
        [IpNet::new(
            transport_peer,
            if transport_peer.is_ipv4() { 32 } else { 128 },
        )?],
    );
    let network =
        VpnNetworkConfiguration::select(&address_conflicts, entropy, policy.uses_virtual_dns())?;
    Ok(PreparedHostNetwork {
        executor,
        platform,
        journal_store,
        policy: policy.clone(),
        network,
    })
}

pub(super) struct HostNetworkGuard<E: CommandExecutor = SystemCommandExecutor> {
    executor: E,
    platform: Platform,
    journal_store: JournalStore,
    session_id: [u8; 16],
    tunnel: TunnelIdentity,
    route_plan: RoutePlan,
    network: VpnNetworkConfiguration,
    transport: TransportSocket,
    bypass: Option<BypassState>,
    static_resources: Vec<OwnedResource>,
    resources: Vec<OwnedResource>,
    #[cfg(target_os = "macos")]
    macos_dns: Option<MacosDnsPolicy>,
    active: bool,
}

impl<E: CommandExecutor> HostNetworkGuard<E> {
    fn apply_initial_state(&mut self) -> Result<()> {
        if let Some(bypass) = &self.bypass
            && bypass.owned
            && let Some(resource) = &bypass.resource
        {
            apply_resource(self.platform, &self.executor, resource, ApplyMode::Initial)?;
        }
        for resource in &self.static_resources {
            if self.resources.contains(resource) {
                apply_resource(self.platform, &self.executor, resource, ApplyMode::Initial)?;
            }
        }
        if self.platform == Platform::Linux {
            self.ensure_no_linux_route_collisions()?;
        }
        self.apply_dns()
    }

    pub(super) fn reconcile(&mut self) -> Result<()> {
        if !self.active {
            bail!("cannot reconcile VPN host-network state after it has been restored");
        }
        if self.platform == Platform::Linux {
            self.ensure_no_linux_route_collisions()?;
        }
        self.reconcile_bypass()?;
        for resource in self.static_resources.clone() {
            self.ensure_desired_resource(resource)?;
        }
        self.apply_dns()
            .context("failed to reconcile VPN DNS policy")
    }

    fn reconcile_bypass(&mut self) -> Result<()> {
        let Some(current) = self.bypass.clone() else {
            return Ok(());
        };
        if self.platform == Platform::Linux {
            return self.reconcile_linux_bypass(current);
        }
        let current_resource = current
            .resource
            .as_ref()
            .context("non-Linux bypass state omitted its host route")?;
        if !current.owned {
            if resource_is_present(self.platform, &self.executor, current_resource)? {
                return Ok(());
            }
            let replacement = self.replacement_for_missing_bypass(&current)?;
            self.bypass = Some(replacement);
            return Ok(());
        }
        if !current.follows_default
            && path_is_available(self.platform, &self.executor, &current.path)?
        {
            return ensure_resource_present(self.platform, &self.executor, current_resource);
        }

        let Some(path) =
            lookup_default_path(self.platform, &self.executor, self.transport.peer.is_ipv6())?
        else {
            bail!(
                "the physical default route for WebSocket peer {} disappeared",
                self.transport.peer.ip()
            );
        };
        if path_uses_tunnel(&path, &self.tunnel) {
            bail!(
                "the physical default route for WebSocket peer {} now uses the VPN interface",
                self.transport.peer.ip()
            );
        }
        let replacement = bypass_resource(self.platform, self.transport.peer.ip(), &path)?;
        if replacement == current.resource {
            return ensure_resource_present(self.platform, &self.executor, current_resource);
        }
        let replacement_resource = replacement
            .as_ref()
            .context("non-Linux replacement bypass omitted its host route")?;

        if !resource_is_present(self.platform, &self.executor, current_resource)? {
            let owned = !resource_is_present(self.platform, &self.executor, replacement_resource)?;
            if owned {
                self.arm_additional_resource(replacement_resource.clone())?;
                apply_resource(
                    self.platform,
                    &self.executor,
                    replacement_resource,
                    ApplyMode::Initial,
                )?;
            }
            self.bypass = Some(BypassState {
                resource: replacement,
                path,
                follows_default: true,
                owned,
            });
            return Ok(());
        }
        if resource_is_present(self.platform, &self.executor, replacement_resource)? {
            cleanup_resource(self.platform, &self.executor, current_resource)?;
            self.bypass = Some(BypassState {
                resource: replacement,
                path,
                follows_default: true,
                owned: false,
            });
            return Ok(());
        }
        self.arm_additional_resource(replacement_resource.clone())?;
        replace_bypass_resource(
            self.platform,
            &self.executor,
            current_resource,
            replacement_resource,
        )?;
        self.bypass = Some(BypassState {
            resource: replacement,
            path,
            follows_default: true,
            owned: true,
        });
        Ok(())
    }

    fn reconcile_linux_bypass(&mut self, current: BypassState) -> Result<()> {
        let PeerPath::Linux(current_path) = &current.path else {
            bail!("Linux bypass state contains a route from another platform");
        };
        let policy_rules = linux_policy_rules(&self.executor, self.transport.peer.is_ipv6())?;
        if policy_rules != current_path.policy_rules {
            bail!(
                "Linux policy-routing rules changed while the VPN was active; refusing to guess a new control-connection FIB"
            );
        }
        if linux_parent_route_is_present(&self.executor, &current_path.parent)? {
            if current.owned
                && let Some(resource) = &current.resource
            {
                return ensure_resource_present(self.platform, &self.executor, resource);
            }
            return Ok(());
        }

        let inventory = inventory_linux_route_records(&self.executor)?;
        let parent = select_linux_replacement_parent(
            &inventory,
            self.transport,
            current_path.parent.table,
            &self.resources,
        )?;
        let replacement_path = LinuxPeerPath {
            parent,
            policy_rules,
            source: self.transport.local.ip(),
        };
        let replacement_path = PeerPath::Linux(replacement_path);
        if path_uses_tunnel(&replacement_path, &self.tunnel) {
            bail!(
                "the replacement route for WebSocket peer {} uses the VPN interface",
                self.transport.peer.ip()
            );
        }
        let replacement_resource =
            bypass_resource(self.platform, self.transport.peer.ip(), &replacement_path)?;
        self.transition_linux_bypass(current, replacement_path, replacement_resource)
    }

    fn transition_linux_bypass(
        &mut self,
        current: BypassState,
        path: PeerPath,
        replacement: Option<OwnedResource>,
    ) -> Result<()> {
        if replacement == current.resource {
            if current.owned
                && let Some(resource) = &replacement
            {
                ensure_resource_present(self.platform, &self.executor, resource)?;
            }
            self.bypass = Some(BypassState {
                resource: replacement,
                path,
                follows_default: false,
                owned: current.owned,
            });
            return Ok(());
        }

        let current_owned_resource = current.resource.as_ref().filter(|_| current.owned);
        let current_is_present = match current_owned_resource {
            Some(resource) => resource_is_present(self.platform, &self.executor, resource)?,
            None => false,
        };
        let replacement_is_present = match &replacement {
            Some(resource) => resource_is_present(self.platform, &self.executor, resource)?,
            None => true,
        };
        let replacement_owned = replacement.is_some() && !replacement_is_present;

        if replacement_owned {
            let resource = replacement
                .as_ref()
                .expect("replacement ownership requires a route resource");
            self.arm_additional_resource(resource.clone())?;
            if current_is_present {
                replace_bypass_resource(
                    self.platform,
                    &self.executor,
                    current_owned_resource.expect("a present owned bypass has a route resource"),
                    resource,
                )?;
            } else {
                apply_resource(self.platform, &self.executor, resource, ApplyMode::Initial)?;
            }
            ensure_resource_present(self.platform, &self.executor, resource)?;
        }

        if current_is_present && !replacement_owned {
            cleanup_resource(
                self.platform,
                &self.executor,
                current_owned_resource.expect("a present owned bypass has a route resource"),
            )?;
        }
        self.bypass = Some(BypassState {
            resource: replacement,
            path,
            follows_default: false,
            owned: replacement_owned,
        });
        Ok(())
    }

    fn ensure_no_linux_route_collisions(&self) -> Result<()> {
        let inventory = inventory_linux_route_records(&self.executor)?;
        if let Some(route) =
            first_linux_route_collision(&inventory, &self.resources, &self.tunnel, self.network)
        {
            bail!(
                "non-session Linux route {} in table {} overlaps an immutable VPN address range",
                route.prefix,
                route.table
            );
        }
        Ok(())
    }

    fn replacement_for_missing_bypass(&mut self, current: &BypassState) -> Result<BypassState> {
        let default =
            lookup_default_path(self.platform, &self.executor, self.transport.peer.is_ipv6())?;
        let path = if path_is_available(self.platform, &self.executor, &current.path)? {
            current.path.clone()
        } else {
            default.clone().with_context(|| {
                format!(
                    "the WebSocket peer {} no longer has a usable physical route",
                    self.transport.peer.ip()
                )
            })?
        };
        if path_uses_tunnel(&path, &self.tunnel) {
            bail!(
                "the replacement route for WebSocket peer {} uses the VPN interface",
                self.transport.peer.ip()
            );
        }
        let resource = bypass_resource(self.platform, self.transport.peer.ip(), &path)?;
        let resource_ref = resource
            .as_ref()
            .context("non-Linux replacement bypass omitted its host route")?;
        let owned = !resource_is_present(self.platform, &self.executor, resource_ref)?;
        if owned {
            self.arm_additional_resource(resource_ref.clone())?;
            apply_resource(
                self.platform,
                &self.executor,
                resource_ref,
                ApplyMode::Initial,
            )?;
        }
        Ok(BypassState {
            resource,
            follows_default: default
                .as_ref()
                .is_some_and(|default| paths_share_egress(default, &path)),
            path,
            owned,
        })
    }

    fn ensure_desired_resource(&mut self, resource: OwnedResource) -> Result<()> {
        if self.resources.contains(&resource) {
            return ensure_resource_present(self.platform, &self.executor, &resource);
        }
        if resource_is_present(self.platform, &self.executor, &resource)? {
            return Ok(());
        }
        self.arm_additional_resource(resource.clone())?;
        apply_resource(self.platform, &self.executor, &resource, ApplyMode::Initial)
    }

    fn arm_additional_resource(&mut self, resource: OwnedResource) -> Result<()> {
        if self.resources.contains(&resource) {
            return Ok(());
        }
        if self.resources.len() >= MAX_JOURNALED_RESOURCES {
            bail!("VPN recovery journal resource limit reached during route reconciliation");
        }
        self.journal_store.arm(&resource)?;
        self.resources.push(resource);
        Ok(())
    }

    fn apply_dns(&mut self) -> Result<()> {
        let Some(dns) = &self.route_plan.dns else {
            return Ok(());
        };
        #[cfg(target_os = "macos")]
        if self.platform == Platform::Macos {
            let policy = MacosDnsPolicy::install(
                self.session_id,
                &self.tunnel.name,
                dns,
                self.macos_dns.take(),
            )?;
            self.macos_dns = Some(policy);
            return Ok(());
        }
        apply_dns_commands(
            self.platform,
            &self.executor,
            &self.tunnel,
            self.session_id,
            dns,
        )
    }

    pub(super) fn restore(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        self.macos_dns.take();
        cleanup_resources(self.platform, &self.executor, &self.resources)?;
        self.journal_store.remove()?;
        self.active = false;
        Ok(())
    }
}

impl<E: CommandExecutor> Drop for HostNetworkGuard<E> {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("failed to restore VPN host-network configuration: {error:#}");
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TunnelIdentity {
    name: String,
    index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BypassState {
    resource: Option<OwnedResource>,
    path: PeerPath,
    follows_default: bool,
    owned: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OwnedResource {
    Route {
        prefix: IpNet,
        target: RouteTarget,
    },
    LinuxIpv6Address {
        interface: String,
        address: Ipv6Addr,
        gateway: Ipv6Addr,
        prefix_len: u8,
    },
    LinuxResolved {
        interface: String,
    },
    MacosIpv6Address {
        interface: String,
        address: Ipv6Addr,
        gateway: Ipv6Addr,
        prefix_len: u8,
    },
    MacosDns {
        session_id: [u8; 16],
    },
    WindowsIpv6Address {
        interface_index: u32,
        address: Ipv6Addr,
        prefix_len: u8,
    },
    WindowsNrpt {
        session_id: [u8; 16],
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
enum RouteTarget {
    Linux {
        table: u32,
        source_prefix: Option<IpNet>,
        source: Option<IpAddr>,
        nexthops: Vec<LinuxNexthop>,
        metric: u32,
    },
    MacosInterface {
        interface: String,
    },
    MacosGateway {
        gateway: String,
    },
    Windows {
        interface_index: u32,
        next_hop: IpAddr,
        metric: u32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
struct LinuxNexthop {
    gateway: Option<IpAddr>,
    interface: String,
    weight: u16,
    on_link: bool,
    pervasive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyMode {
    Initial,
    Reconcile,
}

fn static_resources(
    platform: Platform,
    tunnel: &TunnelIdentity,
    network: VpnNetworkConfiguration,
    route_plan: &RoutePlan,
) -> Vec<OwnedResource> {
    let mut resources = Vec::new();
    if route_plan.requires_ipv6() {
        let address = match platform {
            Platform::Linux => OwnedResource::LinuxIpv6Address {
                interface: tunnel.name.clone(),
                address: network.interface_ipv6,
                gateway: network.gateway_ipv6,
                prefix_len: network.point_to_point_ipv6.prefix_len(),
            },
            Platform::Macos => OwnedResource::MacosIpv6Address {
                interface: tunnel.name.clone(),
                address: network.interface_ipv6,
                gateway: network.gateway_ipv6,
                prefix_len: MACOS_POINT_TO_POINT_IPV6_PREFIX,
            },
            Platform::Windows => OwnedResource::WindowsIpv6Address {
                interface_index: tunnel.index,
                address: network.interface_ipv6,
                prefix_len: network.point_to_point_ipv6.prefix_len(),
            },
        };
        resources.push(address);
    }
    resources.extend(
        route_plan
            .tunnel_prefixes
            .iter()
            .map(|prefix| OwnedResource::Route {
                prefix: *prefix,
                target: tunnel_route_target(platform, tunnel, network, *prefix),
            }),
    );
    resources
}

fn tunnel_route_target(
    platform: Platform,
    tunnel: &TunnelIdentity,
    network: VpnNetworkConfiguration,
    prefix: IpNet,
) -> RouteTarget {
    match platform {
        Platform::Linux => RouteTarget::Linux {
            table: LINUX_MAIN_ROUTE_TABLE,
            source_prefix: None,
            source: None,
            nexthops: vec![LinuxNexthop {
                gateway: None,
                interface: tunnel.name.clone(),
                weight: 1,
                on_link: false,
                pervasive: false,
            }],
            metric: ROUTE_METRIC,
        },
        Platform::Macos => RouteTarget::MacosInterface {
            interface: tunnel.name.clone(),
        },
        Platform::Windows => RouteTarget::Windows {
            interface_index: tunnel.index,
            next_hop: if prefix.addr().is_ipv4() {
                IpAddr::V4(network.gateway_ipv4)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            metric: ROUTE_METRIC,
        },
    }
}

fn dns_resource(
    platform: Platform,
    tunnel: &TunnelIdentity,
    session_id: [u8; 16],
    _dns: &DnsPlan,
) -> OwnedResource {
    match platform {
        Platform::Linux => OwnedResource::LinuxResolved {
            interface: tunnel.name.clone(),
        },
        Platform::Macos => OwnedResource::MacosDns { session_id },
        Platform::Windows => OwnedResource::WindowsNrpt { session_id },
    }
}

fn apply_resource<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    resource: &OwnedResource,
    mode: ApplyMode,
) -> Result<()> {
    validate_resource(platform, resource)?;
    match resource {
        OwnedResource::Route { prefix, target } => apply_route(executor, *prefix, target, mode),
        OwnedResource::LinuxIpv6Address {
            interface,
            address,
            gateway,
            prefix_len,
        } => {
            let verb = if mode == ApplyMode::Initial {
                "add"
            } else {
                "replace"
            };
            run_required(
                executor,
                &CommandSpec::new(
                    "ip",
                    [
                        "-6".to_string(),
                        "address".to_string(),
                        verb.to_string(),
                        format!("{address}/{prefix_len}"),
                        "peer".to_string(),
                        gateway.to_string(),
                        "dev".to_string(),
                        interface.clone(),
                    ],
                ),
            )?;
            Ok(())
        }
        OwnedResource::MacosIpv6Address {
            interface,
            address,
            gateway,
            prefix_len,
        } => {
            if mode == ApplyMode::Reconcile {
                let output = run_required(executor, &CommandSpec::new("ifconfig", [interface]))?;
                if output.contains(&address.to_string()) {
                    return Ok(());
                }
            }
            run_required(
                executor,
                &CommandSpec::new(
                    "ifconfig",
                    [
                        interface.clone(),
                        "inet6".to_string(),
                        address.to_string(),
                        gateway.to_string(),
                        "prefixlen".to_string(),
                        prefix_len.to_string(),
                        "alias".to_string(),
                    ],
                ),
            )?;
            Ok(())
        }
        OwnedResource::WindowsIpv6Address {
            interface_index,
            address,
            prefix_len,
        } => {
            let script = format!(
                "$existing = Get-NetIPAddress -InterfaceIndex {interface_index} -IPAddress '{address}' -AddressFamily IPv6 -ErrorAction SilentlyContinue; \
                 if ($null -eq $existing) {{ \
                     New-NetIPAddress -InterfaceIndex {interface_index} -IPAddress '{address}' \
                         -PrefixLength {prefix_len} -AddressFamily IPv6 -PolicyStore ActiveStore \
                         -ErrorAction Stop | Out-Null \
                 }}"
            );
            run_required(executor, &powershell(script))?;
            Ok(())
        }
        OwnedResource::LinuxResolved { .. }
        | OwnedResource::MacosDns { .. }
        | OwnedResource::WindowsNrpt { .. } => {
            bail!("DNS resources must be applied with their desired DNS policy")
        }
    }
}

fn resource_is_present<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    resource: &OwnedResource,
) -> Result<bool> {
    validate_resource(platform, resource)?;
    match resource {
        OwnedResource::Route { prefix, target } => route_is_present(executor, *prefix, target),
        OwnedResource::LinuxIpv6Address {
            interface, address, ..
        } => {
            let output = executor.execute(&CommandSpec::new(
                "ip",
                ["-6", "address", "show", "dev", interface],
            ))?;
            Ok(output.success && output.stdout.contains(&address.to_string()))
        }
        OwnedResource::MacosIpv6Address {
            interface, address, ..
        } => {
            let output = executor.execute(&CommandSpec::new("ifconfig", [interface]))?;
            Ok(output.success && output.stdout.contains(&address.to_string()))
        }
        OwnedResource::WindowsIpv6Address {
            interface_index,
            address,
            ..
        } => {
            let output = run_required(
                executor,
                &powershell(format!(
                    "$address = Get-NetIPAddress -InterfaceIndex {interface_index} \
                         -IPAddress '{address}' -AddressFamily IPv6 -ErrorAction SilentlyContinue; \
                     if ($null -ne $address) {{ 'present' }}"
                )),
            )?;
            Ok(output.trim() == "present")
        }
        OwnedResource::LinuxResolved { .. }
        | OwnedResource::MacosDns { .. }
        | OwnedResource::WindowsNrpt { .. } => Ok(false),
    }
}

fn ensure_resource_present<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    resource: &OwnedResource,
) -> Result<()> {
    if resource_is_present(platform, executor, resource)? {
        return Ok(());
    }
    apply_resource(platform, executor, resource, ApplyMode::Initial)
}

fn route_is_present<E: CommandExecutor>(
    executor: &E,
    prefix: IpNet,
    target: &RouteTarget,
) -> Result<bool> {
    match target {
        RouteTarget::Linux {
            table,
            source_prefix,
            source,
            nexthops,
            metric,
        } => linux_route_is_present(
            executor,
            prefix,
            *table,
            *source_prefix,
            *source,
            nexthops,
            *metric,
        ),
        RouteTarget::MacosInterface { interface } => {
            macos_route_matches(executor, prefix, None, Some(interface))
        }
        RouteTarget::MacosGateway { gateway } => {
            macos_route_matches(executor, prefix, Some(gateway), None)
        }
        RouteTarget::Windows {
            interface_index,
            next_hop,
            metric,
        } => {
            let output = run_required(
                executor,
                &powershell(format!(
                    "$route = Get-NetRoute -DestinationPrefix '{prefix}' \
                         -InterfaceIndex {interface_index} -NextHop '{next_hop}' \
                         -PolicyStore ActiveStore -ErrorAction SilentlyContinue \
                         | Where-Object {{ $_.RouteMetric -eq {metric} }}; \
                     if ($null -ne $route) {{ 'present' }}"
                )),
            )?;
            Ok(output.trim() == "present")
        }
    }
}

fn apply_route<E: CommandExecutor>(
    executor: &E,
    prefix: IpNet,
    target: &RouteTarget,
    mode: ApplyMode,
) -> Result<()> {
    match target {
        RouteTarget::Linux {
            table,
            source_prefix,
            source,
            nexthops,
            metric,
        } => {
            let verb = if mode == ApplyMode::Initial {
                "add"
            } else {
                "replace"
            };
            let arguments = linux_route_arguments(
                verb,
                prefix,
                *table,
                *source_prefix,
                *source,
                nexthops,
                *metric,
            );
            run_required(executor, &CommandSpec::new("ip", arguments))?;
            Ok(())
        }
        RouteTarget::MacosInterface { interface } => {
            if mode == ApplyMode::Reconcile
                && macos_route_matches(executor, prefix, None, Some(interface))?
            {
                return Ok(());
            }
            run_required(
                executor,
                &CommandSpec::new(
                    "route",
                    [
                        "-n".to_string(),
                        "add".to_string(),
                        macos_family_flag(prefix).to_string(),
                        macos_route_kind(prefix).to_string(),
                        prefix.to_string(),
                        "-interface".to_string(),
                        interface.clone(),
                    ],
                ),
            )?;
            Ok(())
        }
        RouteTarget::MacosGateway { gateway } => {
            if mode == ApplyMode::Reconcile
                && macos_route_matches(executor, prefix, Some(gateway), None)?
            {
                return Ok(());
            }
            run_required(
                executor,
                &CommandSpec::new(
                    "route",
                    [
                        "-n".to_string(),
                        "add".to_string(),
                        macos_family_flag(prefix).to_string(),
                        "-host".to_string(),
                        prefix.addr().to_string(),
                        gateway.clone(),
                    ],
                ),
            )?;
            Ok(())
        }
        RouteTarget::Windows {
            interface_index,
            next_hop,
            metric,
        } => {
            let script = format!(
                "$existing = Get-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} \
                     -NextHop '{next_hop}' -PolicyStore ActiveStore -ErrorAction SilentlyContinue \
                     | Where-Object {{ $_.RouteMetric -eq {metric} }}; \
                 if ($null -eq $existing) {{ \
                     New-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} \
                         -NextHop '{next_hop}' -RouteMetric {metric} -PolicyStore ActiveStore \
                         -ErrorAction Stop | Out-Null \
                 }}"
            );
            run_required(executor, &powershell(script))?;
            Ok(())
        }
    }
}

fn replace_bypass_resource<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    old: &OwnedResource,
    new: &OwnedResource,
) -> Result<()> {
    match (platform, old, new) {
        (
            Platform::Linux,
            OwnedResource::Route {
                prefix: old_prefix,
                target:
                    RouteTarget::Linux {
                        table: old_table, ..
                    },
            },
            OwnedResource::Route {
                prefix: new_prefix,
                target,
            },
        ) if old_prefix == new_prefix => {
            let RouteTarget::Linux {
                table: new_table, ..
            } = target
            else {
                bail!("invalid Linux bypass-route replacement target");
            };
            if old_table == new_table {
                return apply_route(executor, *old_prefix, target, ApplyMode::Reconcile);
            }
            apply_route(executor, *new_prefix, target, ApplyMode::Initial)?;
            if !route_is_present(executor, *new_prefix, target)? {
                bail!("new Linux WebSocket bypass route was not installed");
            }
            cleanup_resource(platform, executor, old)
        }
        (
            Platform::Macos,
            OwnedResource::Route {
                prefix: old_prefix, ..
            },
            OwnedResource::Route {
                prefix: new_prefix,
                target: RouteTarget::MacosGateway { gateway },
            },
        ) if old_prefix == new_prefix => {
            run_required(
                executor,
                &CommandSpec::new(
                    "route",
                    [
                        "-n".to_string(),
                        "change".to_string(),
                        macos_family_flag(*old_prefix).to_string(),
                        "-host".to_string(),
                        old_prefix.addr().to_string(),
                        gateway.clone(),
                    ],
                ),
            )?;
            Ok(())
        }
        (Platform::Windows, _, _) => {
            apply_resource(platform, executor, new, ApplyMode::Initial)?;
            cleanup_resource(platform, executor, old)
        }
        _ => bail!("invalid bypass-route replacement for {platform:?}"),
    }
}

fn apply_dns_commands<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    tunnel: &TunnelIdentity,
    session_id: [u8; 16],
    dns: &DnsPlan,
) -> Result<()> {
    match platform {
        Platform::Linux => {
            let mut server_arguments = vec!["dns".to_string(), tunnel.name.clone()];
            server_arguments.extend(dns.servers.iter().map(ToString::to_string));
            run_required(executor, &CommandSpec::new("resolvectl", server_arguments))?;

            let mut domain_arguments = vec!["domain".to_string(), tunnel.name.clone()];
            match &dns.match_domains {
                DnsMatchDomains::All => domain_arguments.push("~.".to_string()),
                DnsMatchDomains::Selected(domains) => {
                    domain_arguments.extend(domains.iter().map(|domain| format!("~{domain}")));
                }
            }
            run_required(executor, &CommandSpec::new("resolvectl", domain_arguments))?;
            let default_route = if dns.match_domains == DnsMatchDomains::All {
                "true"
            } else {
                "false"
            };
            run_required(
                executor,
                &CommandSpec::new("resolvectl", ["default-route", &tunnel.name, default_route]),
            )?;
            Ok(())
        }
        Platform::Macos => bail!("macOS DNS must be applied through SystemConfiguration"),
        Platform::Windows => {
            run_required(executor, &windows_nrpt_ensure_command(session_id, dns))?;
            Ok(())
        }
    }
}

fn windows_nrpt_ensure_command(session_id: [u8; 16], dns: &DnsPlan) -> CommandSpec {
    let display_name = session_name(session_id);
    let namespaces = match &dns.match_domains {
        DnsMatchDomains::All => vec![".".to_string()],
        DnsMatchDomains::Selected(domains) => domains
            .iter()
            .flat_map(|domain| [domain.clone(), format!(".{domain}")])
            .collect(),
    };
    let namespace_literals = namespaces
        .iter()
        .map(|namespace| format!("'{namespace}'"))
        .collect::<Vec<_>>()
        .join(",");
    let server_literals = dns
        .servers
        .iter()
        .map(|server| format!("'{server}'"))
        .collect::<Vec<_>>()
        .join(",");
    powershell(format!(
        "$displayName = '{display_name}'; \
         $namespaces = @({namespace_literals}); \
         $servers = @({server_literals}); \
         $rules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue \
             | Where-Object {{ $_.DisplayName -eq $displayName }}); \
         $valid = $rules.Count -eq 1; \
         if ($valid) {{ \
             $ruleNamespaces = @($rules[0].Namespace); \
             $ruleServers = @($rules[0].NameServers); \
             $valid = @($namespaces | Where-Object {{ $_ -notin $ruleNamespaces }}).Count -eq 0 \
                 -and @($ruleNamespaces | Where-Object {{ $_ -notin $namespaces }}).Count -eq 0 \
                 -and @($servers | Where-Object {{ $_ -notin $ruleServers }}).Count -eq 0 \
                 -and @($ruleServers | Where-Object {{ $_ -notin $servers }}).Count -eq 0 \
         }}; \
         if (-not $valid) {{ \
             $rules | ForEach-Object {{ \
                 Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop \
             }}; \
             Add-DnsClientNrptRule -Namespace $namespaces -NameServers $servers \
                 -DisplayName $displayName -Comment 'SSHPortal VPN DNS policy' \
                 -ErrorAction Stop | Out-Null; \
             Clear-DnsClientCache -ErrorAction Stop \
         }}"
    ))
}

fn cleanup_resources<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    resources: &[OwnedResource],
) -> Result<()> {
    let mut first_error = None;
    let mut cleaned = HashSet::new();
    for resource in resources.iter().rev() {
        if !cleaned.insert(resource.clone()) {
            continue;
        }
        if let Err(error) = cleanup_resource(platform, executor, resource) {
            debug_log(format!("VPN host-network cleanup failed: {error:#}"));
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => {
            Err(error).context("failed to remove one or more VPN host-network resources")
        }
        None => Ok(()),
    }
}

fn cleanup_resource<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    resource: &OwnedResource,
) -> Result<()> {
    validate_resource(platform, resource)?;
    match resource {
        OwnedResource::Route { prefix, target } => cleanup_route(executor, *prefix, target),
        OwnedResource::LinuxIpv6Address {
            interface,
            address,
            gateway: _,
            prefix_len,
        } => run_cleanup_command(
            executor,
            &CommandSpec::new(
                "ip",
                [
                    "-6",
                    "address",
                    "del",
                    &format!("{address}/{prefix_len}"),
                    "dev",
                    interface,
                ],
            ),
            &["Cannot find device", "Cannot assign requested address"],
        ),
        OwnedResource::LinuxResolved { interface } => run_cleanup_command(
            executor,
            &CommandSpec::new("resolvectl", ["revert", interface]),
            &["not found", "No such"],
        ),
        OwnedResource::MacosIpv6Address {
            interface, address, ..
        } => run_cleanup_command(
            executor,
            &CommandSpec::new(
                "ifconfig",
                [interface, "inet6", &address.to_string(), "-alias"],
            ),
            &["does not exist", "Can't assign requested address"],
        ),
        OwnedResource::MacosDns { session_id } => cleanup_macos_dns(*session_id),
        OwnedResource::WindowsIpv6Address {
            interface_index,
            address,
            ..
        } => {
            let script = format!(
                "$lookupErrors = @(); \
                 $address = Get-NetIPAddress -InterfaceIndex {interface_index} \
                     -IPAddress '{address}' -AddressFamily IPv6 \
                     -ErrorAction SilentlyContinue -ErrorVariable +lookupErrors; \
                 $unexpected = @($lookupErrors | Where-Object {{ \
                     $_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound \
                 }}); \
                 if ($unexpected.Count -gt 0) {{ throw $unexpected[0] }}; \
                 if ($null -ne $address) {{ \
                     $address | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop \
                 }}"
            );
            run_required(executor, &powershell(script))?;
            Ok(())
        }
        OwnedResource::WindowsNrpt { session_id } => {
            let display_name = session_name(*session_id);
            let script = format!(
                "$rules = @(Get-DnsClientNrptRule -ErrorAction Stop \
                     | Where-Object {{ $_.DisplayName -eq '{display_name}' }}); \
                 $rules | ForEach-Object {{ \
                     Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop \
                 }}; \
                 if ($rules.Count -gt 0) {{ Clear-DnsClientCache -ErrorAction SilentlyContinue }}"
            );
            run_required(executor, &powershell(script))?;
            Ok(())
        }
    }
}

fn cleanup_route<E: CommandExecutor>(
    executor: &E,
    prefix: IpNet,
    target: &RouteTarget,
) -> Result<()> {
    match target {
        RouteTarget::Linux {
            table,
            source_prefix,
            source,
            nexthops,
            metric,
        } => {
            let arguments = linux_route_arguments(
                "del",
                prefix,
                *table,
                *source_prefix,
                *source,
                nexthops,
                *metric,
            );
            run_cleanup_command(
                executor,
                &CommandSpec::new("ip", arguments),
                &["No such process", "Cannot find device"],
            )
        }
        RouteTarget::MacosInterface { interface } => {
            if !macos_route_matches(executor, prefix, None, Some(interface))? {
                return Ok(());
            }
            run_cleanup_command(
                executor,
                &CommandSpec::new(
                    "route",
                    [
                        "-n".to_string(),
                        "delete".to_string(),
                        macos_family_flag(prefix).to_string(),
                        macos_route_kind(prefix).to_string(),
                        prefix.to_string(),
                        "-interface".to_string(),
                        interface.clone(),
                    ],
                ),
                &["not in table", "No such process"],
            )
        }
        RouteTarget::MacosGateway { gateway } => {
            if !macos_route_matches(executor, prefix, Some(gateway), None)? {
                return Ok(());
            }
            run_cleanup_command(
                executor,
                &CommandSpec::new(
                    "route",
                    [
                        "-n".to_string(),
                        "delete".to_string(),
                        macos_family_flag(prefix).to_string(),
                        "-host".to_string(),
                        prefix.addr().to_string(),
                        gateway.clone(),
                    ],
                ),
                &["not in table", "No such process"],
            )
        }
        RouteTarget::Windows {
            interface_index,
            next_hop,
            metric,
        } => {
            let script = format!(
                "$lookupErrors = @(); \
                 $routes = @(Get-NetRoute -DestinationPrefix '{prefix}' \
                     -InterfaceIndex {interface_index} -NextHop '{next_hop}' \
                     -PolicyStore ActiveStore -ErrorAction SilentlyContinue \
                     -ErrorVariable +lookupErrors \
                     | Where-Object {{ $_.RouteMetric -eq {metric} }}); \
                 $unexpected = @($lookupErrors | Where-Object {{ \
                     $_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound \
                 }}); \
                 if ($unexpected.Count -gt 0) {{ throw $unexpected[0] }}; \
                 $routes | Remove-NetRoute -Confirm:$false -ErrorAction Stop"
            );
            run_required(executor, &powershell(script))?;
            Ok(())
        }
    }
}

fn run_cleanup_command<E: CommandExecutor>(
    executor: &E,
    command: &CommandSpec,
    absent_markers: &[&str],
) -> Result<()> {
    let output = executor.execute(command)?;
    if output.success
        || absent_markers
            .iter()
            .any(|marker| output.stderr.contains(marker) || output.stdout.contains(marker))
    {
        return Ok(());
    }
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    bail!("`{}` failed during cleanup: {detail}", command.display())
}

fn validate_resource(platform: Platform, resource: &OwnedResource) -> Result<()> {
    match (platform, resource) {
        (
            Platform::Linux,
            OwnedResource::Route {
                prefix,
                target:
                    RouteTarget::Linux {
                        table,
                        source_prefix,
                        source,
                        nexthops,
                        metric,
                    },
            },
        ) => {
            validate_prefix(*prefix)?;
            validate_linux_route_table(*table)?;
            if let Some(source_prefix) = source_prefix {
                validate_prefix(*source_prefix)?;
                if source_prefix.addr().is_ipv4() != prefix.addr().is_ipv4() {
                    bail!("journaled Linux route source and destination use different families");
                }
            }
            validate_gateway_family(*prefix, *source)?;
            validate_linux_nexthops(*prefix, nexthops)?;
            validate_metric(*metric)
        }
        (
            Platform::Linux,
            OwnedResource::LinuxIpv6Address {
                interface,
                prefix_len,
                ..
            },
        ) => {
            validate_interface_name(interface)?;
            if *prefix_len != 126 {
                bail!("invalid journaled Linux IPv6 prefix length");
            }
            Ok(())
        }
        (Platform::Linux, OwnedResource::LinuxResolved { interface }) => {
            validate_interface_name(interface)
        }
        (
            Platform::Macos,
            OwnedResource::Route {
                prefix,
                target: RouteTarget::MacosInterface { interface },
            },
        ) => {
            validate_prefix(*prefix)?;
            validate_interface_name(interface)
        }
        (
            Platform::Macos,
            OwnedResource::Route {
                prefix,
                target: RouteTarget::MacosGateway { gateway },
            },
        ) => {
            validate_prefix(*prefix)?;
            validate_macos_gateway(gateway)
        }
        (
            Platform::Macos,
            OwnedResource::MacosIpv6Address {
                interface,
                prefix_len,
                ..
            },
        ) => {
            validate_interface_name(interface)?;
            if *prefix_len != MACOS_POINT_TO_POINT_IPV6_PREFIX {
                bail!("invalid journaled macOS IPv6 prefix length");
            }
            Ok(())
        }
        (Platform::Macos, OwnedResource::MacosDns { .. }) => Ok(()),
        (
            Platform::Windows,
            OwnedResource::Route {
                prefix,
                target:
                    RouteTarget::Windows {
                        next_hop, metric, ..
                    },
            },
        ) => {
            validate_prefix(*prefix)?;
            validate_gateway_family(*prefix, Some(*next_hop))?;
            validate_metric(*metric)
        }
        (Platform::Windows, OwnedResource::WindowsIpv6Address { prefix_len, .. }) => {
            if *prefix_len != 126 {
                bail!("invalid journaled Windows IPv6 prefix length");
            }
            Ok(())
        }
        (Platform::Windows, OwnedResource::WindowsNrpt { .. }) => Ok(()),
        _ => bail!("journaled resource does not belong to the current platform"),
    }
}

fn validate_prefix(prefix: IpNet) -> Result<()> {
    if prefix != prefix.trunc() {
        bail!("journaled route prefix is not canonical");
    }
    Ok(())
}

fn validate_gateway_family(prefix: IpNet, gateway: Option<IpAddr>) -> Result<()> {
    if gateway.is_some_and(|gateway| gateway.is_ipv4() != prefix.addr().is_ipv4()) {
        bail!("journaled route gateway and prefix use different address families");
    }
    Ok(())
}

fn validate_metric(metric: u32) -> Result<()> {
    if metric != ROUTE_METRIC {
        bail!("journaled route has an unexpected metric");
    }
    Ok(())
}

fn validate_interface_name(interface: &str) -> Result<()> {
    if interface.is_empty() || interface.len() > 128 {
        bail!("invalid VPN interface name");
    }
    if !interface
        .bytes()
        .all(|character| character.is_ascii_alphanumeric() || b"._-".contains(&character))
    {
        bail!("VPN interface name contains an unsupported character");
    }
    Ok(())
}

fn validate_macos_gateway(gateway: &str) -> Result<()> {
    if gateway.is_empty() || gateway.len() > 128 {
        bail!("invalid journaled macOS gateway");
    }
    if !gateway
        .bytes()
        .all(|character| character.is_ascii_alphanumeric() || b".:_%#-".contains(&character))
    {
        bail!("journaled macOS gateway contains an unsupported character");
    }
    Ok(())
}

fn validate_linux_route_table(table: u32) -> Result<()> {
    if table == 0 || table == LINUX_LOCAL_ROUTE_TABLE {
        bail!("invalid journaled Linux route table");
    }
    Ok(())
}

fn validate_linux_nexthops(prefix: IpNet, nexthops: &[LinuxNexthop]) -> Result<()> {
    if nexthops.is_empty() || nexthops.len() > 256 {
        bail!("invalid journaled Linux nexthop count");
    }
    for nexthop in nexthops {
        validate_interface_name(&nexthop.interface)?;
        validate_gateway_family(prefix, nexthop.gateway)?;
        if nexthop.weight == 0
            || nexthop.weight > 256
            || (nexthops.len() == 1 && nexthop.weight != 1)
        {
            bail!("invalid journaled Linux nexthop weight");
        }
    }
    Ok(())
}

fn linux_route_arguments(
    verb: &str,
    prefix: IpNet,
    table: u32,
    source_prefix: Option<IpNet>,
    source: Option<IpAddr>,
    nexthops: &[LinuxNexthop],
    metric: u32,
) -> Vec<String> {
    let mut arguments = vec![
        ip_family_flag(prefix).to_string(),
        "route".to_string(),
        verb.to_string(),
        prefix.to_string(),
        "table".to_string(),
        table.to_string(),
    ];
    if let Some(source_prefix) = source_prefix {
        arguments.extend(["from".to_string(), source_prefix.to_string()]);
    }
    if let Some(source) = source {
        arguments.extend(["src".to_string(), source.to_string()]);
    }
    arguments.extend(["metric".to_string(), metric.to_string()]);
    if nexthops.len() == 1 {
        append_linux_nexthop_arguments(&mut arguments, &nexthops[0], false);
        return arguments;
    }
    for nexthop in nexthops {
        append_linux_nexthop_arguments(&mut arguments, nexthop, true);
    }
    arguments
}

fn append_linux_nexthop_arguments(
    arguments: &mut Vec<String>,
    nexthop: &LinuxNexthop,
    multipath: bool,
) {
    if multipath {
        arguments.push("nexthop".to_string());
    }
    if let Some(gateway) = nexthop.gateway {
        arguments.extend(["via".to_string(), gateway.to_string()]);
    }
    arguments.extend(["dev".to_string(), nexthop.interface.clone()]);
    if multipath {
        arguments.extend(["weight".to_string(), nexthop.weight.to_string()]);
    }
    if nexthop.on_link {
        arguments.push("onlink".to_string());
    }
    if nexthop.pervasive {
        arguments.push("pervasive".to_string());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxRouteRecord {
    identity: serde_json::Value,
    prefix: IpNet,
    source_prefix: Option<IpNet>,
    table: u32,
    route_type: u8,
    protocol: Option<u8>,
    metric: u32,
    preferred_source: Option<IpAddr>,
    nexthops: Vec<LinuxNexthop>,
}

impl LinuxRouteRecord {
    fn matches_destination(&self, destination: IpAddr, source: IpAddr) -> bool {
        self.prefix.contains(&destination)
            && self
                .source_prefix
                .is_none_or(|prefix| prefix.contains(&source))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxPeerPath {
    parent: LinuxRouteRecord,
    policy_rules: serde_json::Value,
    source: IpAddr,
}

fn linux_route_is_present<E: CommandExecutor>(
    executor: &E,
    prefix: IpNet,
    table: u32,
    source_prefix: Option<IpNet>,
    source: Option<IpAddr>,
    nexthops: &[LinuxNexthop],
    metric: u32,
) -> Result<bool> {
    let records = linux_routes_for_exact_prefix(executor, prefix, table)?;
    Ok(records.iter().any(|record| {
        record.route_type == 1
            && record.source_prefix == source_prefix
            && record.preferred_source == source
            && record.metric == metric
            && record.nexthops == nexthops
    }))
}

fn linux_routes_for_exact_prefix<E: CommandExecutor>(
    executor: &E,
    prefix: IpNet,
    table: u32,
) -> Result<Vec<LinuxRouteRecord>> {
    let output = executor.execute(&CommandSpec::new(
        "ip",
        [
            "-j".to_string(),
            "-details".to_string(),
            "-N".to_string(),
            ip_family_flag(prefix).to_string(),
            "route".to_string(),
            "show".to_string(),
            "table".to_string(),
            table.to_string(),
            "exact".to_string(),
            prefix.to_string(),
        ],
    ))?;
    if !output.success {
        return Ok(Vec::new());
    }
    parse_linux_route_records(&output.stdout, prefix.addr().is_ipv6(), Some(table))
}

fn parse_linux_route_records(
    output: &str,
    ipv6: bool,
    default_table: Option<u32>,
) -> Result<Vec<LinuxRouteRecord>> {
    let values = serde_json::from_str::<Vec<serde_json::Value>>(output.trim())
        .context("failed to decode Linux route inventory")?;
    values
        .into_iter()
        .map(|value| parse_linux_route_record(value, ipv6, default_table))
        .collect()
}

fn parse_linux_route_record(
    mut identity: serde_json::Value,
    ipv6: bool,
    default_table: Option<u32>,
) -> Result<LinuxRouteRecord> {
    let object = identity
        .as_object_mut()
        .context("Linux returned a non-object route record")?;
    let destination = json_string(object, "dst")?;
    let prefix = parse_route_destination(destination, ipv6)
        .with_context(|| format!("Linux returned invalid route destination `{destination}`"))?;
    let table = match object.get("table") {
        Some(value) => json_u32(value, "route table")?,
        None => default_table.unwrap_or(LINUX_MAIN_ROUTE_TABLE),
    };
    object.insert(
        "table".to_string(),
        serde_json::Value::String(table.to_string()),
    );
    let route_type = object
        .get("type")
        .map(|value| json_u8(value, "route type"))
        .transpose()?
        .unwrap_or(1);
    let protocol = object
        .get("protocol")
        .map(|value| json_u8(value, "route protocol"))
        .transpose()?;
    let source_prefix = object
        .get("from")
        .map(|value| {
            let source = value
                .as_str()
                .context("Linux returned a non-string source route prefix")?;
            if source == "all" {
                return Ok(None);
            }
            parse_route_destination(source, ipv6)
                .map(Some)
                .with_context(|| format!("Linux returned invalid source route prefix `{source}`"))
        })
        .transpose()?
        .flatten();
    let preferred_source = object
        .get("prefsrc")
        .map(|value| parse_json_ip(value, "preferred route source"))
        .transpose()?;
    let metric = object
        .get("metric")
        .map(|value| json_u32(value, "route metric"))
        .transpose()?
        .unwrap_or(0);
    let nexthops = parse_linux_nexthops(object)?;
    Ok(LinuxRouteRecord {
        identity,
        prefix,
        source_prefix,
        table,
        route_type,
        protocol,
        metric,
        preferred_source,
        nexthops,
    })
}

fn parse_linux_nexthops(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<LinuxNexthop>> {
    let Some(value) = object.get("nexthops") else {
        let Some(interface) = object.get("dev") else {
            return Ok(Vec::new());
        };
        return Ok(vec![parse_linux_nexthop(object, interface, false)?]);
    };
    let values = value
        .as_array()
        .context("Linux returned a non-array multipath route")?;
    values
        .iter()
        .map(|value| {
            let nexthop = value
                .as_object()
                .context("Linux returned a non-object multipath nexthop")?;
            let interface = nexthop
                .get("dev")
                .context("Linux multipath route omitted its interface")?;
            parse_linux_nexthop(nexthop, interface, true)
        })
        .collect()
}

fn parse_linux_nexthop(
    object: &serde_json::Map<String, serde_json::Value>,
    interface: &serde_json::Value,
    multipath: bool,
) -> Result<LinuxNexthop> {
    let interface = interface
        .as_str()
        .context("Linux returned a non-string route interface")?
        .to_string();
    validate_interface_name(&interface)?;
    let gateway = object
        .get("gateway")
        .map(|value| parse_json_ip(value, "route gateway"))
        .transpose()?;
    let weight = if multipath {
        object
            .get("weight")
            .map(|value| json_u16(value, "nexthop weight"))
            .transpose()?
            .unwrap_or(1)
    } else {
        1
    };
    let flags = object
        .get("flags")
        .map(parse_linux_route_flags)
        .transpose()?
        .unwrap_or_default();
    Ok(LinuxNexthop {
        gateway,
        interface,
        weight,
        on_link: flags.contains(&"onlink"),
        pervasive: flags.contains(&"pervasive"),
    })
}

fn parse_linux_route_flags(value: &serde_json::Value) -> Result<Vec<&str>> {
    value
        .as_array()
        .context("Linux returned non-array route flags")?
        .iter()
        .map(|flag| {
            flag.as_str()
                .context("Linux returned a non-string route flag")
        })
        .collect()
}

fn json_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str> {
    object
        .get(key)
        .with_context(|| format!("Linux route record omitted `{key}`"))?
        .as_str()
        .with_context(|| format!("Linux returned a non-string `{key}` route field"))
}

fn json_u8(value: &serde_json::Value, label: &str) -> Result<u8> {
    let value = json_u64(value, label)?;
    u8::try_from(value).with_context(|| format!("Linux returned an out-of-range {label}"))
}

fn json_u16(value: &serde_json::Value, label: &str) -> Result<u16> {
    let value = json_u64(value, label)?;
    u16::try_from(value).with_context(|| format!("Linux returned an out-of-range {label}"))
}

fn json_u32(value: &serde_json::Value, label: &str) -> Result<u32> {
    let value = json_u64(value, label)?;
    u32::try_from(value).with_context(|| format!("Linux returned an out-of-range {label}"))
}

fn json_u64(value: &serde_json::Value, label: &str) -> Result<u64> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    value
        .as_str()
        .with_context(|| format!("Linux returned a non-numeric {label}"))?
        .parse()
        .with_context(|| format!("Linux returned an invalid {label}"))
}

fn parse_json_ip(value: &serde_json::Value, label: &str) -> Result<IpAddr> {
    value
        .as_str()
        .with_context(|| format!("Linux returned a non-string {label}"))?
        .parse()
        .with_context(|| format!("Linux returned an invalid {label}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PeerPath {
    Linux(LinuxPeerPath),
    Macos {
        gateway: String,
        interface: Option<String>,
    },
    Windows {
        next_hop: IpAddr,
        interface_index: u32,
    },
}

fn initial_bypass_state<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    tunnel: &TunnelIdentity,
    transport: TransportSocket,
) -> Result<Option<BypassState>> {
    let peer = transport.peer.ip();
    if peer.is_loopback() {
        return Ok(None);
    }
    let path = lookup_peer_path(platform, executor, transport)?;
    if path_uses_tunnel(&path, tunnel) {
        bail!(
            "the WebSocket peer {peer} already resolves through the new VPN interface; refusing to create a routing loop"
        );
    }
    let follows_default = if platform == Platform::Linux {
        false
    } else {
        lookup_default_path(platform, executor, peer.is_ipv6())?
            .as_ref()
            .is_some_and(|default| paths_share_egress(default, &path))
    };
    Ok(Some(BypassState {
        resource: bypass_resource(platform, peer, &path)?,
        path,
        follows_default,
        owned: false,
    }))
}

fn paths_share_egress(left: &PeerPath, right: &PeerPath) -> bool {
    match (left, right) {
        (PeerPath::Linux(left), PeerPath::Linux(right)) => {
            left.parent.table == right.parent.table
                && left.parent.nexthops == right.parent.nexthops
                && left.source == right.source
        }
        (
            PeerPath::Macos {
                gateway: left_gateway,
                interface: left_interface,
            },
            PeerPath::Macos {
                gateway: right_gateway,
                interface: right_interface,
            },
        ) => {
            left_gateway == right_gateway
                && (left_interface == right_interface
                    || left_interface.is_none()
                    || right_interface.is_none())
        }
        (
            PeerPath::Windows {
                next_hop: left_hop,
                interface_index: left_interface,
            },
            PeerPath::Windows {
                next_hop: right_hop,
                interface_index: right_interface,
            },
        ) => left_hop == right_hop && left_interface == right_interface,
        _ => false,
    }
}

fn bypass_resource(
    platform: Platform,
    peer: IpAddr,
    path: &PeerPath,
) -> Result<Option<OwnedResource>> {
    let prefix = IpNet::new(peer, if peer.is_ipv4() { 32 } else { 128 })?;
    if let (Platform::Linux, PeerPath::Linux(path)) = (platform, path)
        && path.parent.prefix == prefix
    {
        return Ok(None);
    }
    let target = match (platform, path) {
        (Platform::Linux, PeerPath::Linux(path)) => RouteTarget::Linux {
            table: path.parent.table,
            source_prefix: path.parent.source_prefix,
            source: Some(path.source),
            nexthops: path.parent.nexthops.clone(),
            metric: ROUTE_METRIC,
        },
        (Platform::Macos, PeerPath::Macos { gateway, .. }) => RouteTarget::MacosGateway {
            gateway: gateway.clone(),
        },
        (
            Platform::Windows,
            PeerPath::Windows {
                next_hop,
                interface_index,
            },
        ) => RouteTarget::Windows {
            interface_index: *interface_index,
            next_hop: *next_hop,
            metric: ROUTE_METRIC,
        },
        _ => bail!("peer route path does not belong to {platform:?}"),
    };
    Ok(Some(OwnedResource::Route { prefix, target }))
}

fn path_uses_tunnel(path: &PeerPath, tunnel: &TunnelIdentity) -> bool {
    match path {
        PeerPath::Linux(path) => path
            .parent
            .nexthops
            .iter()
            .any(|nexthop| nexthop.interface == tunnel.name),
        PeerPath::Macos { interface, .. } => interface.as_ref() == Some(&tunnel.name),
        PeerPath::Windows {
            interface_index, ..
        } => *interface_index == tunnel.index,
    }
}

fn path_is_available<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    path: &PeerPath,
) -> Result<bool> {
    let command = match (platform, path) {
        (Platform::Linux, PeerPath::Linux(path)) => {
            return linux_parent_route_is_present(executor, &path.parent);
        }
        (
            Platform::Macos,
            PeerPath::Macos {
                interface: Some(interface),
                ..
            },
        ) => CommandSpec::new("ifconfig", [interface]),
        (
            Platform::Macos,
            PeerPath::Macos {
                interface: None, ..
            },
        ) => return Ok(false),
        (
            Platform::Windows,
            PeerPath::Windows {
                interface_index, ..
            },
        ) => powershell(format!(
            "$adapter = Get-NetAdapter -InterfaceIndex {interface_index} \
                 -ErrorAction SilentlyContinue; \
             if ($null -ne $adapter -and $adapter.Status -eq 'Up') {{ 'available' }}"
        )),
        _ => bail!("peer path does not belong to {platform:?}"),
    };
    let output = executor.execute(&command)?;
    if !output.success {
        return Ok(false);
    }
    match platform {
        Platform::Linux => Ok(output.stdout.contains("state UP")
            || output
                .stdout
                .lines()
                .next()
                .is_some_and(|line| line.contains("<") && line.contains("UP"))),
        Platform::Macos => Ok(output.stdout.contains("status: active")),
        Platform::Windows => Ok(output.stdout.trim() == "available"),
    }
}

fn lookup_linux_peer_path<E: CommandExecutor>(
    executor: &E,
    transport: TransportSocket,
) -> Result<LinuxPeerPath> {
    let initial_rules = linux_policy_rules(executor, transport.peer.ip().is_ipv6())?;
    let parent_output = run_required(executor, &linux_route_lookup_command(transport, true))?;
    let resolved_output = run_required(executor, &linux_route_lookup_command(transport, false))?;
    let final_rules = linux_policy_rules(executor, transport.peer.ip().is_ipv6())?;
    if initial_rules != final_rules {
        bail!("Linux policy-routing rules changed during WebSocket route discovery");
    }

    let parent = exactly_one_linux_route(
        parse_linux_route_records(&parent_output, transport.peer.is_ipv6(), None)?,
        "matched parent route",
    )?;
    let resolved = exactly_one_linux_route(
        parse_linux_route_records(&resolved_output, transport.peer.is_ipv6(), None)?,
        "resolved WebSocket route",
    )?;
    validate_linux_parent_route(&parent, &resolved, transport)?;
    Ok(LinuxPeerPath {
        parent,
        policy_rules: initial_rules,
        source: transport.local.ip(),
    })
}

fn linux_route_lookup_command(transport: TransportSocket, fibmatch: bool) -> CommandSpec {
    let mut arguments = vec![
        "-j".to_string(),
        "-details".to_string(),
        "-N".to_string(),
        if transport.peer.is_ipv4() {
            "-4".to_string()
        } else {
            "-6".to_string()
        },
        "route".to_string(),
        "get".to_string(),
        transport.peer.ip().to_string(),
        "from".to_string(),
        transport.local.ip().to_string(),
        "ipproto".to_string(),
        LINUX_TCP_PROTOCOL.to_string(),
        "sport".to_string(),
        transport.local.port().to_string(),
        "dport".to_string(),
        transport.peer.port().to_string(),
    ];
    if fibmatch {
        arguments.push("fibmatch".to_string());
    }
    CommandSpec::new("ip", arguments)
}

fn linux_policy_rules<E: CommandExecutor>(executor: &E, ipv6: bool) -> Result<serde_json::Value> {
    let output = run_required(
        executor,
        &CommandSpec::new(
            "ip",
            [
                "-j",
                "-details",
                "-N",
                if ipv6 { "-6" } else { "-4" },
                "rule",
                "show",
            ],
        ),
    )?;
    let rules: serde_json::Value =
        serde_json::from_str(output.trim()).context("failed to decode Linux policy rules")?;
    if !rules.is_array() {
        bail!("Linux returned a non-array policy-rule inventory");
    }
    Ok(rules)
}

fn exactly_one_linux_route(
    mut records: Vec<LinuxRouteRecord>,
    label: &str,
) -> Result<LinuxRouteRecord> {
    if records.len() != 1 {
        bail!(
            "Linux returned {} records for the {label}; expected exactly one",
            records.len()
        );
    }
    Ok(records.remove(0))
}

fn validate_linux_parent_route(
    parent: &LinuxRouteRecord,
    resolved: &LinuxRouteRecord,
    transport: TransportSocket,
) -> Result<()> {
    if parent.route_type != 1 || resolved.route_type != 1 {
        bail!("the WebSocket peer does not use a unicast Linux route");
    }
    validate_linux_route_table(parent.table)?;
    if parent.table != resolved.table {
        bail!("Linux resolved the WebSocket peer through an inconsistent route table");
    }
    if !parent.matches_destination(transport.peer.ip(), transport.local.ip()) {
        bail!("Linux returned a parent route that does not match the WebSocket socket");
    }
    if resolved.nexthops.len() != 1 || parent.nexthops.is_empty() {
        bail!("Linux did not resolve one concrete WebSocket nexthop");
    }
    let selected = &resolved.nexthops[0];
    if !parent.nexthops.iter().any(|nexthop| {
        nexthop.gateway == selected.gateway && nexthop.interface == selected.interface
    }) {
        bail!("Linux resolved a WebSocket nexthop outside its matched parent route");
    }
    for nexthop in &parent.nexthops {
        validate_gateway_family(parent.prefix, nexthop.gateway)?;
    }
    ensure_supported_linux_route_flags(&parent.identity)?;
    if parent.identity.get("encap").is_some()
        || parent.identity.get("encap_type").is_some()
        || parent.identity.get("newdst").is_some()
    {
        bail!("the WebSocket parent route uses unsupported Linux encapsulation");
    }
    Ok(())
}

fn ensure_supported_linux_route_flags(identity: &serde_json::Value) -> Result<()> {
    let object = identity
        .as_object()
        .context("Linux returned a non-object route identity")?;
    if let Some(flags) = object.get("flags") {
        ensure_supported_linux_flags(flags)?;
    }
    if let Some(nexthops) = object.get("nexthops") {
        for nexthop in nexthops
            .as_array()
            .context("Linux returned non-array route nexthops")?
        {
            if let Some(flags) = nexthop.get("flags") {
                ensure_supported_linux_flags(flags)?;
            }
        }
    }
    Ok(())
}

fn ensure_supported_linux_flags(value: &serde_json::Value) -> Result<()> {
    for flag in parse_linux_route_flags(value)? {
        if flag != "onlink" && flag != "pervasive" {
            bail!("the WebSocket parent route uses unsupported Linux flag `{flag}`");
        }
    }
    Ok(())
}

fn linux_parent_route_is_present<E: CommandExecutor>(
    executor: &E,
    parent: &LinuxRouteRecord,
) -> Result<bool> {
    let records = linux_routes_for_exact_prefix(executor, parent.prefix, parent.table)?;
    Ok(records
        .iter()
        .any(|candidate| candidate.identity == parent.identity))
}

fn lookup_peer_path<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    transport: TransportSocket,
) -> Result<PeerPath> {
    let peer = transport.peer.ip();
    match platform {
        Platform::Linux => lookup_linux_peer_path(executor, transport).map(PeerPath::Linux),
        Platform::Macos => {
            let output = run_required(
                executor,
                &CommandSpec::new(
                    "route",
                    [
                        "-n",
                        "get",
                        if peer.is_ipv4() { "-inet" } else { "-inet6" },
                        &peer.to_string(),
                    ],
                ),
            )?;
            parse_macos_peer_path(&output)
        }
        Platform::Windows => {
            let output = run_required(executor, &find_windows_route(peer))?;
            parse_windows_peer_path(&output)
        }
    }
}

fn lookup_default_path<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    ipv6: bool,
) -> Result<Option<PeerPath>> {
    let command = match platform {
        Platform::Linux => bail!("Linux bypass reconciliation does not use a default-route probe"),
        Platform::Macos => CommandSpec::new(
            "route",
            [
                "-n",
                "get",
                if ipv6 { "-inet6" } else { "-inet" },
                "default",
            ],
        ),
        Platform::Windows => find_windows_default_route(ipv6),
    };
    let output = executor.execute(&command)?;
    if !output.success {
        return Ok(None);
    }
    if output.stdout.trim().is_empty() {
        return Ok(None);
    }
    match platform {
        Platform::Linux => unreachable!("Linux returned before executing a default-route probe"),
        Platform::Macos => parse_macos_peer_path(&output.stdout).map(Some),
        Platform::Windows => parse_windows_peer_path(&output.stdout).map(Some),
    }
}

fn parse_macos_peer_path(output: &str) -> Result<PeerPath> {
    let gateway = macos_route_value(output, "gateway")
        .context("`route get` output did not identify a gateway")?
        .to_string();
    validate_macos_gateway(&gateway)?;
    let interface = macos_route_value(output, "interface").map(ToString::to_string);
    Ok(PeerPath::Macos { gateway, interface })
}

fn parse_windows_peer_path(output: &str) -> Result<PeerPath> {
    let route: WindowsRoutePath =
        serde_json::from_str(output.trim()).context("failed to decode Windows route lookup")?;
    Ok(PeerPath::Windows {
        next_hop: normalize_ip(
            route
                .next_hop
                .parse()
                .context("Windows returned an invalid route next hop")?,
        ),
        interface_index: route.interface_index,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsRoutePath {
    interface_index: u32,
    next_hop: String,
}

fn inventory_routes<E: CommandExecutor>(platform: Platform, executor: &E) -> Result<Vec<IpNet>> {
    let outputs = match platform {
        Platform::Linux => vec![
            run_required(
                executor,
                &CommandSpec::new("ip", ["-o", "-4", "route", "show", "table", "all"]),
            )?,
            run_required(
                executor,
                &CommandSpec::new("ip", ["-o", "-6", "route", "show", "table", "all"]),
            )?,
        ],
        Platform::Macos => vec![
            run_required(
                executor,
                &CommandSpec::new("netstat", ["-rn", "-f", "inet"]),
            )?,
            run_required(
                executor,
                &CommandSpec::new("netstat", ["-rn", "-f", "inet6"]),
            )?,
        ],
        Platform::Windows => vec![run_required(executor, &windows_route_inventory_command())?],
    };

    let mut routes = match platform {
        Platform::Linux => outputs
            .iter()
            .enumerate()
            .flat_map(|(index, output)| parse_linux_route_inventory(output, index == 1))
            .collect(),
        Platform::Macos => outputs
            .iter()
            .enumerate()
            .flat_map(|(index, output)| parse_macos_route_inventory(output, index == 1))
            .collect(),
        Platform::Windows => parse_windows_route_inventory(&outputs[0])?,
    };
    routes.sort();
    routes.dedup();
    Ok(routes)
}

fn inventory_linux_route_records<E: CommandExecutor>(
    executor: &E,
) -> Result<Vec<LinuxRouteRecord>> {
    let ipv4 = run_required(
        executor,
        &CommandSpec::new(
            "ip",
            [
                "-j", "-details", "-N", "-4", "route", "show", "table", "all",
            ],
        ),
    )?;
    let ipv6 = run_required(
        executor,
        &CommandSpec::new(
            "ip",
            [
                "-j", "-details", "-N", "-6", "route", "show", "table", "all",
            ],
        ),
    )?;
    let mut records = parse_linux_route_records(&ipv4, false, None)?;
    records.extend(parse_linux_route_records(&ipv6, true, None)?);
    Ok(records)
}

fn select_linux_replacement_parent(
    inventory: &[LinuxRouteRecord],
    transport: TransportSocket,
    table: u32,
    owned_resources: &[OwnedResource],
) -> Result<LinuxRouteRecord> {
    let mut candidates = inventory
        .iter()
        .filter(|route| route.table == table)
        .filter(|route| route.matches_destination(transport.peer.ip(), transport.local.ip()))
        .filter(|route| !linux_route_matches_any_resource(route, owned_resources))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| std::cmp::Reverse(linux_route_precedence(candidate)));
    let Some(parent) = candidates.first().cloned() else {
        bail!(
            "the WebSocket peer {} no longer has a route in Linux table {table}",
            transport.peer.ip()
        );
    };
    let precedence = linux_route_precedence(&parent);
    if candidates
        .iter()
        .skip(1)
        .any(|candidate| linux_route_precedence(candidate) == precedence)
    {
        bail!(
            "Linux table {table} contains ambiguous replacement routes for WebSocket peer {}",
            transport.peer.ip()
        );
    }
    validate_linux_replacement_parent(&parent, transport, table)?;
    Ok(parent)
}

fn linux_route_precedence(route: &LinuxRouteRecord) -> (u8, u8, std::cmp::Reverse<u32>) {
    (
        route.prefix.prefix_len(),
        route.source_prefix.map_or(0, |source| source.prefix_len()),
        std::cmp::Reverse(route.metric),
    )
}

fn validate_linux_replacement_parent(
    parent: &LinuxRouteRecord,
    transport: TransportSocket,
    table: u32,
) -> Result<()> {
    if parent.route_type != 1 || parent.table != table || parent.nexthops.is_empty() {
        bail!("the replacement Linux WebSocket route is not a usable unicast route");
    }
    if !parent.matches_destination(transport.peer.ip(), transport.local.ip()) {
        bail!("the replacement Linux route does not match the WebSocket socket");
    }
    for nexthop in &parent.nexthops {
        validate_gateway_family(parent.prefix, nexthop.gateway)?;
    }
    ensure_supported_linux_route_flags(&parent.identity)?;
    if parent.identity.get("encap").is_some()
        || parent.identity.get("encap_type").is_some()
        || parent.identity.get("newdst").is_some()
    {
        bail!("the replacement WebSocket route uses unsupported Linux encapsulation");
    }
    Ok(())
}

fn linux_route_matches_any_resource(route: &LinuxRouteRecord, resources: &[OwnedResource]) -> bool {
    resources.iter().any(|resource| match resource {
        OwnedResource::Route {
            prefix,
            target:
                RouteTarget::Linux {
                    table,
                    source_prefix,
                    source,
                    nexthops,
                    metric,
                },
        } => {
            route.prefix == *prefix
                && route.table == *table
                && route.source_prefix == *source_prefix
                && route.route_type == 1
                && route.preferred_source == *source
                && route.nexthops == *nexthops
                && route.metric == *metric
        }
        _ => false,
    })
}

fn linux_route_is_session_owned(
    route: &LinuxRouteRecord,
    resources: &[OwnedResource],
    tunnel: &TunnelIdentity,
    network: VpnNetworkConfiguration,
) -> bool {
    if linux_route_matches_any_resource(route, resources) {
        return true;
    }
    if route.protocol != Some(2)
        || !matches!(
            route.table,
            LINUX_MAIN_ROUTE_TABLE | LINUX_LOCAL_ROUTE_TABLE
        )
        || route.nexthops.len() != 1
        || route.nexthops[0].interface != tunnel.name
    {
        return false;
    }
    let point_to_point = if route.prefix.addr().is_ipv4() {
        IpNet::V4(network.point_to_point_ipv4)
    } else {
        IpNet::V6(network.point_to_point_ipv6)
    };
    route.prefix == point_to_point
        || (route.prefix.prefix_len() == route.prefix.max_prefix_len()
            && point_to_point.contains(&route.prefix.addr()))
}

fn immutable_session_networks(network: VpnNetworkConfiguration) -> Vec<IpNet> {
    let mut networks = vec![
        IpNet::V4(network.point_to_point_ipv4),
        IpNet::V6(network.point_to_point_ipv6),
    ];
    if let Some(synthetic) = network.synthetic {
        networks.extend(synthetic.routes());
    }
    networks
}

fn first_linux_route_collision<'a>(
    inventory: &'a [LinuxRouteRecord],
    resources: &[OwnedResource],
    tunnel: &TunnelIdentity,
    network: VpnNetworkConfiguration,
) -> Option<&'a LinuxRouteRecord> {
    let immutable = immutable_session_networks(network);
    inventory.iter().find(|route| {
        route.prefix.prefix_len() > 0
            && !linux_route_is_session_owned(route, resources, tunnel, network)
            && immutable
                .iter()
                .any(|network| networks_overlap(route.prefix, *network))
    })
}

fn networks_overlap(left: IpNet, right: IpNet) -> bool {
    if left.addr().is_ipv4() != right.addr().is_ipv4() {
        return false;
    }
    left.contains(&right.network()) || right.contains(&left.network())
}

fn parse_linux_route_inventory(output: &str, ipv6: bool) -> Vec<IpNet> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let first = fields.next()?;
            let destination = if linux_route_type(first) {
                fields.next()?
            } else {
                first
            };
            parse_route_destination(destination, ipv6)
        })
        .collect()
}

fn linux_route_type(value: &str) -> bool {
    matches!(
        value,
        "local"
            | "broadcast"
            | "unreachable"
            | "prohibit"
            | "blackhole"
            | "throw"
            | "nat"
            | "multicast"
    )
}

fn parse_macos_route_inventory(output: &str, ipv6: bool) -> Vec<IpNet> {
    let mut in_table = false;
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("Destination") {
                in_table = true;
                return None;
            }
            if !in_table || trimmed.is_empty() {
                return None;
            }
            let destination = trimmed.split_whitespace().next()?;
            parse_macos_destination(destination, ipv6)
        })
        .collect()
}

fn parse_macos_destination(value: &str, ipv6: bool) -> Option<IpNet> {
    if value == "default" {
        return if ipv6 {
            "::/0".parse().ok()
        } else {
            "0.0.0.0/0".parse().ok()
        };
    }
    if ipv6 {
        let without_scope = remove_ipv6_scope(value);
        return parse_route_destination(&without_scope, true);
    }
    if let Ok(network) = value.parse::<IpNet>() {
        return Some(network.trunc());
    }

    let (address, explicit_prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let octets = address.split('.').collect::<Vec<_>>();
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    let mut expanded = [0_u8; 4];
    for (index, octet) in octets.iter().enumerate() {
        expanded[index] = octet.parse().ok()?;
    }
    let prefix = explicit_prefix
        .map(str::parse::<u8>)
        .transpose()
        .ok()?
        .unwrap_or((octets.len() * 8) as u8);
    Ipv4Net::new(Ipv4Addr::from(expanded), prefix)
        .ok()
        .map(IpNet::V4)
        .map(|network| network.trunc())
}

fn parse_windows_route_inventory(output: &str) -> Result<Vec<IpNet>> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    let prefixes = if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<String>>(trimmed)
            .context("failed to decode the Windows route inventory")?
    } else {
        vec![
            serde_json::from_str::<String>(trimmed)
                .context("failed to decode the Windows route inventory")?,
        ]
    };
    prefixes
        .iter()
        .map(|prefix| {
            prefix
                .parse::<IpNet>()
                .map(|network| network.trunc())
                .with_context(|| format!("Windows returned invalid route prefix `{prefix}`"))
        })
        .collect()
}

fn parse_route_destination(value: &str, ipv6: bool) -> Option<IpNet> {
    if value == "default" {
        return if ipv6 {
            "::/0".parse().ok()
        } else {
            "0.0.0.0/0".parse().ok()
        };
    }
    if let Ok(network) = value.parse::<IpNet>() {
        return Some(network.trunc());
    }
    let address = value.parse::<IpAddr>().ok()?;
    IpNet::new(address, if address.is_ipv4() { 32 } else { 128 }).ok()
}

fn remove_ipv6_scope(value: &str) -> String {
    let Some(percent) = value.find('%') else {
        return value.to_string();
    };
    let suffix = value[percent..].find('/').map(|offset| percent + offset);
    match suffix {
        Some(slash) => format!("{}{}", &value[..percent], &value[slash..]),
        None => value[..percent].to_string(),
    }
}

fn macos_route_matches<E: CommandExecutor>(
    executor: &E,
    prefix: IpNet,
    gateway: Option<&str>,
    interface: Option<&str>,
) -> Result<bool> {
    let output = executor.execute(&CommandSpec::new(
        "route",
        [
            "-n",
            "get",
            macos_family_flag(prefix),
            &prefix.addr().to_string(),
        ],
    ))?;
    if !output.success {
        if ["not in table", "No such process"]
            .iter()
            .any(|marker| output.stderr.contains(marker) || output.stdout.contains(marker))
        {
            return Ok(false);
        }
        let detail = if output.stderr.trim().is_empty() {
            output.stdout.trim()
        } else {
            output.stderr.trim()
        };
        bail!("failed to inspect macOS route `{prefix}`: {detail}");
    }
    if !macos_destination_matches(&output.stdout, prefix) {
        return Ok(false);
    }
    let gateway_matches = gateway
        .is_none_or(|expected| macos_route_value(&output.stdout, "gateway") == Some(expected));
    let interface_matches = interface
        .is_none_or(|expected| macos_route_value(&output.stdout, "interface") == Some(expected));
    Ok(gateway_matches && interface_matches)
}

fn macos_destination_matches(output: &str, prefix: IpNet) -> bool {
    let Some(destination) = macos_route_value(output, "destination") else {
        return false;
    };
    if destination == "default" {
        return prefix.prefix_len() == 0;
    }
    if let Some(parsed) = parse_macos_destination(destination, prefix.addr().is_ipv6())
        && parsed == prefix
    {
        return true;
    }
    let Ok(address) = remove_ipv6_scope(destination).parse::<IpAddr>() else {
        return false;
    };
    if address != prefix.addr() {
        return false;
    }
    if prefix.prefix_len() == prefix.max_prefix_len() {
        return true;
    }
    let Some(mask) = macos_route_value(output, "mask") else {
        return false;
    };
    macos_mask_prefix_len(mask, prefix.addr().is_ipv6()) == Some(prefix.prefix_len())
}

fn macos_mask_prefix_len(mask: &str, ipv6: bool) -> Option<u8> {
    if let Some(hexadecimal) = mask.strip_prefix("0x") {
        let value = u128::from_str_radix(hexadecimal, 16).ok()?;
        let width = if ipv6 { 128 } else { 32 };
        let aligned = value << (128 - width);
        let prefix = aligned.leading_ones() as u8;
        let expected = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        return (aligned == expected).then_some(prefix);
    }
    let address = remove_ipv6_scope(mask).parse::<IpAddr>().ok()?;
    match address {
        IpAddr::V4(mask) => contiguous_prefix_len(u128::from(u32::from(mask)), 32),
        IpAddr::V6(mask) => contiguous_prefix_len(u128::from(mask), 128),
    }
}

fn contiguous_prefix_len(value: u128, width: u8) -> Option<u8> {
    let aligned = value << (128 - width);
    let prefix = aligned.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (aligned == expected).then_some(prefix)
}

fn macos_route_value<'a>(output: &'a str, name: &str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then_some(value.trim())
    })
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

fn ip_family_flag(prefix: IpNet) -> &'static str {
    if prefix.addr().is_ipv4() { "-4" } else { "-6" }
}

fn macos_family_flag(prefix: IpNet) -> &'static str {
    if prefix.addr().is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    }
}

fn macos_route_kind(prefix: IpNet) -> &'static str {
    if prefix.prefix_len() == prefix.max_prefix_len() {
        "-host"
    } else {
        "-net"
    }
}

fn powershell(script: impl Into<String>) -> CommandSpec {
    let script = format!(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); {}",
        script.into()
    );
    CommandSpec::new(
        "powershell.exe",
        [
            "-NoLogo".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            script,
        ],
    )
}

fn find_windows_route(peer: IpAddr) -> CommandSpec {
    powershell(format!(
        "$source, $route = Find-NetRoute -RemoteIPAddress '{peer}' -ErrorAction Stop; \
         if ($null -eq $route) {{ throw 'No route found' }}; \
         [pscustomobject]@{{InterfaceIndex=$route.InterfaceIndex;NextHop=$route.NextHop}} \
         | ConvertTo-Json -Compress"
    ))
}

fn find_windows_default_route(ipv6: bool) -> CommandSpec {
    let family = if ipv6 { "IPv6" } else { "IPv4" };
    let prefix = if ipv6 { "::/0" } else { "0.0.0.0/0" };
    powershell(format!(
        "$route = Get-NetRoute -AddressFamily {family} -DestinationPrefix '{prefix}' \
             -PolicyStore ActiveStore -ErrorAction Stop \
             | Sort-Object @{{Expression={{$_.RouteMetric + $_.InterfaceMetric}}}} \
             | Select-Object -First 1; \
         if ($null -eq $route) {{ throw 'No default route found' }}; \
         [pscustomobject]@{{InterfaceIndex=$route.InterfaceIndex;NextHop=$route.NextHop}} \
         | ConvertTo-Json -Compress"
    ))
}

fn windows_route_inventory_command() -> CommandSpec {
    powershell(
        "Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop \
         | ForEach-Object { $_.DestinationPrefix } | ConvertTo-Json -Compress",
    )
}

#[derive(Clone, Debug)]
struct JournalStore {
    path: PathBuf,
    #[cfg(unix)]
    owner_uid: u32,
}

impl JournalStore {
    fn production() -> Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return Ok(Self {
            path: PathBuf::from("/var/run/sshportal/network-state.jsonl"),
            owner_uid: 0,
        });
        #[cfg(target_os = "windows")]
        {
            let output = run_required(
                &SystemCommandExecutor,
                &powershell("[Environment]::GetFolderPath('CommonApplicationData')"),
            )?;
            let program_data = output.trim();
            if program_data.is_empty() {
                bail!("Windows returned an empty common application-data directory");
            }
            Ok(Self {
                path: PathBuf::from(program_data)
                    .join("SSHPortal")
                    .join("network-state.jsonl"),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        bail!("VPN routing is supported only on Linux, macOS, and Windows");
    }

    fn begin(&self, header: &JournalHeader) -> Result<()> {
        self.ensure_parent()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path).with_context(|| {
            format!(
                "failed to create VPN recovery journal {}; another VPN session may be active",
                self.path.display()
            )
        })?;
        #[cfg(target_os = "windows")]
        if let Err(error) = secure_windows_path(&self.path) {
            drop(file);
            let _ignored = fs::remove_file(&self.path);
            return Err(error).context("failed to secure the VPN recovery journal");
        }
        let result = write_journal_record(&mut file, &JournalRecord::Header(header.clone()))
            .and_then(|()| {
                file.sync_all()
                    .context("failed to sync VPN recovery journal")
            });
        if let Err(error) = result {
            drop(file);
            return match self.remove() {
                Ok(()) => Err(error).context("failed to initialize VPN recovery journal"),
                Err(remove_error) => Err(error).context(format!(
                    "failed to initialize VPN recovery journal; removing the incomplete journal also failed: {remove_error:#}"
                )),
            };
        }
        Ok(())
    }

    fn arm(&self, resource: &OwnedResource) -> Result<()> {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .context("failed to reopen VPN recovery journal")?;
        write_journal_record(&mut file, &JournalRecord::Resource(resource.clone()))?;
        file.sync_all()
            .context("failed to sync VPN recovery journal")
    }

    fn load(&self) -> Result<Option<SessionJournal>> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).context("failed to inspect the VPN recovery journal");
            }
        }
        self.validate_existing_file()?;
        let mut contents = String::new();
        File::open(&self.path)
            .context("failed to open the VPN recovery journal")?
            .take(MAX_JOURNAL_BYTES + 1)
            .read_to_string(&mut contents)
            .context("failed to read the VPN recovery journal")?;
        if contents.len() as u64 > MAX_JOURNAL_BYTES {
            bail!("VPN recovery journal exceeds its size limit");
        }
        if !contents.ends_with('\n') {
            if let Some((complete, _partial)) = contents.rsplit_once('\n') {
                contents.truncate(complete.len() + 1);
            } else {
                bail!("VPN recovery journal contains no complete record");
            }
        }

        let mut records = contents.lines();
        let header = match records.next() {
            Some(line) => match serde_json::from_str::<JournalRecord>(line)
                .context("failed to decode VPN recovery journal header")?
            {
                JournalRecord::Header(header) => header,
                JournalRecord::Resource(_) => bail!("VPN recovery journal has no header"),
            },
            None => bail!("VPN recovery journal is empty"),
        };
        let mut resources = Vec::new();
        for line in records {
            match serde_json::from_str::<JournalRecord>(line)
                .context("failed to decode a VPN recovery journal record")?
            {
                JournalRecord::Header(_) => bail!("VPN recovery journal contains two headers"),
                JournalRecord::Resource(resource) => resources.push(resource),
            }
        }
        Ok(Some(SessionJournal { header, resources }))
    }

    fn remove(&self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("failed to remove VPN recovery journal"),
        }
    }

    fn ensure_parent(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("VPN recovery journal path has no parent directory")?;
        #[cfg(not(target_os = "windows"))]
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create VPN recovery journal directory {}",
                parent.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = fs::symlink_metadata(parent).with_context(|| {
                format!(
                    "failed to inspect VPN recovery journal directory {}",
                    parent.display()
                )
            })?;
            if !metadata.file_type().is_dir() {
                bail!("VPN recovery journal directory is not a real directory");
            }
            if metadata.uid() != self.owner_uid {
                bail!("VPN recovery journal directory has an untrusted owner");
            }
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).with_context(|| {
                format!(
                    "failed to secure VPN recovery journal directory {}",
                    parent.display()
                )
            })?;
            validate_unix_journal_directory(parent, self.owner_uid)?;
        }
        #[cfg(target_os = "windows")]
        {
            if parent.exists() {
                validate_windows_journal_directory(parent)?;
            } else {
                fs::create_dir(parent).with_context(|| {
                    format!(
                        "failed to create VPN recovery journal directory {}",
                        parent.display()
                    )
                })?;
                secure_windows_path(parent)?;
                validate_windows_journal_directory(parent)?;
            }
        }
        Ok(())
    }

    fn validate_existing_file(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("VPN recovery journal path has no parent directory")?;
        #[cfg(unix)]
        validate_unix_journal_directory(parent, self.owner_uid)?;
        #[cfg(target_os = "windows")]
        validate_windows_journal_directory(parent)?;
        let metadata = fs::symlink_metadata(&self.path)
            .context("failed to inspect the VPN recovery journal")?;
        if !metadata.file_type().is_file() {
            bail!("VPN recovery journal is not a regular file");
        }
        if metadata.len() > MAX_JOURNAL_BYTES {
            bail!("VPN recovery journal exceeds its size limit");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != self.owner_uid {
                bail!("VPN recovery journal has an untrusted owner");
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("VPN recovery journal permissions are not private");
            }
        }
        #[cfg(target_os = "windows")]
        {
            let length = metadata.len();
            let output = run_required(
                &SystemCommandExecutor,
                &powershell(format!(
                    "$item = Get-Item -LiteralPath '{}' -Force -ErrorAction Stop; \
                     if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ \
                         throw 'VPN recovery journal is a reparse point' \
                     }}; $item.Length",
                    self.path
                        .to_str()
                        .context("VPN recovery journal path is not valid Unicode")?
                        .replace('\'', "''")
                )),
            )?;
            let windows_length = output
                .trim()
                .parse::<u64>()
                .context("Windows returned an invalid VPN recovery journal length")?;
            if windows_length != length {
                bail!("VPN recovery journal changed while it was being validated");
            }
            validate_windows_path_security(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn validate_unix_journal_directory(path: &Path, owner_uid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect VPN journal directory {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!("VPN recovery journal directory is not a real directory");
    }
    if metadata.uid() != owner_uid {
        bail!("VPN recovery journal directory has an untrusted owner");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("VPN recovery journal directory permissions are not private");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn secure_windows_path(path: &Path) -> Result<()> {
    let path = path
        .to_str()
        .context("VPN recovery journal path is not valid Unicode")?;
    for arguments in [
        vec![path, "/inheritance:r"],
        vec![path, "/setowner", "*S-1-5-32-544", "/C"],
        vec![path, "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "/C"],
    ] {
        run_required(
            &SystemCommandExecutor,
            &CommandSpec::new("icacls.exe", arguments),
        )?;
    }
    validate_windows_path_security(Path::new(path))
}

#[cfg(target_os = "windows")]
fn validate_windows_path_security(path: &Path) -> Result<()> {
    let literal = path
        .to_str()
        .context("VPN recovery journal path is not valid Unicode")?
        .replace('\'', "''");
    let script = format!(
        "$acl = Get-Acl -LiteralPath '{literal}' -ErrorAction Stop; \
         $owner = $acl.Owner; \
         try {{ \
             $owner = ([System.Security.Principal.NTAccount]$owner).Translate( \
                 [System.Security.Principal.SecurityIdentifier]).Value \
         }} catch {{}}; \
         $allowed = @('S-1-5-18','S-1-5-32-544'); \
         $write = [int][System.Security.AccessControl.FileSystemRights]::Write \
             -bor [int][System.Security.AccessControl.FileSystemRights]::Delete \
             -bor [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions \
             -bor [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership; \
         $unsafe = @($acl.Access | Where-Object {{ \
             $sid = $_.IdentityReference; \
             try {{ \
                 $sid = $_.IdentityReference.Translate( \
                     [System.Security.Principal.SecurityIdentifier]).Value \
             }} catch {{}}; \
             $_.AccessControlType -eq 'Allow' -and $sid -notin $allowed \
                 -and (([int]$_.FileSystemRights -band $write) -ne 0) \
         }}); \
         if ($owner -in $allowed -and $unsafe.Count -eq 0) {{ 'secure' }}"
    );
    let output = run_required(&SystemCommandExecutor, &powershell(script))?;
    if output.trim() != "secure" {
        bail!(
            "VPN recovery journal path {} is writable by a non-administrator",
            path.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_windows_journal_directory(path: &Path) -> Result<()> {
    let literal = path
        .to_str()
        .context("VPN recovery journal path is not valid Unicode")?
        .replace('\'', "''");
    let output = run_required(
        &SystemCommandExecutor,
        &powershell(format!(
            "$item = Get-Item -LiteralPath '{literal}' -Force -ErrorAction Stop; \
             if ($item.PSIsContainer \
                 -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {{ \
                 'directory' \
             }}"
        )),
    )?;
    if output.trim() != "directory" {
        bail!("VPN recovery journal directory is not a real directory");
    }
    validate_windows_path_security(path)
}

fn write_journal_record(file: &mut File, record: &JournalRecord) -> Result<()> {
    serde_json::to_writer(&mut *file, record).context("failed to encode VPN recovery journal")?;
    file.write_all(b"\n")
        .context("failed to write VPN recovery journal")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "record", content = "value", rename_all = "snake_case")]
enum JournalRecord {
    Header(JournalHeader),
    Resource(OwnedResource),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct JournalHeader {
    version: u8,
    platform: Platform,
    owner_pid: u32,
    owner_identity: String,
    session_id: [u8; 16],
}

#[derive(Clone, Debug)]
struct SessionJournal {
    header: JournalHeader,
    resources: Vec<OwnedResource>,
}

struct SessionIdentity {
    id: [u8; 16],
    process_identity: String,
}

impl SessionIdentity {
    fn new(platform: Platform) -> Result<Self> {
        let mut id = [0_u8; 16];
        rand::fill(&mut id);
        let process_identity = process_identity(platform, std::process::id())?
            .context("failed to determine the VPN process identity")?;
        Ok(Self {
            id,
            process_identity,
        })
    }
}

fn recover_stale_journal<E: CommandExecutor>(
    platform: Platform,
    executor: &E,
    store: &JournalStore,
) -> Result<()> {
    let Some(journal) = store.load()? else {
        return Ok(());
    };
    validate_journal(platform, &journal)?;
    if process_identity(platform, journal.header.owner_pid)?.as_deref()
        == Some(journal.header.owner_identity.as_str())
    {
        bail!(
            "another sshportal VPN session (process {}) still owns the host-network state",
            journal.header.owner_pid
        );
    }

    cleanup_resources(platform, executor, &journal.resources)
        .context("failed to recover host-network state left by an interrupted VPN session")?;
    store.remove()
}

fn validate_journal(platform: Platform, journal: &SessionJournal) -> Result<()> {
    if journal.header.version != JOURNAL_VERSION {
        bail!(
            "unsupported VPN recovery journal version {}",
            journal.header.version
        );
    }
    if journal.header.platform != platform {
        bail!("VPN recovery journal belongs to a different operating system");
    }
    if journal.header.owner_pid == 0 {
        bail!("VPN recovery journal contains an invalid owner process ID");
    }
    if journal.header.owner_identity.is_empty() || journal.header.owner_identity.len() > 256 {
        bail!("VPN recovery journal contains an invalid process identity");
    }
    if journal.resources.len() > MAX_JOURNALED_RESOURCES {
        bail!("VPN recovery journal contains too many resources");
    }
    for resource in &journal.resources {
        validate_resource(platform, resource)?;
        match resource {
            OwnedResource::MacosDns { session_id } | OwnedResource::WindowsNrpt { session_id }
                if *session_id != journal.header.session_id =>
            {
                bail!("VPN recovery journal contains a resource from another session")
            }
            _ => {}
        }
    }
    Ok(())
}

fn process_identity(platform: Platform, pid: u32) -> Result<Option<String>> {
    match platform {
        Platform::Linux => linux_process_identity(pid),
        Platform::Macos => command_process_identity(CommandSpec::new(
            "ps",
            ["-p", &pid.to_string(), "-o", "lstart="],
        )),
        Platform::Windows => command_process_identity(powershell(format!(
            "$process = Get-Process -Id {pid} -ErrorAction SilentlyContinue; \
             if ($null -ne $process) {{ $process.StartTime.ToUniversalTime().Ticks }}"
        ))),
    }
}

fn linux_process_identity(pid: u32) -> Result<Option<String>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect process {pid} for VPN recovery"));
        }
    };
    let closing_parenthesis = contents
        .rfind(')')
        .context("Linux process stat has no command terminator")?;
    let fields = contents[closing_parenthesis + 1..]
        .split_whitespace()
        .collect::<Vec<_>>();
    let start_time = fields
        .get(19)
        .context("Linux process stat has no start time")?;
    Ok(Some((*start_time).to_string()))
}

fn command_process_identity(command: CommandSpec) -> Result<Option<String>> {
    let output = SystemCommandExecutor.execute(&command)?;
    if output.success {
        let identity = output.stdout.trim();
        return if identity.is_empty() {
            Ok(None)
        } else {
            Ok(Some(identity.to_string()))
        };
    }
    if output.stdout.trim().is_empty() && output.stderr.trim().is_empty() {
        return Ok(None);
    }
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    bail!(
        "`{}` failed while inspecting a process: {detail}",
        command.display()
    )
}

fn session_name(session_id: [u8; 16]) -> String {
    let mut encoded = String::with_capacity(32);
    for byte in session_id {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("SSHPortal-{encoded}")
}

#[cfg(target_os = "macos")]
struct MacosDnsPolicy {
    store: SCDynamicStore,
    key: String,
}

#[cfg(target_os = "macos")]
impl MacosDnsPolicy {
    fn install(
        session_id: [u8; 16],
        interface: &str,
        dns: &DnsPlan,
        existing: Option<Self>,
    ) -> Result<Self> {
        let session_name = session_name(session_id);
        let key = format!("State:/Network/Service/{session_name}/DNS");
        let policy = match existing {
            Some(policy) => policy,
            None => Self {
                store: SCDynamicStoreBuilder::new(session_name.as_str())
                    .session_keys(true)
                    .build()
                    .context("failed to open the macOS SystemConfiguration dynamic store")?,
                key,
            },
        };
        let dictionary = macos_dns_dictionary(interface, dns);
        if !policy
            .store
            .set(policy.key.as_str(), dictionary.to_untyped())
        {
            bail!("macOS rejected the VPN DNS configuration");
        }
        Ok(policy)
    }
}

#[cfg(target_os = "macos")]
fn macos_dns_dictionary(interface: &str, dns: &DnsPlan) -> CFDictionary<CFString, CFType> {
    let servers = dns
        .servers
        .iter()
        .map(|server| CFString::new(&server.to_string()))
        .collect::<Vec<_>>();
    let match_domains = match &dns.match_domains {
        DnsMatchDomains::All => vec![CFString::new("")],
        DnsMatchDomains::Selected(domains) => {
            domains.iter().map(|domain| CFString::new(domain)).collect()
        }
    };
    CFDictionary::from_CFType_pairs(&[
        (
            CFString::new("ServerAddresses"),
            CFArray::from_CFTypes(&servers).into_CFType(),
        ),
        (
            CFString::new("InterfaceName"),
            CFString::new(interface).into_CFType(),
        ),
        (
            CFString::new("SupplementalMatchDomains"),
            CFArray::from_CFTypes(&match_domains).into_CFType(),
        ),
        (
            CFString::new("SupplementalMatchDomainsNoSearch"),
            CFNumber::from(1).into_CFType(),
        ),
        (
            CFString::new("SearchOrder"),
            CFNumber::from(1).into_CFType(),
        ),
    ])
}

#[cfg(target_os = "macos")]
fn cleanup_macos_dns(session_id: [u8; 16]) -> Result<()> {
    let session_name = session_name(session_id);
    let store = SCDynamicStoreBuilder::new("SSHPortal recovery")
        .build()
        .context("failed to open macOS SystemConfiguration for VPN DNS cleanup")?;
    let key = format!("State:/Network/Service/{session_name}/DNS");
    if store.get(key.as_str()).is_some()
        && !store.remove(key.as_str())
        && store.get(key.as_str()).is_some()
    {
        bail!("macOS rejected removal of the VPN DNS configuration");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn cleanup_macos_dns(_session_id: [u8; 16]) -> Result<()> {
    bail!("cannot clean a macOS DNS resource on this operating system")
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct MockState {
        calls: Vec<CommandSpec>,
        outputs: VecDeque<Result<CommandOutput>>,
    }

    #[derive(Clone, Default)]
    struct MockExecutor {
        state: Arc<Mutex<MockState>>,
    }

    impl MockExecutor {
        fn with_outputs(outputs: impl IntoIterator<Item = Result<CommandOutput>>) -> Self {
            Self {
                state: Arc::new(Mutex::new(MockState {
                    calls: Vec::new(),
                    outputs: outputs.into_iter().collect(),
                })),
            }
        }

        fn calls(&self) -> Vec<CommandSpec> {
            self.state.lock().unwrap().calls.clone()
        }
    }

    impl CommandExecutor for MockExecutor {
        fn execute(&self, command: &CommandSpec) -> Result<CommandOutput> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(command.clone());
            state
                .outputs
                .pop_front()
                .unwrap_or_else(|| Ok(CommandOutput::success("")))
        }
    }

    fn selected_network(synthetic: bool) -> VpnNetworkConfiguration {
        VpnNetworkConfiguration::select(&[], [7; 16], synthetic).unwrap()
    }

    fn linux_target(interface: &str, gateway: Option<IpAddr>) -> RouteTarget {
        RouteTarget::Linux {
            table: LINUX_MAIN_ROUTE_TABLE,
            source_prefix: None,
            source: None,
            nexthops: vec![LinuxNexthop {
                gateway,
                interface: interface.to_string(),
                weight: 1,
                on_link: false,
                pervasive: false,
            }],
            metric: ROUTE_METRIC,
        }
    }

    fn transport_socket() -> TransportSocket {
        TransportSocket::new(
            "192.0.2.2:8080".parse().unwrap(),
            "203.0.113.8:50000".parse().unwrap(),
        )
        .unwrap()
    }

    fn linux_route_fixture(json: &str) -> LinuxRouteRecord {
        exactly_one_linux_route(
            parse_linux_route_records(json, false, None).unwrap(),
            "test route",
        )
        .unwrap()
    }

    fn macos_route_fixture(prefix: IpNet, gateway: &str, interface: &str) -> String {
        format!(
            "route to: {}\ndestination: {prefix}\ngateway: {gateway}\ninterface: {interface}\n",
            prefix.addr()
        )
    }

    fn journal_store(temp: &TempDir) -> JournalStore {
        JournalStore {
            path: temp.path().join("state.jsonl"),
            #[cfg(unix)]
            owner_uid: {
                use std::os::unix::fs::MetadataExt;

                temp.path().metadata().unwrap().uid()
            },
        }
    }

    #[test]
    fn full_tunnel_forces_dns_through_runtime_synthetic_servers() {
        let network = selected_network(true);
        let plan = RoutePlan::for_policy(&SystemVpnPolicy::full_tunnel(), network).unwrap();
        let dns = plan.dns.unwrap();

        assert_eq!(plan.tunnel_prefixes, SPLIT_DEFAULT_ROUTES);
        assert_eq!(dns.servers, network.synthetic.unwrap().dns_servers());
        assert_eq!(dns.match_domains, DnsMatchDomains::All);
    }

    #[test]
    fn cidr_only_plan_neither_claims_synthetic_routes_nor_changes_dns() {
        let policy = SystemVpnPolicy::new(
            vec![
                "10.20.0.0/16".parse().unwrap(),
                "2001:db8:7::/48".parse().unwrap(),
            ],
            Vec::new(),
        )
        .unwrap();
        let plan = RoutePlan::for_policy(&policy, selected_network(false)).unwrap();

        assert_eq!(
            plan.tunnel_prefixes,
            [
                "10.20.0.0/16".parse().unwrap(),
                "2001:db8:7::/48".parse().unwrap()
            ]
        );
        assert!(plan.dns.is_none());
    }

    #[test]
    fn domain_plan_routes_both_runtime_synthetic_pools_and_scopes_dns() {
        let policy = SystemVpnPolicy::new(
            Vec::new(),
            vec!["anthem.com".to_string(), "elevancehealth.com".to_string()],
        )
        .unwrap();
        let network = selected_network(true);
        let plan = RoutePlan::for_policy(&policy, network).unwrap();

        assert_eq!(plan.tunnel_prefixes, network.synthetic.unwrap().routes());
        assert_eq!(
            plan.dns.unwrap().match_domains,
            DnsMatchDomains::Selected(vec![
                "anthem.com".to_string(),
                "elevancehealth.com".to_string()
            ])
        );
    }

    #[test]
    fn policy_cidrs_are_reserved_from_internal_and_synthetic_address_selection() {
        let entropy = [29; 16];
        let baseline = VpnNetworkConfiguration::select(&[], entropy, true).unwrap();
        let baseline_synthetic = baseline.synthetic.unwrap();
        let policy = SystemVpnPolicy::new(
            vec![
                IpNet::V4(baseline.point_to_point_ipv4),
                IpNet::V4(baseline_synthetic.ipv4),
            ],
            vec!["example.com".to_string()],
        )
        .unwrap();
        let temp = TempDir::new().unwrap();
        let prepared = prepare_with(
            &policy,
            entropy,
            "203.0.113.7".parse().unwrap(),
            Platform::Linux,
            MockExecutor::with_outputs([
                Ok(CommandOutput::success("")),
                Ok(CommandOutput::success("")),
            ]),
            journal_store(&temp),
        )
        .unwrap();
        let selected = prepared.network_configuration();

        assert_ne!(selected.point_to_point_ipv4, baseline.point_to_point_ipv4);
        assert_ne!(selected.synthetic.unwrap().ipv4, baseline_synthetic.ipv4);
    }

    #[test]
    fn websocket_peer_addresses_are_reserved_from_ipv4_and_ipv6_session_pools() {
        let entropy = [31; 16];
        let baseline = VpnNetworkConfiguration::select(&[], entropy, true).unwrap();
        let policy = SystemVpnPolicy::new(Vec::new(), vec!["example.com".to_string()]).unwrap();

        let ipv4_temp = TempDir::new().unwrap();
        let ipv4 = prepare_with(
            &policy,
            entropy,
            IpAddr::V4(baseline.gateway_ipv4),
            Platform::Linux,
            MockExecutor::with_outputs([
                Ok(CommandOutput::success("")),
                Ok(CommandOutput::success("")),
            ]),
            journal_store(&ipv4_temp),
        )
        .unwrap()
        .network_configuration();
        assert!(!ipv4.point_to_point_ipv4.contains(&baseline.gateway_ipv4));

        let ipv6_peer = baseline.synthetic.unwrap().ipv6_first;
        let ipv6_temp = TempDir::new().unwrap();
        let ipv6 = prepare_with(
            &policy,
            entropy,
            IpAddr::V6(ipv6_peer),
            Platform::Linux,
            MockExecutor::with_outputs([
                Ok(CommandOutput::success("")),
                Ok(CommandOutput::success("")),
            ]),
            journal_store(&ipv6_temp),
        )
        .unwrap()
        .network_configuration();
        assert!(!ipv6.synthetic.unwrap().ipv6.contains(&ipv6_peer));
    }

    #[test]
    fn journal_is_complete_before_the_first_mutation_and_cleanup_is_reverse_ordered() {
        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [3; 16],
        };
        let first = OwnedResource::Route {
            prefix: "203.0.113.8/32".parse().unwrap(),
            target: linux_target("eth0", Some("192.0.2.1".parse().unwrap())),
        };
        let second = OwnedResource::Route {
            prefix: "10.20.0.0/16".parse().unwrap(),
            target: linux_target("tun7", None),
        };
        store.begin(&header).unwrap();
        store.arm(&first).unwrap();
        store.arm(&second).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.resources, [first.clone(), second.clone()]);

        let executor = MockExecutor::default();
        cleanup_resources(Platform::Linux, &executor, &loaded.resources).unwrap();
        let calls = executor.calls();
        assert_eq!(calls[0].arguments[3], "10.20.0.0/16");
        assert_eq!(calls[1].arguments[3], "203.0.113.8/32");
    }

    #[test]
    fn cleanup_is_idempotent_when_routes_and_interfaces_already_disappeared() {
        let executor = MockExecutor::with_outputs([
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "RTNETLINK answers: No such process".to_string(),
            }),
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "Cannot find device tun7".to_string(),
            }),
        ]);
        let resources = [
            OwnedResource::LinuxIpv6Address {
                interface: "tun7".to_string(),
                address: "fd00::2".parse().unwrap(),
                gateway: "fd00::1".parse().unwrap(),
                prefix_len: 126,
            },
            OwnedResource::Route {
                prefix: "10.20.0.0/16".parse().unwrap(),
                target: linux_target("tun7", None),
            },
        ];

        cleanup_resources(Platform::Linux, &executor, &resources).unwrap();
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn stale_macos_journal_recovers_after_the_tunnel_and_routes_disappear() {
        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Macos,
            owner_pid: std::process::id(),
            owner_identity: "gone".to_string(),
            session_id: [19; 16],
        };
        let resources = [
            OwnedResource::MacosIpv6Address {
                interface: "utun19".to_string(),
                address: "fd00::2".parse().unwrap(),
                gateway: "fd00::1".parse().unwrap(),
                prefix_len: MACOS_POINT_TO_POINT_IPV6_PREFIX,
            },
            OwnedResource::Route {
                prefix: "198.18.0.0/16".parse().unwrap(),
                target: RouteTarget::MacosInterface {
                    interface: "utun19".to_string(),
                },
            },
            OwnedResource::Route {
                prefix: "fd7f:1234::/96".parse().unwrap(),
                target: RouteTarget::MacosInterface {
                    interface: "utun19".to_string(),
                },
            },
        ];
        store.begin(&header).unwrap();
        for resource in &resources {
            store.arm(resource).unwrap();
        }
        let executor = MockExecutor::with_outputs([
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "route: writing to routing socket: not in table".to_string(),
            }),
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "route: writing to routing socket: not in table".to_string(),
            }),
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "ifconfig: interface utun19 does not exist".to_string(),
            }),
        ]);

        recover_stale_journal(Platform::Macos, &executor, &store).unwrap();

        assert!(!store.path.exists());
        let calls = executor.calls();
        assert_eq!(calls.len(), 3);
        assert!(
            calls
                .iter()
                .all(|call| !call.arguments.contains(&"delete".to_string()))
        );
    }

    #[test]
    fn macos_cleanup_leaves_a_foreign_interface_route_untouched() {
        let prefix = "10.20.0.0/16".parse().unwrap();
        let executor = MockExecutor::with_outputs([Ok(CommandOutput::success(
            macos_route_fixture(prefix, "192.0.2.1", "en0"),
        ))]);
        let target = RouteTarget::MacosInterface {
            interface: "utun19".to_string(),
        };

        cleanup_route(&executor, prefix, &target).unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments[1], "get");
    }

    #[test]
    fn macos_cleanup_leaves_a_foreign_gateway_route_untouched() {
        let prefix = "203.0.113.8/32".parse().unwrap();
        let executor = MockExecutor::with_outputs([Ok(CommandOutput::success(
            macos_route_fixture(prefix, "192.0.2.254", "en0"),
        ))]);
        let target = RouteTarget::MacosGateway {
            gateway: "192.0.2.1".to_string(),
        };

        cleanup_route(&executor, prefix, &target).unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments[1], "get");
    }

    #[test]
    fn macos_cleanup_deletes_the_exact_owned_interface_route() {
        let prefix = "fd7f:1234::/96".parse().unwrap();
        let executor = MockExecutor::with_outputs([
            Ok(CommandOutput::success(macos_route_fixture(
                prefix, "utun19", "utun19",
            ))),
            Ok(CommandOutput::success("")),
        ]);
        let target = RouteTarget::MacosInterface {
            interface: "utun19".to_string(),
        };

        cleanup_route(&executor, prefix, &target).unwrap();

        assert_eq!(
            executor.calls()[1].arguments,
            [
                "-n",
                "delete",
                "-inet6",
                "-net",
                "fd7f:1234::/96",
                "-interface",
                "utun19",
            ]
        );
    }

    #[test]
    fn macos_cleanup_deletes_the_exact_owned_gateway_route() {
        let prefix = "203.0.113.8/32".parse().unwrap();
        let executor = MockExecutor::with_outputs([
            Ok(CommandOutput::success(macos_route_fixture(
                prefix,
                "192.0.2.1",
                "en0",
            ))),
            Ok(CommandOutput::success("")),
        ]);
        let target = RouteTarget::MacosGateway {
            gateway: "192.0.2.1".to_string(),
        };

        cleanup_route(&executor, prefix, &target).unwrap();

        assert_eq!(
            executor.calls()[1].arguments,
            ["-n", "delete", "-inet", "-host", "203.0.113.8", "192.0.2.1",]
        );
    }

    #[test]
    fn macos_cleanup_tolerates_an_owned_route_disappearing_after_inspection() {
        let prefix = "10.20.0.0/16".parse().unwrap();
        let executor = MockExecutor::with_outputs([
            Ok(CommandOutput::success(macos_route_fixture(
                prefix, "utun19", "utun19",
            ))),
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "route: writing to routing socket: not in table".to_string(),
            }),
        ]);
        let target = RouteTarget::MacosInterface {
            interface: "utun19".to_string(),
        };

        cleanup_route(&executor, prefix, &target).unwrap();

        assert_eq!(executor.calls().len(), 2);
    }

    #[test]
    fn macos_cleanup_surfaces_route_inspection_failures() {
        let prefix = "10.20.0.0/16".parse().unwrap();
        let executor = MockExecutor::with_outputs([Ok(CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "route: permission denied".to_string(),
        })]);
        let target = RouteTarget::MacosInterface {
            interface: "utun19".to_string(),
        };

        assert!(cleanup_route(&executor, prefix, &target).is_err());
        assert_eq!(executor.calls().len(), 1);
    }

    #[test]
    fn stale_journal_is_reconciled_before_it_is_removed() {
        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [4; 16],
        };
        let resource = OwnedResource::Route {
            prefix: "203.0.113.8/32".parse().unwrap(),
            target: linux_target("eth0", Some("192.0.2.1".parse().unwrap())),
        };
        store.begin(&header).unwrap();
        store.arm(&resource).unwrap();
        let executor = MockExecutor::default();

        recover_stale_journal(Platform::Linux, &executor, &store).unwrap();

        assert!(!store.path.exists());
        assert_eq!(executor.calls()[0].arguments[2], "del");
    }

    #[test]
    fn failed_stale_cleanup_preserves_the_journal_for_a_later_recovery() {
        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [4; 16],
        };
        let resource = OwnedResource::Route {
            prefix: "203.0.113.8/32".parse().unwrap(),
            target: linux_target("eth0", Some("192.0.2.1".parse().unwrap())),
        };
        store.begin(&header).unwrap();
        store.arm(&resource).unwrap();
        let executor = MockExecutor::with_outputs([Ok(CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "permission denied".to_string(),
        })]);

        assert!(recover_stale_journal(Platform::Linux, &executor, &store).is_err());

        assert!(store.path.exists());
    }

    #[test]
    fn incomplete_trailing_journal_record_is_ignored() {
        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [5; 16],
        };
        store.begin(&header).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&store.path)
            .unwrap()
            .write_all(b"{\"record\":\"res")
            .unwrap();

        let loaded = store.load().unwrap().unwrap();

        assert!(loaded.resources.is_empty());
    }

    #[test]
    fn malformed_complete_journal_record_is_rejected() {
        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [6; 16],
        };
        store.begin(&header).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&store.path)
            .unwrap()
            .write_all(b"not-json\n")
            .unwrap();

        assert!(store.load().is_err());
    }

    #[test]
    fn oversized_journal_is_rejected_before_parsing() {
        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [6; 16],
        };
        store.begin(&header).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&store.path)
            .unwrap()
            .set_len(MAX_JOURNAL_BYTES + 1)
            .unwrap();

        assert!(store.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let target = temp.path().join("attacker-controlled.jsonl");
        fs::write(&target, b"{}\n").unwrap();
        symlink(&target, &store.path).unwrap();

        assert!(store.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_rejects_public_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [7; 16],
        };
        store.begin(&header).unwrap();
        fs::set_permissions(&store.path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(store.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_rejects_public_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [7; 16],
        };
        store.begin(&header).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();

        assert!(store.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_rejects_an_untrusted_owner_expectation() {
        let temp = TempDir::new().unwrap();
        let store = journal_store(&temp);
        let header = JournalHeader {
            version: JOURNAL_VERSION,
            platform: Platform::Linux,
            owner_pid: u32::MAX,
            owner_identity: "gone".to_string(),
            session_id: [7; 16],
        };
        store.begin(&header).unwrap();
        let untrusted = JournalStore {
            path: store.path.clone(),
            owner_uid: store.owner_uid.wrapping_add(1),
        };

        assert!(untrusted.load().is_err());
    }

    #[test]
    fn linux_inventory_parses_typed_and_host_routes_without_mistaking_gateways() {
        let mut routes = parse_linux_route_inventory(
            "default via 192.0.2.1 dev eth0\n\
             10.20.0.0/16 via 192.0.2.9 dev eth0\n\
             local 192.0.2.20 dev eth0 table local\n",
            false,
        );
        routes.extend(parse_linux_route_inventory(
            "unreachable 2001:db8:4::/48 metric 1024\n",
            true,
        ));

        assert_eq!(
            routes,
            [
                "0.0.0.0/0".parse().unwrap(),
                "10.20.0.0/16".parse().unwrap(),
                "192.0.2.20/32".parse().unwrap(),
                "2001:db8:4::/48".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn linux_bypass_preserves_socket_policy_table_source_and_multipath_semantics() {
        let transport = transport_socket();
        let parent = linux_route_fixture(
            r#"[{"type":"1","dst":"203.0.113.0/24","table":"100","protocol":"3","scope":"0","prefsrc":"192.0.2.2","flags":[],"nexthops":[{"gateway":"192.0.2.1","dev":"ethernet0","weight":2,"flags":["onlink"]},{"gateway":"198.51.100.1","dev":"wifi0","weight":3,"flags":[]}]}]"#,
        );
        let resolved = linux_route_fixture(
            r#"[{"type":"1","dst":"203.0.113.8","from":"192.0.2.2","gateway":"192.0.2.1","dev":"ethernet0","table":"100","flags":[],"uid":0,"cache":[]}]"#,
        );
        validate_linux_parent_route(&parent, &resolved, transport).unwrap();
        let path = PeerPath::Linux(LinuxPeerPath {
            parent,
            policy_rules: serde_json::json!([]),
            source: transport.local.ip(),
        });
        let resource = bypass_resource(Platform::Linux, transport.peer.ip(), &path)
            .unwrap()
            .unwrap();
        let OwnedResource::Route { prefix, target } = resource else {
            panic!("Linux bypass did not produce a route");
        };
        let RouteTarget::Linux {
            table,
            source_prefix,
            source,
            nexthops,
            metric,
        } = target
        else {
            panic!("Linux bypass produced another platform's target");
        };

        assert_eq!(table, 100);
        assert_eq!(source, Some(transport.local.ip()));
        assert_eq!(nexthops[0].weight, 2);
        assert!(nexthops[0].on_link);
        assert_eq!(nexthops[1].weight, 3);
        let arguments = linux_route_arguments(
            "add",
            prefix,
            table,
            source_prefix,
            source,
            &nexthops,
            metric,
        );
        assert_eq!(arguments[4..6], ["table", "100"]);
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["src", "192.0.2.2"])
        );
        assert!(arguments.windows(2).any(|pair| pair == ["weight", "2"]));
        assert!(arguments.windows(2).any(|pair| pair == ["weight", "3"]));
        assert!(arguments.contains(&"onlink".to_string()));

        let lookup = linux_route_lookup_command(transport, true);
        assert!(
            lookup
                .arguments
                .windows(2)
                .any(|pair| pair == ["from", "192.0.2.2"])
        );
        assert!(
            lookup
                .arguments
                .windows(2)
                .any(|pair| pair == ["ipproto", "6"])
        );
        assert!(
            lookup
                .arguments
                .windows(2)
                .any(|pair| pair == ["sport", "8080"])
        );
        assert!(
            lookup
                .arguments
                .windows(2)
                .any(|pair| pair == ["dport", "50000"])
        );
        assert_eq!(lookup.arguments.last().unwrap(), "fibmatch");
    }

    #[test]
    fn linux_ipv6_bypass_preserves_source_selector_and_socket_source() {
        let transport = TransportSocket::new(
            "[2001:db8:1::22]:8080".parse().unwrap(),
            "[2001:db8:2::8]:50000".parse().unwrap(),
        )
        .unwrap();
        let parent = exactly_one_linux_route(
            parse_linux_route_records(
                r#"[{"type":"1","dst":"2001:db8:2::/64","from":"2001:db8:1::/64","gateway":"2001:db8:ffff::1","dev":"ethernet0","table":"100","protocol":"3","scope":"0","prefsrc":"2001:db8:1::99","flags":[]}]"#,
                true,
                None,
            )
            .unwrap(),
            "source-specific IPv6 parent route",
        )
        .unwrap();
        let resolved = exactly_one_linux_route(
            parse_linux_route_records(
                r#"[{"type":"1","dst":"2001:db8:2::8","from":"2001:db8:1::22","gateway":"2001:db8:ffff::1","dev":"ethernet0","table":"100","flags":[],"uid":0,"cache":[]}]"#,
                true,
                None,
            )
            .unwrap(),
            "resolved source-specific IPv6 route",
        )
        .unwrap();
        validate_linux_parent_route(&parent, &resolved, transport).unwrap();

        let resource = bypass_resource(
            Platform::Linux,
            transport.peer.ip(),
            &PeerPath::Linux(LinuxPeerPath {
                parent,
                policy_rules: serde_json::json!([]),
                source: transport.local.ip(),
            }),
        )
        .unwrap()
        .unwrap();
        let OwnedResource::Route {
            prefix,
            target:
                RouteTarget::Linux {
                    table,
                    source_prefix,
                    source,
                    nexthops,
                    metric,
                },
        } = resource
        else {
            panic!("Linux IPv6 bypass did not produce a Linux route");
        };
        let arguments = linux_route_arguments(
            "add",
            prefix,
            table,
            source_prefix,
            source,
            &nexthops,
            metric,
        );

        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["from", "2001:db8:1::/64"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["src", "2001:db8:1::22"])
        );
        assert!(!arguments.contains(&"2001:db8:1::99".to_string()));
    }

    #[test]
    fn linux_parent_revalidation_detects_a_same_interface_gateway_change() {
        let parent = linux_route_fixture(
            r#"[{"type":"1","dst":"default","gateway":"192.0.2.1","dev":"ethernet0","table":"100","protocol":"3","scope":"0","flags":[]}]"#,
        );
        let unchanged = MockExecutor::with_outputs([Ok(CommandOutput::success(
            r#"[{"type":"1","dst":"default","gateway":"192.0.2.1","dev":"ethernet0","protocol":"3","scope":"0","flags":[]}]"#,
        ))]);
        assert!(linux_parent_route_is_present(&unchanged, &parent).unwrap());

        let changed = MockExecutor::with_outputs([Ok(CommandOutput::success(
            r#"[{"type":"1","dst":"default","gateway":"192.0.2.254","dev":"ethernet0","protocol":"3","scope":"0","flags":[]}]"#,
        ))]);
        assert!(!linux_parent_route_is_present(&changed, &parent).unwrap());
    }

    #[test]
    fn linux_replacement_selection_ignores_the_owned_pin_and_uses_the_parent_fib() {
        let transport = transport_socket();
        let inventory = parse_linux_route_records(
            r#"[
                {"type":"1","dst":"203.0.113.8","gateway":"192.0.2.1","dev":"ethernet0","table":"100","protocol":"3","scope":"0","prefsrc":"192.0.2.2","metric":4,"flags":[]},
                {"type":"1","dst":"203.0.113.0/24","gateway":"192.0.2.254","dev":"ethernet0","table":"100","protocol":"3","scope":"0","prefsrc":"192.0.2.2","metric":25,"flags":[]},
                {"type":"1","dst":"default","gateway":"198.51.100.1","dev":"wifi0","table":"100","protocol":"3","scope":"0","metric":100,"flags":[]}
            ]"#,
            false,
            None,
        )
        .unwrap();
        let owned = OwnedResource::Route {
            prefix: "203.0.113.8/32".parse().unwrap(),
            target: RouteTarget::Linux {
                table: 100,
                source_prefix: None,
                source: Some(transport.local.ip()),
                nexthops: vec![LinuxNexthop {
                    gateway: Some("192.0.2.1".parse().unwrap()),
                    interface: "ethernet0".to_string(),
                    weight: 1,
                    on_link: false,
                    pervasive: false,
                }],
                metric: ROUTE_METRIC,
            },
        };

        let replacement =
            select_linux_replacement_parent(&inventory, transport, 100, &[owned]).unwrap();

        assert_eq!(replacement.prefix, "203.0.113.0/24".parse().unwrap());
        assert_eq!(
            replacement.nexthops[0].gateway,
            Some("192.0.2.254".parse().unwrap())
        );
        assert_eq!(replacement.nexthops[0].interface, "ethernet0");
    }

    #[test]
    fn linux_runtime_collision_inventory_excludes_only_owned_and_kernel_tunnel_routes() {
        let network = selected_network(true);
        let tunnel = TunnelIdentity {
            name: "tun42".to_string(),
            index: 42,
        };
        let owned_prefix = IpNet::V4(network.synthetic.unwrap().ipv4);
        let owned = OwnedResource::Route {
            prefix: owned_prefix,
            target: linux_target("tun42", None),
        };
        let owned_record = linux_route_fixture(&format!(
            r#"[{{"type":"1","dst":"{owned_prefix}","dev":"tun42","table":"254","protocol":"3","scope":"253","metric":4,"flags":[]}}]"#
        ));
        let intrinsic_record = linux_route_fixture(&format!(
            r#"[{{"type":"1","dst":"{}","dev":"tun42","table":"254","protocol":"2","scope":"253","prefsrc":"{}","flags":[]}}]"#,
            network.gateway_ipv4, network.interface_ipv4
        ));
        let collision_prefix =
            IpNet::new(owned_prefix.addr(), owned_prefix.prefix_len() + 1).unwrap();
        let collision_record = linux_route_fixture(&format!(
            r#"[{{"type":"1","dst":"{collision_prefix}","dev":"ethernet0","table":"254","protocol":"3","scope":"253","flags":[]}}]"#
        ));
        let inventory = [owned_record, intrinsic_record, collision_record.clone()];

        assert_eq!(
            first_linux_route_collision(&inventory, &[owned], &tunnel, network),
            Some(&collision_record)
        );
    }

    #[test]
    fn macos_inventory_expands_bsd_abbreviated_ipv4_destinations_and_scopes() {
        let ipv4 = parse_macos_route_inventory(
            "Routing tables\n\nInternet:\nDestination        Gateway\ndefault            192.0.2.1\n127                127.0.0.1\n192.168.7/24       link#4\n",
            false,
        );
        let ipv6 = parse_macos_route_inventory(
            "Internet6:\nDestination                             Gateway\ndefault                                 fe80::1%en0\nfe80::%en0/64                           link#4\n",
            true,
        );

        assert_eq!(
            ipv4,
            [
                "0.0.0.0/0".parse().unwrap(),
                "127.0.0.0/8".parse().unwrap(),
                "192.168.7.0/24".parse().unwrap(),
            ]
        );
        assert_eq!(
            ipv6,
            ["::/0".parse().unwrap(), "fe80::/64".parse().unwrap()]
        );
    }

    #[test]
    fn windows_plan_uses_runtime_gateways_and_session_scoped_root_nrpt() {
        let network = selected_network(true);
        let plan = RoutePlan::for_policy(&SystemVpnPolicy::full_tunnel(), network).unwrap();
        let tunnel = TunnelIdentity {
            name: "sshportal".to_string(),
            index: 14,
        };
        let resources = static_resources(Platform::Windows, &tunnel, network, &plan);

        let route = resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::Route {
                    prefix,
                    target: RouteTarget::Windows { next_hop, .. },
                } if prefix.addr().is_ipv4() => Some(*next_hop),
                _ => None,
            })
            .unwrap();
        assert_eq!(route, IpAddr::V4(network.gateway_ipv4));
        let ipv6_route = resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::Route {
                    prefix,
                    target: RouteTarget::Windows { next_hop, .. },
                } if prefix.addr().is_ipv6() => Some(*next_hop),
                _ => None,
            })
            .unwrap();
        assert_eq!(ipv6_route, IpAddr::V6(Ipv6Addr::UNSPECIFIED));

        let command = windows_nrpt_ensure_command([9; 16], plan.dns.as_ref().unwrap());
        let script = command.arguments.last().unwrap();
        assert!(script.contains("$namespaces = @('.')"));
        assert!(script.contains(&network.synthetic.unwrap().ipv4_dns.to_string()));
        assert!(script.contains("SSHPortal-09090909090909090909090909090909"));
    }

    #[test]
    fn linux_full_dns_plan_uses_route_only_root_domain_and_both_servers() {
        let network = selected_network(true);
        let dns = RoutePlan::for_policy(&SystemVpnPolicy::full_tunnel(), network)
            .unwrap()
            .dns
            .unwrap();
        let tunnel = TunnelIdentity {
            name: "tun7".to_string(),
            index: 7,
        };
        let executor = MockExecutor::default();

        apply_dns_commands(Platform::Linux, &executor, &tunnel, [8; 16], &dns).unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].arguments[0..2], ["dns", "tun7"]);
        assert!(
            calls[0]
                .arguments
                .contains(&network.synthetic.unwrap().ipv4_dns.to_string())
        );
        assert!(
            calls[0]
                .arguments
                .contains(&network.synthetic.unwrap().ipv6_dns.to_string())
        );
        assert_eq!(calls[1].arguments, ["domain", "tun7", "~."]);
        assert_eq!(calls[2].arguments, ["default-route", "tun7", "true"]);
    }

    #[test]
    fn linux_bypass_reconciliation_replaces_the_owned_host_route_atomically() {
        let old = OwnedResource::Route {
            prefix: "203.0.113.8/32".parse().unwrap(),
            target: linux_target("enp1s0", Some("192.0.2.1".parse().unwrap())),
        };
        let new = OwnedResource::Route {
            prefix: "203.0.113.8/32".parse().unwrap(),
            target: linux_target("wlan0", Some("198.51.100.1".parse().unwrap())),
        };
        let executor = MockExecutor::default();

        replace_bypass_resource(Platform::Linux, &executor, &old, &new).unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments[2], "replace");
        assert!(calls[0].arguments.contains(&"wlan0".to_string()));
        assert!(calls[0].arguments.contains(&"198.51.100.1".to_string()));
    }

    #[test]
    fn linux_cross_table_bypass_replacement_is_verified_before_old_pin_removal() {
        let prefix = "203.0.113.8/32".parse().unwrap();
        let old = OwnedResource::Route {
            prefix,
            target: RouteTarget::Linux {
                table: 100,
                source_prefix: None,
                source: Some("192.0.2.2".parse().unwrap()),
                nexthops: vec![LinuxNexthop {
                    gateway: Some("192.0.2.1".parse().unwrap()),
                    interface: "ethernet0".to_string(),
                    weight: 1,
                    on_link: false,
                    pervasive: false,
                }],
                metric: ROUTE_METRIC,
            },
        };
        let new = OwnedResource::Route {
            prefix,
            target: RouteTarget::Linux {
                table: 200,
                source_prefix: None,
                source: Some("198.51.100.2".parse().unwrap()),
                nexthops: vec![LinuxNexthop {
                    gateway: Some("198.51.100.1".parse().unwrap()),
                    interface: "wifi0".to_string(),
                    weight: 1,
                    on_link: false,
                    pervasive: false,
                }],
                metric: ROUTE_METRIC,
            },
        };
        let executor = MockExecutor::with_outputs([
            Ok(CommandOutput::success("")),
            Ok(CommandOutput::success(
                r#"[{"type":"1","dst":"203.0.113.8","gateway":"198.51.100.1","dev":"wifi0","protocol":"3","scope":"0","prefsrc":"198.51.100.2","metric":4,"flags":[]}]"#,
            )),
            Ok(CommandOutput::success("")),
        ]);

        replace_bypass_resource(Platform::Linux, &executor, &old, &new).unwrap();

        let calls = executor.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].arguments[2], "add");
        assert_eq!(calls[0].arguments[5], "200");
        assert_eq!(calls[1].arguments[5], "show");
        assert_eq!(calls[2].arguments[2], "del");
        assert_eq!(calls[2].arguments[5], "100");
    }

    #[test]
    fn initial_linux_route_application_never_overwrites_an_existing_route() {
        let resource = OwnedResource::Route {
            prefix: "10.20.0.0/16".parse().unwrap(),
            target: linux_target("tun7", None),
        };
        let executor = MockExecutor::default();

        apply_resource(Platform::Linux, &executor, &resource, ApplyMode::Initial).unwrap();

        assert_eq!(executor.calls()[0].arguments[2], "add");
    }

    #[test]
    fn linux_command_plan_uses_runtime_interface_gateway_and_synthetic_addresses() {
        let network = selected_network(true);
        let plan = RoutePlan::for_policy(&SystemVpnPolicy::full_tunnel(), network).unwrap();
        let tunnel = TunnelIdentity {
            name: "tun42".to_string(),
            index: 42,
        };
        let resources = static_resources(Platform::Linux, &tunnel, network, &plan);
        let executor = MockExecutor::default();

        for resource in &resources {
            apply_resource(Platform::Linux, &executor, resource, ApplyMode::Initial).unwrap();
        }
        apply_dns_commands(
            Platform::Linux,
            &executor,
            &tunnel,
            [8; 16],
            plan.dns.as_ref().unwrap(),
        )
        .unwrap();

        let calls = executor.calls();
        let displays = calls.iter().map(CommandSpec::display).collect::<Vec<_>>();
        assert!(
            displays
                .iter()
                .any(|display| display.contains("ip -4 route add 0.0.0.0/1")
                    && display.contains("dev tun42"))
        );
        assert!(displays.iter().any(|display| {
            display.contains(&format!(
                "ip -6 address add {}/126 peer {} dev tun42",
                network.interface_ipv6, network.gateway_ipv6
            ))
        }));
        assert!(displays.iter().any(|display| {
            display.contains(&format!(
                "resolvectl dns tun42 {} {}",
                network.synthetic.unwrap().ipv4_dns,
                network.synthetic.unwrap().ipv6_dns
            ))
        }));
    }

    #[test]
    fn macos_command_plan_uses_runtime_interface_and_session_dns_identity() {
        let network = selected_network(true);
        let plan = RoutePlan::for_policy(&SystemVpnPolicy::full_tunnel(), network).unwrap();
        let tunnel = TunnelIdentity {
            name: "utun42".to_string(),
            index: 42,
        };
        let resources = static_resources(Platform::Macos, &tunnel, network, &plan);
        let executor = MockExecutor::default();

        for resource in &resources {
            apply_resource(Platform::Macos, &executor, resource, ApplyMode::Initial).unwrap();
        }

        let displays = executor
            .calls()
            .iter()
            .map(CommandSpec::display)
            .collect::<Vec<_>>();
        assert!(displays.iter().any(|display| {
            display.contains(&format!(
                "ifconfig utun42 inet6 {} {} prefixlen 128 alias",
                network.interface_ipv6, network.gateway_ipv6
            ))
        }));
        assert!(displays.iter().any(|display| {
            display.contains("route -n add -inet -net 0.0.0.0/1 -interface utun42")
        }));
        assert_eq!(
            dns_resource(
                Platform::Macos,
                &tunnel,
                [6; 16],
                plan.dns.as_ref().unwrap()
            ),
            OwnedResource::MacosDns {
                session_id: [6; 16]
            }
        );
    }

    #[test]
    fn platform_cleanup_plans_remove_only_session_owned_resources() {
        let session_id = [6; 16];
        let linux = MockExecutor::default();
        cleanup_resource(
            Platform::Linux,
            &linux,
            &OwnedResource::LinuxResolved {
                interface: "tun42".to_string(),
            },
        )
        .unwrap();
        assert_eq!(linux.calls()[0].arguments, ["revert", "tun42"]);

        let macos = OwnedResource::MacosDns { session_id };
        assert_eq!(
            macos,
            dns_resource(
                Platform::Macos,
                &TunnelIdentity {
                    name: "utun42".to_string(),
                    index: 42,
                },
                session_id,
                &DnsPlan {
                    servers: ["198.18.0.1".parse().unwrap(), "fd00::1".parse().unwrap()],
                    match_domains: DnsMatchDomains::All,
                },
            )
        );

        let windows = MockExecutor::default();
        cleanup_resource(
            Platform::Windows,
            &windows,
            &OwnedResource::WindowsNrpt { session_id },
        )
        .unwrap();
        let script = windows.calls()[0].arguments.last().unwrap().clone();
        assert!(script.contains("$_.DisplayName -eq 'SSHPortal-06060606060606060606060606060606'"));
        assert!(script.contains("Remove-DnsClientNrptRule"));
        assert!(script.contains("Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop"));
    }

    #[test]
    fn windows_cleanup_ignores_only_absence_and_surfaces_removal_failures() {
        let route = OwnedResource::Route {
            prefix: "10.20.0.0/16".parse().unwrap(),
            target: RouteTarget::Windows {
                interface_index: 42,
                next_hop: "10.0.0.1".parse().unwrap(),
                metric: ROUTE_METRIC,
            },
        };
        let executor = MockExecutor::default();
        cleanup_resource(Platform::Windows, &executor, &route).unwrap();
        let script = executor.calls()[0].arguments.last().unwrap().clone();
        assert!(script.contains("ErrorVariable +lookupErrors"));
        assert!(script.contains("ErrorCategory]::ObjectNotFound"));
        assert!(script.contains("Remove-NetRoute -Confirm:$false -ErrorAction Stop"));

        let failing = MockExecutor::with_outputs([Ok(CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "Access is denied".to_string(),
        })]);
        assert!(cleanup_resource(Platform::Windows, &failing, &route).is_err());
    }

    #[test]
    fn windows_command_plan_uses_runtime_interface_and_gateway() {
        let network = selected_network(true);
        let plan = RoutePlan::for_policy(&SystemVpnPolicy::full_tunnel(), network).unwrap();
        let tunnel = TunnelIdentity {
            name: "sshportal".to_string(),
            index: 42,
        };
        let resources = static_resources(Platform::Windows, &tunnel, network, &plan);
        let executor = MockExecutor::default();

        for resource in &resources {
            apply_resource(Platform::Windows, &executor, resource, ApplyMode::Initial).unwrap();
        }

        let displays = executor
            .calls()
            .iter()
            .map(CommandSpec::display)
            .collect::<Vec<_>>();
        assert!(displays.iter().any(|display| {
            display.contains(&format!(
                "New-NetIPAddress -InterfaceIndex 42 -IPAddress '{}' -PrefixLength 126",
                network.interface_ipv6
            ))
        }));
        assert!(displays.iter().any(|display| {
            display.contains(&format!(
                "New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex 42 -NextHop '{}'",
                network.gateway_ipv4
            ))
        }));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_full_dns_uses_empty_match_domain_and_both_runtime_servers() {
        let network = selected_network(true);
        let dns = RoutePlan::for_policy(&SystemVpnPolicy::full_tunnel(), network)
            .unwrap()
            .dns
            .unwrap();
        let dictionary = macos_dns_dictionary("utun9", &dns);

        let servers = dictionary.find(CFString::new("ServerAddresses")).unwrap();
        let server_description = format!("{servers:?}");
        assert!(server_description.contains(&network.synthetic.unwrap().ipv4_dns.to_string()));
        assert!(server_description.contains(&network.synthetic.unwrap().ipv6_dns.to_string()));
        let domains = dictionary
            .find(CFString::new("SupplementalMatchDomains"))
            .unwrap();
        assert_eq!(domains.downcast::<CFArray>().unwrap().len(), 1);
        let interface = dictionary.find(CFString::new("InterfaceName")).unwrap();
        assert!(format!("{interface:?}").contains("utun9"));
    }
}
