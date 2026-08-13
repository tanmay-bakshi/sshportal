use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result, bail};

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

use super::policy::SystemVpnPolicy;
use super::{VIRTUAL_DNS_POOL, VIRTUAL_DNS_SERVER};

const SPLIT_DEFAULT_ROUTES: [&str; 4] = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

#[cfg(target_os = "windows")]
use super::{VPN_GATEWAY_IPV4, VPN_INTERFACE_IPV6};

#[cfg(target_os = "windows")]
const ROUTE_METRIC: u32 = 4;

#[derive(Debug, Eq, PartialEq)]
struct RoutePlan {
    tunnel_prefixes: Vec<String>,
    route_system_dns: bool,
    split_dns_domains: Vec<String>,
}

impl RoutePlan {
    fn for_policy(policy: &SystemVpnPolicy) -> Self {
        if policy.is_full_tunnel() {
            return Self {
                tunnel_prefixes: SPLIT_DEFAULT_ROUTES
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                route_system_dns: true,
                split_dns_domains: Vec::new(),
            };
        }

        let mut tunnel_prefixes = Vec::new();
        for network in policy.include_cidrs() {
            if network.prefix_len() == 0 {
                let defaults = if network.addr().is_ipv4() {
                    &SPLIT_DEFAULT_ROUTES[..2]
                } else {
                    &SPLIT_DEFAULT_ROUTES[2..]
                };
                append_unique_prefixes(&mut tunnel_prefixes, defaults.iter().copied());
                continue;
            }
            append_unique_prefixes(&mut tunnel_prefixes, [network.to_string()]);
        }
        if !policy.include_domains().is_empty() {
            append_unique_prefixes(&mut tunnel_prefixes, [VIRTUAL_DNS_POOL]);
        }

        Self {
            tunnel_prefixes,
            route_system_dns: false,
            split_dns_domains: policy.include_domains().to_vec(),
        }
    }

    #[cfg(target_os = "windows")]
    fn requires_ipv6(&self) -> bool {
        self.tunnel_prefixes
            .iter()
            .any(|prefix| prefix.contains(':'))
    }
}

fn append_unique_prefixes<I, S>(prefixes: &mut Vec<String>, additions: I)
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    for addition in additions {
        let addition = addition.into();
        if !prefixes.contains(&addition) {
            prefixes.push(addition);
        }
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

pub(super) trait CommandExecutor {
    fn run(&self, command: &CommandSpec) -> Result<String>;
}

pub(super) struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn run(&self, command: &CommandSpec) -> Result<String> {
        let output = Command::new(&command.program)
            .args(&command.arguments)
            .output()
            .with_context(|| format!("failed to start `{}`", command.display()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            bail!("`{}` failed: {detail}", command.display());
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("`{}` returned non-UTF-8 output", command.display()))
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn unique_network_session_name() -> String {
    let mut random = [0_u8; 8];
    rand::fill(&mut random);
    format!(
        "SSHPortal-{}-{:016x}",
        std::process::id(),
        u64::from_be_bytes(random)
    )
}

#[cfg(target_os = "macos")]
struct MacosDnsPolicy {
    store: SCDynamicStore,
    key: String,
    active: bool,
}

#[cfg(target_os = "macos")]
impl MacosDnsPolicy {
    fn install(domains: &[String]) -> Result<Self> {
        let session_name = unique_network_session_name();
        let store = SCDynamicStoreBuilder::new(session_name.as_str())
            .session_keys(true)
            .build()
            .context("failed to open the macOS SystemConfiguration dynamic store")?;
        let key = format!("State:/Network/Service/{session_name}/DNS");
        let dictionary = macos_dns_dictionary(domains);
        if !store.set(key.as_str(), dictionary.to_untyped()) {
            bail!("macOS rejected the supplemental DNS configuration for selected VPN domains");
        }
        Ok(Self {
            store,
            key,
            active: true,
        })
    }

    fn restore(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        if !self.store.remove(self.key.as_str()) {
            bail!("macOS failed to remove supplemental DNS configuration");
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn macos_dns_dictionary(domains: &[String]) -> CFDictionary<CFString, CFType> {
    let server_addresses =
        CFArray::from_CFTypes(&[CFString::new(VIRTUAL_DNS_SERVER)]).into_CFType();
    let match_domains = domains
        .iter()
        .map(|domain| CFString::new(domain))
        .collect::<Vec<_>>();
    let supplemental_match_domains = CFArray::from_CFTypes(&match_domains).into_CFType();
    CFDictionary::from_CFType_pairs(&[
        (CFString::new("ServerAddresses"), server_addresses),
        (
            CFString::new("SupplementalMatchDomains"),
            supplemental_match_domains,
        ),
        (
            CFString::new("SupplementalMatchDomainsNoSearch"),
            CFNumber::from(1).into_CFType(),
        ),
    ])
}

pub(super) struct RouteGuard<E: CommandExecutor = SystemCommandExecutor> {
    executor: E,
    rollback: Vec<CommandSpec>,
    #[cfg(target_os = "macos")]
    dns_policy: Option<MacosDnsPolicy>,
    active: bool,
}

impl<E: CommandExecutor> RouteGuard<E> {
    fn new(executor: E) -> Self {
        Self {
            executor,
            rollback: Vec::new(),
            #[cfg(target_os = "macos")]
            dns_policy: None,
            active: true,
        }
    }

    fn query(&self, command: CommandSpec) -> Result<String> {
        self.executor.run(&command)
    }

    fn apply(&mut self, setup: CommandSpec, rollback: CommandSpec) -> Result<()> {
        self.executor.run(&setup)?;
        self.rollback.push(rollback);
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "windows", test))]
    fn apply_group(
        &mut self,
        setups: impl IntoIterator<Item = CommandSpec>,
        rollback: CommandSpec,
    ) -> Result<()> {
        let mut setups = setups.into_iter();
        let Some(first) = setups.next() else {
            return Ok(());
        };
        self.executor.run(&first)?;
        self.rollback.push(rollback);
        for setup in setups {
            self.executor.run(&setup)?;
        }
        Ok(())
    }

    pub(super) fn restore(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let mut first_error = None;
        #[cfg(target_os = "macos")]
        if let Some(mut dns_policy) = self.dns_policy.take()
            && let Err(error) = dns_policy.restore()
        {
            debug_log(format!("VPN split DNS cleanup failed: {error:#}"));
            first_error = Some(error);
        }
        while let Some(command) = self.rollback.pop() {
            if let Err(error) = self.executor.run(&command) {
                debug_log(format!(
                    "VPN cleanup command `{}` failed: {error:#}",
                    command.display()
                ));
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error).context("failed to restore one or more VPN network settings"),
            None => Ok(()),
        }
    }
}

impl<E: CommandExecutor> Drop for RouteGuard<E> {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("failed to restore VPN network configuration: {error:#}");
        }
    }
}

pub(super) fn configure(
    tun_name: &str,
    tun_index: i32,
    transport_peers: &[IpAddr],
    policy: &SystemVpnPolicy,
) -> Result<RouteGuard> {
    let executor = SystemCommandExecutor;
    let plan = RoutePlan::for_policy(policy);
    configure_with_executor(tun_name, tun_index, transport_peers, &plan, executor)
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

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn host_prefix(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => format!("{address}/32"),
        IpAddr::V6(address) => format!("{address}/128"),
    }
}

#[cfg(target_os = "linux")]
fn configure_with_executor<E: CommandExecutor>(
    tun_name: &str,
    _tun_index: i32,
    transport_peers: &[IpAddr],
    plan: &RoutePlan,
    executor: E,
) -> Result<RouteGuard<E>> {
    let transport_peers =
        deduplicate_ips(transport_peers.iter().copied().map(normalize_ip).collect());
    let mut guard = RouteGuard::new(executor);

    for peer_ip in &transport_peers {
        if peer_ip.is_loopback() {
            continue;
        }
        let family = if peer_ip.is_ipv4() { "-4" } else { "-6" };
        let output = guard.query(CommandSpec::new(
            "ip",
            [family, "route", "get", &peer_ip.to_string()],
        ))?;
        let path = parse_linux_route_path(&output)?;
        let prefix = host_prefix(*peer_ip);
        let mut setup = vec![
            family.to_string(),
            "route".to_string(),
            "add".to_string(),
            prefix.clone(),
        ];
        let mut rollback = vec![
            family.to_string(),
            "route".to_string(),
            "del".to_string(),
            prefix,
        ];
        if let Some(gateway) = path.gateway {
            setup.extend(["via".to_string(), gateway.clone()]);
            rollback.extend(["via".to_string(), gateway]);
        }
        setup.extend(["dev".to_string(), path.interface.clone()]);
        rollback.extend(["dev".to_string(), path.interface]);
        guard.apply(
            CommandSpec::new("ip", setup),
            CommandSpec::new("ip", rollback),
        )?;
    }

    if plan.route_system_dns {
        for dns_server in linux_dns_servers(&guard) {
            if transport_peers.contains(&dns_server) || dns_server.is_loopback() {
                continue;
            }
            apply_linux_tun_route(&mut guard, tun_name, &host_prefix(dns_server))?;
        }
    }
    for prefix in &plan.tunnel_prefixes {
        apply_linux_tun_route(&mut guard, tun_name, prefix)?;
    }
    if !plan.split_dns_domains.is_empty() {
        configure_linux_split_dns(&mut guard, tun_name, &plan.split_dns_domains)?;
    }
    Ok(guard)
}

#[cfg(target_os = "linux")]
fn configure_linux_split_dns<E: CommandExecutor>(
    guard: &mut RouteGuard<E>,
    tun_name: &str,
    domains: &[String],
) -> Result<()> {
    let mut domain_arguments = vec!["domain".to_string(), tun_name.to_string()];
    domain_arguments.extend(domains.iter().map(|domain| format!("~{domain}")));
    guard
        .apply_group(
            [
                CommandSpec::new("resolvectl", ["dns", tun_name, VIRTUAL_DNS_SERVER]),
                CommandSpec::new("resolvectl", domain_arguments),
                CommandSpec::new("resolvectl", ["default-route", tun_name, "false"]),
            ],
            CommandSpec::new("resolvectl", ["revert", tun_name]),
        )
        .context(
            "selected VPN domains require systemd-resolved and a working `resolvectl`; split DNS was not installed",
        )
}

#[cfg(target_os = "linux")]
fn apply_linux_tun_route<E: CommandExecutor>(
    guard: &mut RouteGuard<E>,
    tun_name: &str,
    prefix: &str,
) -> Result<()> {
    let family = if prefix.contains(':') { "-6" } else { "-4" };
    guard.apply(
        CommandSpec::new("ip", [family, "route", "add", prefix, "dev", tun_name]),
        CommandSpec::new("ip", [family, "route", "del", prefix, "dev", tun_name]),
    )
}

#[cfg(target_os = "linux")]
struct LinuxRoutePath {
    gateway: Option<String>,
    interface: String,
}

#[cfg(target_os = "linux")]
fn parse_linux_route_path(output: &str) -> Result<LinuxRoutePath> {
    let fields = output.split_whitespace().collect::<Vec<_>>();
    let interface = value_after(&fields, "dev")
        .context("`ip route get` output did not identify an interface")?
        .to_string();
    let gateway = value_after(&fields, "via").map(str::to_string);
    Ok(LinuxRoutePath { gateway, interface })
}

#[cfg(target_os = "linux")]
fn linux_dns_servers<E: CommandExecutor>(guard: &RouteGuard<E>) -> Vec<IpAddr> {
    let mut servers = std::fs::read_to_string("/etc/resolv.conf")
        .map(|contents| parse_resolv_conf(&contents))
        .unwrap_or_default();
    let resolvectl = CommandSpec::new("resolvectl", ["dns"]);
    match guard.query(resolvectl) {
        Ok(output) => servers.extend(parse_ip_tokens(&output)),
        Err(error) => debug_log(format!(
            "could not inspect systemd-resolved DNS servers; /etc/resolv.conf will be used: {error:#}"
        )),
    }
    deduplicate_ips(servers)
}

#[cfg(target_os = "macos")]
fn configure_with_executor<E: CommandExecutor>(
    tun_name: &str,
    _tun_index: i32,
    transport_peers: &[IpAddr],
    plan: &RoutePlan,
    executor: E,
) -> Result<RouteGuard<E>> {
    let transport_peers =
        deduplicate_ips(transport_peers.iter().copied().map(normalize_ip).collect());
    let mut guard = RouteGuard::new(executor);

    for peer_ip in &transport_peers {
        if peer_ip.is_loopback() {
            continue;
        }
        let family = if peer_ip.is_ipv4() { "-inet" } else { "-inet6" };
        let output = guard.query(CommandSpec::new(
            "route",
            ["-n", "get", family, &peer_ip.to_string()],
        ))?;
        if let Some(gateway) = parse_macos_gateway(&output) {
            let address = peer_ip.to_string();
            guard.apply(
                CommandSpec::new("route", ["-n", "add", family, "-host", &address, &gateway]),
                CommandSpec::new(
                    "route",
                    ["-n", "delete", family, "-host", &address, &gateway],
                ),
            )?;
        }
    }

    if plan.route_system_dns {
        let dns_output = guard.query(CommandSpec::new("scutil", ["--dns"]))?;
        for dns_server in deduplicate_ips(parse_macos_dns_servers(&dns_output)) {
            if transport_peers.contains(&dns_server) || dns_server.is_loopback() {
                continue;
            }
            apply_macos_tun_route(&mut guard, tun_name, &dns_server.to_string(), true)?;
        }
    }
    for prefix in &plan.tunnel_prefixes {
        apply_macos_tun_route(&mut guard, tun_name, prefix, false)?;
    }
    if !plan.split_dns_domains.is_empty() {
        guard.dns_policy = Some(MacosDnsPolicy::install(&plan.split_dns_domains)?);
    }
    Ok(guard)
}

#[cfg(target_os = "macos")]
fn apply_macos_tun_route<E: CommandExecutor>(
    guard: &mut RouteGuard<E>,
    tun_name: &str,
    prefix: &str,
    host: bool,
) -> Result<()> {
    let family = if prefix.contains(':') {
        "-inet6"
    } else {
        "-inet"
    };
    let kind = if host { "-host" } else { "-net" };
    guard.apply(
        CommandSpec::new(
            "route",
            ["-n", "add", family, kind, prefix, "-interface", tun_name],
        ),
        CommandSpec::new(
            "route",
            ["-n", "delete", family, kind, prefix, "-interface", tun_name],
        ),
    )
}

#[cfg(target_os = "macos")]
fn parse_macos_gateway(output: &str) -> Option<String> {
    for line in output.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "gateway" {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn parse_macos_dns_servers(output: &str) -> Vec<IpAddr> {
    output
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.trim().starts_with("nameserver[") {
                return None;
            }
            parse_scoped_ip(value.trim())
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn configure_with_executor<E: CommandExecutor>(
    _tun_name: &str,
    tun_index: i32,
    transport_peers: &[IpAddr],
    plan: &RoutePlan,
    executor: E,
) -> Result<RouteGuard<E>> {
    let transport_peers =
        deduplicate_ips(transport_peers.iter().copied().map(normalize_ip).collect());
    let mut guard = RouteGuard::new(executor);

    for peer_ip in &transport_peers {
        if peer_ip.is_loopback() {
            continue;
        }
        let output = guard.query(find_windows_route(*peer_ip))?;
        let route: WindowsRoutePath =
            serde_json::from_str(output.trim()).context("failed to decode Find-NetRoute output")?;
        let prefix = host_prefix(*peer_ip);
        apply_windows_route(&mut guard, &prefix, route.interface_index, &route.next_hop)?;
    }

    if plan.requires_ipv6() {
        let ipv6_address = VPN_INTERFACE_IPV6.to_string();
        let add_ipv6_address = format!(
            "New-NetIPAddress -InterfaceIndex {tun_index} -IPAddress '{ipv6_address}' \
             -PrefixLength 64 -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null"
        );
        let remove_ipv6_address = format!(
            "Get-NetIPAddress -InterfaceIndex {tun_index} -IPAddress '{ipv6_address}' \
             -AddressFamily IPv6 -ErrorAction SilentlyContinue \
             | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue"
        );
        guard.apply(
            powershell(add_ipv6_address),
            powershell(remove_ipv6_address),
        )?;
    }

    if plan.route_system_dns {
        let dns_query = "Get-DnsClientServerAddress | ForEach-Object { $_.ServerAddresses } \
                         | Where-Object { $_ } | ConvertTo-Json -Compress";
        let dns_output = guard.query(powershell(dns_query))?;
        for dns_server in parse_windows_dns_servers(&dns_output)? {
            if transport_peers.contains(&dns_server) || dns_server.is_loopback() {
                continue;
            }
            let next_hop = if dns_server.is_ipv4() {
                VPN_GATEWAY_IPV4.to_string()
            } else {
                "::".to_string()
            };
            apply_windows_route(&mut guard, &host_prefix(dns_server), tun_index, &next_hop)?;
        }
    }
    for prefix in &plan.tunnel_prefixes {
        let next_hop = if prefix.contains(':') {
            "::".to_string()
        } else {
            VPN_GATEWAY_IPV4.to_string()
        };
        apply_windows_route(&mut guard, prefix, tun_index, &next_hop)?;
    }
    if !plan.split_dns_domains.is_empty() {
        configure_windows_split_dns(&mut guard, &plan.split_dns_domains)?;
    }
    Ok(guard)
}

#[cfg(target_os = "windows")]
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsRoutePath {
    interface_index: i32,
    next_hop: String,
}

#[cfg(target_os = "windows")]
fn powershell(script: impl Into<String>) -> CommandSpec {
    CommandSpec::new(
        "powershell.exe",
        [
            "-NoLogo".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            script.into(),
        ],
    )
}

#[cfg(target_os = "windows")]
fn find_windows_route(peer_ip: IpAddr) -> CommandSpec {
    let query = format!(
        "$source, $route = Find-NetRoute -RemoteIPAddress '{peer_ip}' -ErrorAction Stop; \
         if ($null -eq $route) {{ throw 'No route found' }}; \
         [pscustomobject]@{{InterfaceIndex=$route.InterfaceIndex;NextHop=$route.NextHop}} \
         | ConvertTo-Json -Compress"
    );
    powershell(query)
}

#[cfg(target_os = "windows")]
fn apply_windows_route<E: CommandExecutor>(
    guard: &mut RouteGuard<E>,
    prefix: &str,
    interface_index: i32,
    next_hop: &str,
) -> Result<()> {
    let setup = format!(
        "New-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} \
         -NextHop '{next_hop}' -RouteMetric {ROUTE_METRIC} -PolicyStore ActiveStore \
         -ErrorAction Stop | Out-Null"
    );
    let rollback = format!(
        "Get-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} \
         -NextHop '{next_hop}' -PolicyStore ActiveStore -ErrorAction SilentlyContinue \
         | Where-Object {{ $_.RouteMetric -eq {ROUTE_METRIC} }} \
         | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
    );
    guard.apply(powershell(setup), powershell(rollback))
}

#[cfg(target_os = "windows")]
fn configure_windows_split_dns<E: CommandExecutor>(
    guard: &mut RouteGuard<E>,
    domains: &[String],
) -> Result<()> {
    let display_name = unique_network_session_name();
    // NRPT represents the apex and its suffix namespace separately. Keep them in one rule so the
    // policy covers both without creating overlapping rule objects.
    let mut setup = domains
        .iter()
        .map(|domain| {
            powershell(format!(
                "Add-DnsClientNrptRule -Namespace '{domain}','.{domain}' \
                 -NameServers '{}' -DisplayName '{display_name}' \
                 -Comment 'SSHPortal selective VPN session' -ErrorAction Stop | Out-Null",
                VIRTUAL_DNS_SERVER
            ))
        })
        .collect::<Vec<_>>();
    let namespaces = domains
        .iter()
        .flat_map(|domain| [format!("'{domain}'"), format!("'.{domain}'")])
        .collect::<Vec<_>>()
        .join(",");
    setup.push(powershell(format!(
        "$expectedNamespaces = @({namespaces}); \
         foreach ($namespace in $expectedNamespaces) {{ \
             $policy = Get-DnsClientNrptPolicy -Effective -Namespace $namespace -ErrorAction Stop; \
             if ($null -eq $policy -or -not (@($policy.NameServers) -contains '{}')) {{ \
                 throw \"The SSHPortal NRPT rule for $namespace is not effective\" \
             }} \
         }}",
        VIRTUAL_DNS_SERVER
    )));
    setup.push(powershell("Clear-DnsClientCache -ErrorAction Stop"));
    let rollback = powershell(format!(
        "Get-DnsClientNrptRule -ErrorAction SilentlyContinue \
         | Where-Object {{ $_.DisplayName -eq '{display_name}' }} \
         | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }}; \
         Clear-DnsClientCache -ErrorAction SilentlyContinue"
    ));
    guard
        .apply_group(setup, rollback)
        .context("failed to install Windows NRPT rules for selected VPN domains")
}

#[cfg(target_os = "windows")]
fn parse_windows_dns_servers(output: &str) -> Result<Vec<IpAddr>> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    let values = if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<String>>(trimmed)
            .context("failed to decode Windows DNS server list")?
    } else {
        vec![
            serde_json::from_str::<String>(trimmed)
                .context("failed to decode Windows DNS server")?,
        ]
    };
    Ok(deduplicate_ips(
        values
            .iter()
            .filter_map(|value| parse_scoped_ip(value))
            .collect(),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn configure_with_executor<E: CommandExecutor>(
    _tun_name: &str,
    _tun_index: i32,
    _transport_peers: &[IpAddr],
    _plan: &RoutePlan,
    executor: E,
) -> Result<RouteGuard<E>> {
    let _guard = RouteGuard::new(executor);
    bail!("VPN routing is supported only on Linux, macOS, and Windows")
}

#[cfg(target_os = "linux")]
fn value_after<'a>(fields: &'a [&str], key: &str) -> Option<&'a str> {
    fields
        .windows(2)
        .find_map(|pair| (pair[0] == key).then_some(pair[1]))
}

#[cfg(target_os = "linux")]
fn parse_resolv_conf(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let content = line.split('#').next()?.trim();
            let mut fields = content.split_whitespace();
            if fields.next()? != "nameserver" {
                return None;
            }
            parse_scoped_ip(fields.next()?)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_ip_tokens(contents: &str) -> Vec<IpAddr> {
    contents
        .split_whitespace()
        .filter_map(|token| {
            parse_scoped_ip(token.trim_matches(|character: char| {
                character == '(' || character == ')' || character == ','
            }))
        })
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn parse_scoped_ip(value: &str) -> Option<IpAddr> {
    let without_scope = value.split('%').next()?;
    without_scope.parse().ok()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn deduplicate_ips(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut result = Vec::new();
    for address in addresses {
        if !result.contains(&address) {
            result.push(address);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use anyhow::{Result, anyhow};

    use super::{CommandExecutor, CommandSpec, RouteGuard, RoutePlan, normalize_ip};
    use crate::vpn::SystemVpnPolicy;

    #[derive(Default)]
    struct MockState {
        calls: Vec<CommandSpec>,
        results: VecDeque<Result<String>>,
    }

    #[derive(Clone, Default)]
    struct MockExecutor {
        state: Arc<Mutex<MockState>>,
    }

    impl MockExecutor {
        fn with_results(results: impl IntoIterator<Item = Result<String>>) -> Self {
            Self {
                state: Arc::new(Mutex::new(MockState {
                    calls: Vec::new(),
                    results: results.into_iter().collect(),
                })),
            }
        }

        fn calls(&self) -> Vec<CommandSpec> {
            self.state.lock().unwrap().calls.clone()
        }
    }

    impl CommandExecutor for MockExecutor {
        fn run(&self, command: &CommandSpec) -> Result<String> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(command.clone());
            state
                .results
                .pop_front()
                .unwrap_or_else(|| Ok(String::new()))
        }
    }

    #[test]
    fn route_guard_rolls_back_only_successful_changes_in_reverse_order() {
        let executor = MockExecutor::default();
        let observer = executor.clone();
        let mut guard = RouteGuard::new(executor);
        let add_first = CommandSpec::new("route", ["add", "first"]);
        let remove_first = CommandSpec::new("route", ["remove", "first"]);
        let add_second = CommandSpec::new("route", ["add", "second"]);
        let remove_second = CommandSpec::new("route", ["remove", "second"]);

        guard
            .apply(add_first.clone(), remove_first.clone())
            .unwrap();
        guard
            .apply(add_second.clone(), remove_second.clone())
            .unwrap();
        guard.restore().unwrap();
        drop(guard);

        assert_eq!(
            observer.calls(),
            vec![add_first, add_second, remove_second, remove_first]
        );
    }

    #[test]
    fn failed_setup_is_not_registered_for_rollback() {
        let executor = MockExecutor::with_results([
            Ok(String::new()),
            Err(anyhow!("setup failed")),
            Ok(String::new()),
        ]);
        let observer = executor.clone();
        let mut guard = RouteGuard::new(executor);
        let add_first = CommandSpec::new("route", ["add", "first"]);
        let remove_first = CommandSpec::new("route", ["remove", "first"]);
        let add_second = CommandSpec::new("route", ["add", "second"]);
        let remove_second = CommandSpec::new("route", ["remove", "second"]);

        guard
            .apply(add_first.clone(), remove_first.clone())
            .unwrap();
        assert!(guard.apply(add_second.clone(), remove_second).is_err());
        guard.restore().unwrap();

        assert_eq!(observer.calls(), vec![add_first, add_second, remove_first]);
    }

    #[test]
    fn grouped_setup_registers_cleanup_after_its_first_success() {
        let executor = MockExecutor::with_results([
            Ok(String::new()),
            Err(anyhow!("second setup failed")),
            Ok(String::new()),
        ]);
        let observer = executor.clone();
        let mut guard = RouteGuard::new(executor);
        let first = CommandSpec::new("network", ["first"]);
        let second = CommandSpec::new("network", ["second"]);
        let rollback = CommandSpec::new("network", ["rollback"]);

        assert!(
            guard
                .apply_group([first.clone(), second.clone()], rollback.clone())
                .is_err()
        );
        guard.restore().unwrap();

        assert_eq!(observer.calls(), vec![first, second, rollback]);
    }

    #[test]
    fn full_tunnel_plan_preserves_split_defaults_and_system_dns_routes() {
        let plan = RoutePlan::for_policy(&SystemVpnPolicy::default());

        assert_eq!(
            plan.tunnel_prefixes,
            ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
        );
        assert!(plan.route_system_dns);
        assert!(plan.split_dns_domains.is_empty());
    }

    #[test]
    fn cidr_only_plan_installs_only_selected_network_routes() {
        let policy = SystemVpnPolicy::new(
            vec![
                "10.20.0.0/16".parse().unwrap(),
                "2001:db8:7::/48".parse().unwrap(),
            ],
            Vec::new(),
        )
        .unwrap();

        let plan = RoutePlan::for_policy(&policy);

        assert_eq!(plan.tunnel_prefixes, ["10.20.0.0/16", "2001:db8:7::/48"]);
        assert!(!plan.route_system_dns);
        assert!(plan.split_dns_domains.is_empty());
    }

    #[test]
    fn domain_plan_routes_the_fake_ip_pool_and_installs_split_dns() {
        let policy = SystemVpnPolicy::new(
            Vec::new(),
            vec!["anthem.com".to_string(), "elevancehealth.com".to_string()],
        )
        .unwrap();

        let plan = RoutePlan::for_policy(&policy);

        assert_eq!(plan.tunnel_prefixes, ["198.18.0.0/15"]);
        assert!(!plan.route_system_dns);
        assert_eq!(plan.split_dns_domains, ["anthem.com", "elevancehealth.com"]);
    }

    #[test]
    fn combined_plan_has_union_semantics_and_expands_default_cidrs() {
        let policy = SystemVpnPolicy::new(
            vec![
                "0.0.0.0/0".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            vec!["anthem.com".to_string()],
        )
        .unwrap();

        let plan = RoutePlan::for_policy(&policy);

        assert_eq!(
            plan.tunnel_prefixes,
            ["0.0.0.0/1", "128.0.0.0/1", "2001:db8::/32", "198.18.0.0/15"]
        );
        assert_eq!(plan.split_dns_domains, ["anthem.com"]);
    }

    #[test]
    fn ipv4_mapped_peer_addresses_are_normalized() {
        let mapped = "::ffff:192.0.2.9".parse().unwrap();

        assert_eq!(
            normalize_ip(mapped),
            "192.0.2.9".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_gateway_routes() {
        let route = super::parse_linux_route_path(
            "203.0.113.8 via 192.0.2.1 dev eth0 src 192.0.2.20 uid 1000",
        )
        .unwrap();

        assert_eq!(route.gateway.as_deref(), Some("192.0.2.1"));
        assert_eq!(route.interface, "eth0");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_resolver_configuration() {
        let servers = super::parse_resolv_conf(
            "# generated\nnameserver 127.0.0.53\nnameserver 2001:db8::53 # local\n",
        );

        assert_eq!(
            servers,
            vec![
                "127.0.0.53".parse::<std::net::IpAddr>().unwrap(),
                "2001:db8::53".parse::<std::net::IpAddr>().unwrap()
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_split_dns_uses_route_only_systemd_resolved_domains() {
        let executor = MockExecutor::default();
        let observer = executor.clone();
        let mut guard = RouteGuard::new(executor);

        super::configure_linux_split_dns(
            &mut guard,
            "tun7",
            &["anthem.com".to_string(), "elevancehealth.com".to_string()],
        )
        .unwrap();
        guard.restore().unwrap();

        let calls = observer.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].arguments, ["dns", "tun7", "198.18.0.1"]);
        assert_eq!(
            calls[1].arguments,
            ["domain", "tun7", "~anthem.com", "~elevancehealth.com"]
        );
        assert_eq!(calls[2].arguments, ["default-route", "tun7", "false"]);
        assert_eq!(calls[3].arguments, ["revert", "tun7"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_split_dns_dictionary_contains_server_and_match_domains() {
        use core_foundation::{array::CFArray, number::CFNumber, string::CFString};

        let dictionary = super::macos_dns_dictionary(&[
            "anthem.com".to_string(),
            "elevancehealth.com".to_string(),
        ]);

        let server_addresses = dictionary.find(CFString::new("ServerAddresses")).unwrap();
        assert_eq!(server_addresses.downcast::<CFArray>().unwrap().len(), 1);
        assert!(format!("{server_addresses:?}").contains("198.18.0.1"));
        let match_domains = dictionary
            .find(CFString::new("SupplementalMatchDomains"))
            .unwrap();
        assert_eq!(match_domains.downcast::<CFArray>().unwrap().len(), 2);
        let match_domains_description = format!("{match_domains:?}");
        assert!(match_domains_description.contains("anthem.com"));
        assert!(match_domains_description.contains("elevancehealth.com"));
        let no_search = dictionary
            .find(CFString::new("SupplementalMatchDomainsNoSearch"))
            .unwrap();
        assert_eq!(no_search.downcast::<CFNumber>().unwrap().to_i32(), Some(1));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_route_lookup_uses_the_route_object_returned_second() {
        let command = super::find_windows_route("203.0.113.8".parse().unwrap());

        assert_eq!(command.program, "powershell.exe");
        assert_eq!(
            command.arguments[..3],
            ["-NoLogo", "-NoProfile", "-NonInteractive"]
        );
        let script = command.arguments.last().unwrap();
        assert!(script.contains("$source, $route = Find-NetRoute -RemoteIPAddress '203.0.113.8'"));
        assert!(script.contains("InterfaceIndex=$route.InterfaceIndex"));
        assert!(script.contains("NextHop=$route.NextHop"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_route_changes_are_scoped_to_the_active_store() {
        let executor = MockExecutor::default();
        let observer = executor.clone();
        let mut guard = RouteGuard::new(executor);

        super::apply_windows_route(&mut guard, "0.0.0.0/1", 14, "10.254.0.1").unwrap();
        guard.restore().unwrap();

        let calls = observer.calls();
        assert_eq!(calls.len(), 2);
        let setup = calls[0].arguments.last().unwrap();
        assert!(setup.contains("New-NetRoute -DestinationPrefix '0.0.0.0/1'"));
        assert!(setup.contains("-InterfaceIndex 14 -NextHop '10.254.0.1'"));
        assert!(setup.contains("-RouteMetric 4 -PolicyStore ActiveStore"));
        let rollback = calls[1].arguments.last().unwrap();
        assert!(rollback.contains("Get-NetRoute -DestinationPrefix '0.0.0.0/1'"));
        assert!(rollback.contains("Remove-NetRoute -Confirm:$false"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_split_dns_uses_session_scoped_suffix_nrpt_rules() {
        let executor = MockExecutor::default();
        let observer = executor.clone();
        let mut guard = RouteGuard::new(executor);

        super::configure_windows_split_dns(
            &mut guard,
            &["anthem.com".to_string(), "elevancehealth.com".to_string()],
        )
        .unwrap();
        guard.restore().unwrap();

        let calls = observer.calls();
        assert_eq!(calls.len(), 5);
        let anthem_setup = calls[0].arguments.last().unwrap();
        assert!(anthem_setup.contains("-Namespace 'anthem.com','.anthem.com'"));
        assert!(anthem_setup.contains("-NameServers '198.18.0.1'"));
        assert!(anthem_setup.contains("-DisplayName 'SSHPortal-"));
        let elevance_setup = calls[1].arguments.last().unwrap();
        assert!(elevance_setup.contains("-Namespace 'elevancehealth.com','.elevancehealth.com'"));
        assert!(elevance_setup.contains("-DisplayName 'SSHPortal-"));
        let validation = calls[2].arguments.last().unwrap();
        assert!(validation.contains("Get-DnsClientNrptPolicy -Effective"));
        assert!(validation.contains("'anthem.com','.anthem.com'"));
        assert!(validation.contains("-contains '198.18.0.1'"));
        assert!(
            calls[3]
                .arguments
                .last()
                .unwrap()
                .contains("Clear-DnsClientCache")
        );
        let rollback = calls[4].arguments.last().unwrap();
        assert!(rollback.contains("$_.DisplayName -eq 'SSHPortal-"));
        assert!(rollback.contains("Remove-DnsClientNrptRule -Name $_.Name -Force"));
        assert!(rollback.contains("Clear-DnsClientCache"));
    }
}
