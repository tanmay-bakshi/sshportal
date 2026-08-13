use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::debug::debug_log;

const SPLIT_DEFAULT_ROUTES: [&str; 4] = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

#[cfg(target_os = "windows")]
use super::{VPN_GATEWAY_IPV4, VPN_INTERFACE_IPV6};

#[cfg(target_os = "windows")]
const ROUTE_METRIC: u32 = 4;

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

pub(super) struct RouteGuard<E: CommandExecutor = SystemCommandExecutor> {
    executor: E,
    rollback: Vec<CommandSpec>,
    active: bool,
}

impl<E: CommandExecutor> RouteGuard<E> {
    fn new(executor: E) -> Self {
        Self {
            executor,
            rollback: Vec::new(),
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

    pub(super) fn restore(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let mut first_error = None;
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
            Some(error) => Err(error).context("failed to restore one or more VPN routes"),
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
) -> Result<RouteGuard> {
    let executor = SystemCommandExecutor;
    configure_with_executor(tun_name, tun_index, transport_peers, executor)
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

    for dns_server in linux_dns_servers(&guard) {
        if transport_peers.contains(&dns_server) || dns_server.is_loopback() {
            continue;
        }
        apply_linux_tun_route(&mut guard, tun_name, &host_prefix(dns_server))?;
    }
    // Split defaults preserve the operating system's original defaults for rollback. Directly
    // attached networks remain local, while explicit DNS host routes prevent resolver leaks.
    for prefix in SPLIT_DEFAULT_ROUTES {
        apply_linux_tun_route(&mut guard, tun_name, prefix)?;
    }
    Ok(guard)
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

    let dns_output = guard.query(CommandSpec::new("scutil", ["--dns"]))?;
    for dns_server in deduplicate_ips(parse_macos_dns_servers(&dns_output)) {
        if transport_peers.contains(&dns_server) || dns_server.is_loopback() {
            continue;
        }
        apply_macos_tun_route(&mut guard, tun_name, &dns_server.to_string(), true)?;
    }
    // Split defaults preserve the operating system's original defaults for rollback. Directly
    // attached networks remain local, while explicit DNS host routes prevent resolver leaks.
    for prefix in SPLIT_DEFAULT_ROUTES {
        apply_macos_tun_route(&mut guard, tun_name, prefix, false)?;
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
    // Split defaults preserve the operating system's original defaults for rollback. Directly
    // attached networks remain local, while explicit DNS host routes prevent resolver leaks.
    for prefix in SPLIT_DEFAULT_ROUTES {
        let next_hop = if prefix.contains(':') {
            "::".to_string()
        } else {
            VPN_GATEWAY_IPV4.to_string()
        };
        apply_windows_route(&mut guard, prefix, tun_index, &next_hop)?;
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

    use super::{CommandExecutor, CommandSpec, RouteGuard, normalize_ip};

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
}
