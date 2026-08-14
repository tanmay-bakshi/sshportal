#!/usr/bin/env python3

"""Run an isolated Linux end-to-end validation of sshportal VPN mode."""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path

from docker_e2e import (
    IMAGE_TAG,
    PROJECT_ROOT,
    SpawnedProcess,
    build_image,
    read_available_output,
    spawn_pty_process,
    terminate_process,
    wait_for_process_exit,
    wait_for_text,
)


CONTROL_NETWORK: str = "sshportal-vpn-e2e-control"
EGRESS_NETWORK: str = "sshportal-vpn-e2e-egress"
SERVER_NAME: str = "sshportal-vpn-e2e-server"
CLIENT_NAME: str = "sshportal-vpn-e2e-client"
PROXY_NAME: str = "sshportal-vpn-e2e-proxy"
ECHO_NAME: str = "sshportal-vpn-e2e-echo"
JOIN_TOKEN: str = "vpn-e2e-token"
TEST_DNS_SERVER: str = "203.0.113.53"
CLOSE_DELIMITED_BODY_SIZE: int = 256 * 1024
SERVER_IMAGE_SUFFIX: str = "-vpn-systemd-resolved"
SERVER_READY_FILE: str = "/run/sshportal-vpn-e2e-ready"
SERVER_PID_FILE: str = "/run/sshportal-server.pid"
RECOVERY_JOURNAL: str = "/var/run/sshportal/network-state.jsonl"
ECHO_DOMAIN: str = "echo.test"
SYNTHETIC_IPV4_RANGE: ipaddress.IPv4Network = ipaddress.IPv4Network("198.18.0.0/15")
POLICY_ROUTE_TABLE: int = 100
POLICY_RULE_PRIORITY: int = 100
FOREIGN_ROUTE_TABLE: int = 200


class VpnSessionPolicy(Enum):
    """VPN routing policies exercised by the privileged integration fixture."""

    FULL_TUNNEL = "full-tunnel"
    CIDR_SELECTIVE = "CIDR-selective"
    DOMAIN_SELECTIVE = "domain-selective"


def run_checked(command: list[str]) -> None:
    """Run a command and fail if it exits unsuccessfully.

    :param command: Command and arguments to execute.
    :raises RuntimeError: If the command exits unsuccessfully.
    """

    try:
        subprocess.run(command, cwd=PROJECT_ROOT, check=True)
    except subprocess.CalledProcessError as error:
        rendered_command = " ".join(command)
        raise RuntimeError(
            f"command exited with {error.returncode}: {rendered_command}"
        ) from error


def command_output(command: list[str]) -> str:
    """Run a command and return its standard output.

    :param command: Command and arguments to execute.
    :returns: Decoded standard output.
    """

    completed: subprocess.CompletedProcess[str] = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        rendered_command = " ".join(command)
        raise RuntimeError(
            f"command exited with {completed.returncode}: {rendered_command}\n{output}"
        )
    return output


def remove_container(name: str) -> None:
    """Force-remove one known test container if it exists.

    :param name: Exact container name.
    """

    subprocess.run(
        ["docker", "rm", "--force", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def remove_network(name: str) -> None:
    """Remove one known test network if it exists.

    :param name: Exact network name.
    """

    subprocess.run(
        ["docker", "network", "rm", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def prepare_networks() -> None:
    """Create isolated control and client-egress networks."""

    remove_network(CONTROL_NETWORK)
    remove_network(EGRESS_NETWORK)
    run_checked(["docker", "network", "create", CONTROL_NETWORK])
    run_checked(["docker", "network", "create", "--internal", EGRESS_NETWORK])


def generate_tls_material(directory: Path) -> None:
    """Generate a short-lived CA and proxy certificate for the WSS hop.

    :param directory: Directory that receives the certificate material.
    """

    extension_path = directory / "server.ext"
    extension_path.write_text(
        "subjectAltName=DNS:proxy\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    run_checked(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=sshportal VPN E2E CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(directory / "ca.key"),
            "-out",
            str(directory / "ca.crt"),
        ]
    )
    run_checked(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=proxy",
            "-keyout",
            str(directory / "server.key"),
            "-out",
            str(directory / "server.csr"),
        ]
    )
    run_checked(
        [
            "openssl",
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            str(directory / "server.csr"),
            "-CA",
            str(directory / "ca.crt"),
            "-CAkey",
            str(directory / "ca.key"),
            "-CAcreateserial",
            "-extfile",
            str(extension_path),
            "-out",
            str(directory / "server.crt"),
        ]
    )
    (directory / "Caddyfile").write_text(
        "{\n"
        "    auto_https off\n"
        "}\n"
        "https://proxy:8443 {\n"
        "    tls /certs/server.crt /certs/server.key\n"
        "    reverse_proxy server:8080\n"
        "}\n",
        encoding="utf-8",
    )


def start_echo_service(image_tag: str) -> str:
    """Start TCP and UDP echo endpoints reachable only from the client.

    :param image_tag: Existing sshportal runtime image.
    :returns: Echo container IPv4 address.
    """

    remove_container(ECHO_NAME)
    run_checked(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            ECHO_NAME,
            "--network",
            EGRESS_NETWORK,
            "--network-alias",
            ECHO_DOMAIN,
            image_tag,
            "/bin/sh",
            "-lc",
            "printf '%s\\n' '#!/bin/sh' "
            "'printf \"HTTP/1.1 200 OK\\r\\nContent-Length: 11\\r\\n"
            "Connection: close\\r\\n\\r\\nvpn-tcp-ok\\n\"' "
            "> /tmp/http-response && "
            "chmod 0755 /tmp/http-response && "
            "nc -l -k -p 8081 -e /tmp/http-response & "
            "printf \"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\n\\r\\n\" "
            "> /tmp/close-delimited-response && "
            f"head -c {CLOSE_DELIMITED_BODY_SIZE} /dev/zero | tr \"\\000\" x "
            ">> /tmp/close-delimited-response; "
            "nc -l -p 8082 < /tmp/close-delimited-response > /dev/null & "
            "exec nc -u -l -k -p 19090 -e cat",
        ]
    )
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        inspection = command_output(
            [
                "docker",
                "inspect",
                "--format",
                f"{{{{.State.Running}}}} "
                f"{{{{(index .NetworkSettings.Networks \"{EGRESS_NETWORK}\").IPAddress}}}}",
                ECHO_NAME,
            ]
        ).strip()
        running, _, echo_ip = inspection.partition(" ")
        if running != "true":
            logs = command_output(["docker", "logs", ECHO_NAME])
            raise RuntimeError(f"echo service exited during startup:\n{logs}")
        if len(echo_ip) > 0:
            return echo_ip
        time.sleep(0.1)

    raise RuntimeError("echo service did not receive an egress-network address")


def build_server_image(image_tag: str, platform: str | None) -> str:
    """Build the privileged test runtime with a real systemd-resolved control plane.

    :param image_tag: Existing sshportal runtime image containing the static binaries.
    :param platform: Optional Docker platform such as ``linux/amd64``.
    :returns: Derived server runtime image tag.
    """

    server_image_tag = f"{image_tag}{SERVER_IMAGE_SUFFIX}"
    command = [
        "docker",
        "buildx",
        "build",
        "--load",
        "--build-arg",
        f"SSHPORTAL_IMAGE={image_tag}",
        "--file",
        "tools/vpn_e2e_server.Dockerfile",
        "--tag",
        server_image_tag,
    ]
    if platform is not None:
        command.extend(["--platform", platform])
    command.append(".")
    run_checked(command)
    return server_image_tag


def wait_for_server_fixture() -> None:
    """Wait for DBus and systemd-resolved in the server container.

    :raises RuntimeError: If the fixture exits or does not become ready in time.
    """

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        ready = subprocess.run(
            ["docker", "exec", SERVER_NAME, "test", "-e", SERVER_READY_FILE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if ready.returncode == 0:
            return
        inspection = command_output(
            ["docker", "inspect", "--format", "{{.State.Running}}", SERVER_NAME]
        ).strip()
        if inspection != "true":
            logs = command_output(["docker", "logs", SERVER_NAME])
            raise RuntimeError(f"VPN server fixture exited during startup:\n{logs}")
        time.sleep(0.1)

    logs = command_output(["docker", "logs", SERVER_NAME])
    raise RuntimeError(f"VPN server fixture did not become ready:\n{logs}")


def start_server(
    image_tag: str,
    include_cidr: str | None,
    include_domain: str | None,
) -> SpawnedProcess:
    """Start the privileged operator-side VPN server container.

    :param image_tag: Existing sshportal runtime image.
    :param include_cidr: Optional CIDR for a selective VPN session.
    :param include_domain: Optional domain suffix for a selective VPN session.
    :returns: Attached server process.
    """

    remove_container(SERVER_NAME)
    run_checked(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            SERVER_NAME,
            "--network",
            CONTROL_NETWORK,
            "--network-alias",
            "server",
            "--dns",
            TEST_DNS_SERVER,
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "-e",
            "SSHPORTAL_DEBUG=1",
            image_tag,
            "sleep",
            "infinity",
        ]
    )
    wait_for_server_fixture()

    server_command: list[str] = [
        "/usr/local/bin/sshportal-server",
        "--listen",
        "0.0.0.0:8080",
        "--operator-name",
        "support-team",
        "--join-token",
        JOIN_TOKEN,
        "--vpn",
    ]
    if include_cidr is not None:
        server_command.extend(["--vpn-include-cidr", include_cidr])
    if include_domain is not None:
        server_command.extend(["--vpn-include-domain", include_domain])
    return spawn_pty_process(
        "VPN server",
        [
            "docker",
            "exec",
            "--interactive",
            "--tty",
            SERVER_NAME,
            "/bin/bash",
            "-lc",
            f"printf '%s\\n' \"$BASHPID\" > {SERVER_PID_FILE}; exec \"$@\"",
            "sshportal-vpn-e2e-server",
            *server_command,
        ],
    )


def start_tls_proxy(certificate_directory: Path) -> None:
    """Start a Caddy reverse proxy for the encrypted client hop.

    :param certificate_directory: Directory containing Caddy and TLS files.
    """

    remove_container(PROXY_NAME)
    run_checked(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            PROXY_NAME,
            "--network",
            CONTROL_NETWORK,
            "--network-alias",
            "proxy",
            "-v",
            f"{certificate_directory}:/certs:ro",
            "-v",
            f"{certificate_directory / 'Caddyfile'}:/etc/caddy/Caddyfile:ro",
            "caddy:2.10.2-alpine",
        ]
    )
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        logs = command_output(["docker", "logs", PROXY_NAME])
        if "serving initial configuration" in logs:
            return
        time.sleep(0.2)
    raise RuntimeError(f"Caddy did not become ready:\n{logs}")


def container_ipv4_address(name: str, network: str) -> str:
    """Return one container's IPv4 address on a named Docker network.

    :param name: Exact container name.
    :param network: Exact Docker network name.
    :returns: Validated IPv4 address.
    :raises RuntimeError: If Docker reports no valid address.
    """

    output = command_output(
        [
            "docker",
            "inspect",
            "--format",
            f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
            name,
        ]
    ).strip()
    try:
        return str(ipaddress.IPv4Address(output))
    except ipaddress.AddressValueError as error:
        raise RuntimeError(
            f"container {name} has no valid IPv4 address on network {network}: {output!r}"
        ) from error


def network_ipv4_subnet(name: str) -> ipaddress.IPv4Network:
    """Return the IPv4 subnet assigned to a Docker network.

    :param name: Exact Docker network name.
    :returns: Validated IPv4 network.
    :raises RuntimeError: If Docker reports no valid IPv4 subnet.
    """

    output = command_output(
        [
            "docker",
            "network",
            "inspect",
            "--format",
            "{{(index .IPAM.Config 0).Subnet}}",
            name,
        ]
    ).strip()
    try:
        network = ipaddress.ip_network(output)
    except ValueError as error:
        raise RuntimeError(
            f"Docker network {name} has no valid subnet: {output!r}"
        ) from error
    if not isinstance(network, ipaddress.IPv4Network):
        raise RuntimeError(f"Docker network {name} unexpectedly uses IPv6: {network}")
    return network


def json_records(command: list[str], label: str) -> list[dict[str, object]]:
    """Run a command that must return a JSON array of objects.

    :param command: Command and arguments to execute.
    :param label: Human-readable output description.
    :returns: Decoded object records.
    :raises RuntimeError: If the output does not have the expected shape.
    """

    output = command_output(command)
    try:
        decoded: object = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} returned invalid JSON:\n{output}") from error
    if not isinstance(decoded, list) or not all(
        isinstance(record, dict) for record in decoded
    ):
        raise RuntimeError(f"{label} returned a non-object JSON inventory:\n{output}")
    return decoded


def configure_source_policy_routing(transport_peer: str) -> None:
    """Route the server's WebSocket source through a non-main Linux table.

    :param transport_peer: Immediate WebSocket peer inside the control network.
    :raises RuntimeError: If the physical control path cannot be identified.
    """

    server_address = container_ipv4_address(SERVER_NAME, CONTROL_NETWORK)
    control_subnet = network_ipv4_subnet(CONTROL_NETWORK)
    if ipaddress.IPv4Address(server_address) not in control_subnet:
        raise RuntimeError(
            f"server address {server_address} is outside control subnet {control_subnet}"
        )
    if ipaddress.IPv4Address(transport_peer) not in control_subnet:
        raise RuntimeError(
            f"WebSocket peer {transport_peer} is outside control subnet {control_subnet}"
        )

    records = json_records(
        [
            "docker",
            "exec",
            SERVER_NAME,
            "ip",
            "-j",
            "-4",
            "route",
            "get",
            transport_peer,
            "from",
            server_address,
        ],
        "initial WebSocket route lookup",
    )
    if len(records) != 1:
        raise RuntimeError(
            f"initial WebSocket route lookup returned {len(records)} records"
        )
    interface = records[0].get("dev")
    if not isinstance(interface, str) or len(interface) == 0:
        raise RuntimeError(
            "initial WebSocket route lookup did not identify a physical interface"
        )

    run_checked(
        [
            "docker",
            "exec",
            SERVER_NAME,
            "ip",
            "-4",
            "route",
            "add",
            "table",
            str(POLICY_ROUTE_TABLE),
            str(control_subnet),
            "dev",
            interface,
            "src",
            server_address,
        ]
    )
    run_checked(
        [
            "docker",
            "exec",
            SERVER_NAME,
            "ip",
            "-4",
            "rule",
            "add",
            "priority",
            str(POLICY_RULE_PRIORITY),
            "from",
            f"{server_address}/32",
            "table",
            str(POLICY_ROUTE_TABLE),
        ]
    )
    run_probe(
        ["ip", "-4", "rule", "show"],
        f"from {server_address} lookup {POLICY_ROUTE_TABLE}",
        "source policy rule",
    )
    run_probe(
        [
            "ip",
            "-4",
            "route",
            "show",
            "table",
            str(POLICY_ROUTE_TABLE),
            "exact",
            str(control_subnet),
        ],
        f"dev {interface}",
        "non-main control-network route",
    )


def start_unprivileged_client(image_tag: str, certificate_directory: Path) -> SpawnedProcess:
    """Create a two-network client container and run sshportal without privileges.

    :param image_tag: Existing sshportal runtime image.
    :param certificate_directory: Directory containing the test CA.
    :returns: Attached client process.
    """

    remove_container(CLIENT_NAME)
    client_url = f"https://proxy:8443/connect?token={JOIN_TOKEN}"
    run_checked(
        [
            "docker",
            "create",
            "--rm",
            "--name",
            CLIENT_NAME,
            "--network",
            EGRESS_NETWORK,
            "-v",
            f"{certificate_directory / 'ca.crt'}:/usr/local/share/ca-certificates/sshportal-e2e.crt:ro",
            "-e",
            "TERM=dumb",
            "-it",
            image_tag,
            "/bin/sh",
            "-lc",
            "update-ca-certificates >/dev/null && "
            "exec su nobody -s /bin/sh -c "
            f"'/usr/local/bin/sshportal-client --server \"{client_url}\" --approve-session'",
        ]
    )
    run_checked(
        [
            "docker",
            "network",
            "connect",
            "--alias",
            "client",
            CONTROL_NETWORK,
            CLIENT_NAME,
        ]
    )
    return spawn_pty_process(
        "unprivileged VPN client",
        ["docker", "start", "--attach", "--interactive", CLIENT_NAME],
    )


def assert_client_is_unprivileged() -> None:
    """Verify that the client container has neither NET_ADMIN nor a TUN device."""

    inspection = command_output(["docker", "inspect", CLIENT_NAME])
    if re.search(r'"NET_ADMIN"', inspection) is not None:
        raise RuntimeError("VPN client unexpectedly has NET_ADMIN")
    if re.search(r'"PathOnHost":\s*"/dev/net/tun"', inspection) is not None:
        raise RuntimeError("VPN client unexpectedly has a TUN device")


def run_probe(command: list[str], expected: str, label: str) -> str:
    """Run an operator-side probe and require expected output.

    :param command: Command to run inside the server container.
    :param expected: Required output fragment.
    :param label: Human-readable probe name.
    :returns: Combined standard output and standard error.
    """

    output = command_output(["docker", "exec", SERVER_NAME, *command])
    if expected not in output:
        raise RuntimeError(f"{label} failed, expected {expected!r} in:\n{output}")
    return output


def run_probe_excluding(command: list[str], unexpected: str, label: str) -> None:
    """Run an operator-side probe and reject an unexpected output fragment.

    :param command: Command to run inside the server container.
    :param unexpected: Output fragment that must not appear.
    :param label: Human-readable probe name.
    """

    output = command_output(["docker", "exec", SERVER_NAME, *command])
    if unexpected in output:
        raise RuntimeError(
            f"{label} failed, did not expect {unexpected!r} in:\n{output}"
        )


def resolve_selected_domain(interface_name: str, real_address: str) -> str:
    """Resolve the client-only test name through the tunnel's split-DNS link.

    :param interface_name: Active TUN interface name.
    :param real_address: Echo service address visible only to the client.
    :returns: Synthetic IPv4 address returned to the operator.
    :raises RuntimeError: If systemd-resolved does not use the selective tunnel policy.
    """

    run_probe(
        ["resolvectl", "status", interface_name],
        f"DNS Domain: ~{ECHO_DOMAIN}",
        "systemd-resolved suffix route",
    )
    resolution = run_probe(
        ["resolvectl", "query", "--cache=no", "--type=A", ECHO_DOMAIN],
        ECHO_DOMAIN,
        "domain-selective DNS query",
    )
    for candidate in re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", resolution):
        try:
            address = ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            continue
        if address not in SYNTHETIC_IPV4_RANGE:
            continue
        if str(address) == real_address:
            raise RuntimeError("selected DNS query exposed the client's real echo address")
        run_probe(
            ["ip", "route", "get", str(address)],
            f"dev {interface_name}",
            "synthetic-address TUN route",
        )
        return str(address)

    raise RuntimeError(
        "domain-selective DNS query did not return an RFC 2544 synthetic IPv4 address:\n"
        f"{resolution}"
    )


def wait_for_host_network_cleanup(
    interface_name: str,
    transport_peer: str,
    preserved_foreign_prefix: str | None = None,
) -> None:
    """Wait for session-owned network state to disappear.

    :param interface_name: TUN interface expected to be removed.
    :param transport_peer: Immediate WebSocket peer whose bypass route must be removed.
    :param preserved_foreign_prefix: Optional foreign route that must remain untouched.
    :raises RuntimeError: If cleanup is incomplete.
    """

    deadline = time.monotonic() + 5.0
    link_output = ""
    bypass_output = ""
    resolved_status = ""
    foreign_output = ""
    journal_exists = True
    while time.monotonic() < deadline:
        link = subprocess.run(
            [
                "docker",
                "exec",
                SERVER_NAME,
                "ip",
                "link",
                "show",
                "dev",
                interface_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        link_output = link.stdout
        bypass_output = command_output(
            [
                "docker",
                "exec",
                SERVER_NAME,
                "ip",
                "-4",
                "route",
                "show",
                "table",
                "all",
                "exact",
                f"{transport_peer}/32",
            ]
        )
        resolved_status = command_output(
            ["docker", "exec", SERVER_NAME, "resolvectl", "status"]
        )
        journal = subprocess.run(
            ["docker", "exec", SERVER_NAME, "test", "-e", RECOVERY_JOURNAL],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        journal_exists = journal.returncode == 0
        foreign_route_preserved = preserved_foreign_prefix is None
        if preserved_foreign_prefix is not None:
            preserved_foreign_address = str(
                ipaddress.ip_network(preserved_foreign_prefix).network_address
            )
            foreign_output = command_output(
                [
                    "docker",
                    "exec",
                    SERVER_NAME,
                    "ip",
                    "-4",
                    "route",
                    "show",
                    "table",
                    str(FOREIGN_ROUTE_TABLE),
                    "exact",
                    preserved_foreign_prefix,
                ]
            )
            foreign_route_preserved = (
                preserved_foreign_address in foreign_output
                and "dev lo" in foreign_output
            )
        if (
            link.returncode != 0
            and len(bypass_output) == 0
            and f"({interface_name})" not in resolved_status
            and not journal_exists
            and foreign_route_preserved
        ):
            return
        time.sleep(0.1)

    raise RuntimeError(
        "VPN host-network state survived server shutdown:\n"
        f"interface:\n{link_output}\n"
        f"transport bypass:\n{bypass_output}\n"
        f"systemd-resolved:\n{resolved_status}\n"
        f"recovery journal exists: {journal_exists}\n"
        f"preserved foreign route:\n{foreign_output}"
    )


def stop_server_and_verify_cleanup(
    server: SpawnedProcess,
    interface_name: str,
    transport_peer: str,
) -> None:
    """Gracefully stop the VPN server and inspect host-network cleanup.

    :param server: Attached server process.
    :param interface_name: TUN interface expected to be removed.
    :param transport_peer: Immediate WebSocket peer whose bypass route must be removed.
    :raises RuntimeError: If shutdown or cleanup is incomplete.
    """

    run_checked(
        [
            "docker",
            "exec",
            SERVER_NAME,
            "/bin/bash",
            "-lc",
            f'kill -INT "$(cat {SERVER_PID_FILE})"',
        ]
    )
    server_exit_code = wait_for_process_exit(server, 30.0)
    read_available_output(server, 0.2)
    if server_exit_code != 0:
        raise RuntimeError(
            f"VPN server exited with {server_exit_code} during cleanup:\n{server.transcript}"
        )
    if "failed to restore VPN" in server.transcript:
        raise RuntimeError(f"VPN route cleanup failed:\n{server.transcript}")
    wait_for_host_network_cleanup(interface_name, transport_peer)


def install_foreign_synthetic_route(interface_name: str) -> str:
    """Install a foreign host route inside the active synthetic IPv4 pool.

    :param interface_name: Active TUN interface carrying the synthetic pool.
    :returns: Installed foreign host prefix.
    :raises RuntimeError: If the active pool cannot be identified.
    """

    records = json_records(
        [
            "docker",
            "exec",
            SERVER_NAME,
            "ip",
            "-j",
            "-4",
            "route",
            "show",
            "dev",
            interface_name,
        ],
        "active TUN route inventory",
    )
    synthetic_networks: list[ipaddress.IPv4Network] = []
    for record in records:
        destination = record.get("dst")
        if not isinstance(destination, str):
            continue
        try:
            network = ipaddress.ip_network(destination)
        except ValueError:
            continue
        if not isinstance(network, ipaddress.IPv4Network):
            continue
        if network.subnet_of(SYNTHETIC_IPV4_RANGE):
            synthetic_networks.append(network)
    if len(synthetic_networks) != 1:
        raise RuntimeError(
            "active TUN route inventory did not identify exactly one synthetic "
            f"IPv4 pool: {synthetic_networks}"
        )

    collision_address = synthetic_networks[0].network_address + 42
    collision_prefix = f"{collision_address}/32"
    run_checked(
        [
            "docker",
            "exec",
            SERVER_NAME,
            "ip",
            "-4",
            "route",
            "add",
            "table",
            str(FOREIGN_ROUTE_TABLE),
            collision_prefix,
            "dev",
            "lo",
        ]
    )
    run_probe(
        [
            "ip",
            "-4",
            "route",
            "show",
            "table",
            str(FOREIGN_ROUTE_TABLE),
            "exact",
            collision_prefix,
        ],
        "dev lo",
        "foreign synthetic-pool collision",
    )
    return collision_prefix


def verify_collision_fails_closed(
    server: SpawnedProcess,
    interface_name: str,
    transport_peer: str,
) -> None:
    """Trigger reconciliation failure and verify complete owned-state restoration.

    :param server: Attached server process.
    :param interface_name: Active TUN interface expected to be removed.
    :param transport_peer: Immediate WebSocket peer whose bypass route must be removed.
    :raises RuntimeError: If the session does not fail closed and cleanly.
    """

    foreign_prefix = install_foreign_synthetic_route(interface_name)
    server_exit_code = wait_for_process_exit(server, 30.0)
    read_available_output(server, 0.2)
    if server_exit_code == 0:
        raise RuntimeError(
            "VPN server accepted a foreign route overlapping its synthetic pool"
        )
    expected_error = "overlaps an immutable VPN address range"
    if expected_error not in server.transcript:
        raise RuntimeError(
            f"VPN server exited without the immutable-overlap error:\n{server.transcript}"
        )
    if "failed to restore VPN" in server.transcript:
        raise RuntimeError(f"VPN route cleanup failed:\n{server.transcript}")
    wait_for_host_network_cleanup(
        interface_name,
        transport_peer,
        preserved_foreign_prefix=foreign_prefix,
    )


def run_vpn_session(
    image_tag: str,
    server_image_tag: str,
    certificate_directory: Path,
    policy: VpnSessionPolicy,
) -> None:
    """Run the complete WSS, TUN, TCP, UDP, DNS, and cleanup test.

    :param image_tag: Existing sshportal runtime image.
    :param server_image_tag: Privileged test runtime with systemd-resolved.
    :param certificate_directory: Directory containing TLS test material.
    :param policy: Routing policy to exercise.
    """

    echo_ip = start_echo_service(image_tag)
    include_cidr = (
        f"{echo_ip}/32" if policy is VpnSessionPolicy.CIDR_SELECTIVE else None
    )
    include_domain = (
        ECHO_DOMAIN if policy is VpnSessionPolicy.DOMAIN_SELECTIVE else None
    )
    server = start_server(server_image_tag, include_cidr, include_domain)
    client: SpawnedProcess | None = None
    try:
        wait_for_text(server, "sshportal server listening on http://0.0.0.0:8080", 30.0)
        start_tls_proxy(certificate_directory)
        transport_peer = container_ipv4_address(PROXY_NAME, CONTROL_NETWORK)
        configure_source_policy_routing(transport_peer)
        client = start_unprivileged_client(image_tag, certificate_directory)
        assert_client_is_unprivileged()
        wait_for_text(client, "VPN egress session approved", 30.0)
        server_transcript = wait_for_text(server, "VPN active on interface", 30.0)
        interface_match = re.search(r"VPN active on interface (\S+)", server_transcript)
        if interface_match is None:
            raise RuntimeError(f"could not identify VPN interface:\n{server_transcript}")
        interface_name = interface_match.group(1)
        run_checked(
            ["docker", "exec", SERVER_NAME, "test", "-f", RECOVERY_JOURNAL]
        )
        bypass_output = run_probe(
            [
                "ip",
                "-4",
                "route",
                "show",
                "table",
                "all",
                "exact",
                f"{transport_peer}/32",
            ],
            transport_peer,
            "WebSocket peer physical-route bypass",
        )
        if f"table {POLICY_ROUTE_TABLE}" not in bypass_output:
            raise RuntimeError(
                "WebSocket bypass escaped the source-selected policy table:\n"
                f"{bypass_output}"
            )

        if policy is VpnSessionPolicy.DOMAIN_SELECTIVE:
            run_probe_excluding(
                ["ip", "route", "get", echo_ip],
                f"dev {interface_name}",
                "real destination remains outside the selective route",
            )
            synthetic_ip = resolve_selected_domain(interface_name, echo_ip)
            run_probe(
                ["wget", "-qO-", "-T", "10", f"http://{synthetic_ip}:8081/"],
                "vpn-tcp-ok",
                "synthetic-address hostname reversal",
            )
        else:
            run_probe(
                ["ip", "route", "get", echo_ip],
                f"dev {interface_name}",
                "TUN route",
            )
        if policy is not VpnSessionPolicy.FULL_TUNNEL:
            run_probe_excluding(
                ["ip", "route", "get", "1.1.1.1"],
                f"dev {interface_name}",
                "unmatched direct route",
            )

        destination = (
            ECHO_DOMAIN
            if policy is VpnSessionPolicy.DOMAIN_SELECTIVE
            else echo_ip
        )
        run_probe(
            ["wget", "-qO-", "-T", "10", f"http://{destination}:8081/"],
            "vpn-tcp-ok",
            "TCP tunnel",
        )
        run_probe(
            [
                "/bin/sh",
                "-lc",
                f"wget -qO /tmp/close-delimited-body -T 10 http://{destination}:8082/ && "
                "wc -c < /tmp/close-delimited-body",
            ],
            str(CLOSE_DELIMITED_BODY_SIZE),
            "close-delimited TCP response",
        )
        if policy is VpnSessionPolicy.FULL_TUNNEL:
            run_probe(
                ["wget", "-qO-", "-T", "10", f"http://{ECHO_DOMAIN}:8081/"],
                "vpn-tcp-ok",
                "virtual DNS and client-side resolution",
            )
        run_probe(
            [
                "/bin/sh",
                "-lc",
                f"printf 'vpn-udp-ok' | nc -u -w 5 {destination} 19090",
            ],
            "vpn-udp-ok",
            "UDP tunnel",
        )

        if policy is VpnSessionPolicy.DOMAIN_SELECTIVE:
            verify_collision_fails_closed(server, interface_name, transport_peer)
        else:
            stop_server_and_verify_cleanup(server, interface_name, transport_peer)
    except RuntimeError as error:
        read_available_output(server, 0.2)
        client_transcript = ""
        if client is not None:
            read_available_output(client, 0.2)
            client_transcript = client.transcript
        raise RuntimeError(
            f"{policy.value} session failed: {error}\n\n"
            f"--- VPN server transcript ---\n{server.transcript}\n\n"
            f"--- VPN client transcript ---\n{client_transcript}"
        ) from error
    finally:
        if client is not None:
            terminate_process(client)
        terminate_process(server)
        for name in [CLIENT_NAME, SERVER_NAME, PROXY_NAME, ECHO_NAME]:
            remove_container(name)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    :returns: Parsed arguments.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="reuse an existing base Docker image",
    )
    parser.add_argument(
        "--image-tag",
        default=IMAGE_TAG,
        help=f"Docker image tag to build and run (default: {IMAGE_TAG})",
    )
    parser.add_argument(
        "--platform",
        help="Optional Docker platform such as linux/amd64 or linux/arm64",
    )
    return parser.parse_args()


def main() -> int:
    """Run the VPN end-to-end test.

    :returns: Process exit status.
    """

    arguments = parse_arguments()
    if arguments.skip_build is False:
        build_image(arguments.image_tag, arguments.platform)
    server_image_tag = build_server_image(arguments.image_tag, arguments.platform)

    certificate_directory = PROJECT_ROOT / ".tmp-docker-vpn-e2e"
    if certificate_directory.exists():
        shutil.rmtree(certificate_directory)
    certificate_directory.mkdir(parents=True)
    os.chmod(certificate_directory, 0o755)
    try:
        for name in [CLIENT_NAME, SERVER_NAME, PROXY_NAME, ECHO_NAME]:
            remove_container(name)
        prepare_networks()
        generate_tls_material(certificate_directory)
        for policy in VpnSessionPolicy:
            run_vpn_session(
                arguments.image_tag,
                server_image_tag,
                certificate_directory,
                policy,
            )
    finally:
        for name in [CLIENT_NAME, SERVER_NAME, PROXY_NAME, ECHO_NAME]:
            remove_container(name)
        remove_network(CONTROL_NETWORK)
        remove_network(EGRESS_NETWORK)
        shutil.rmtree(certificate_directory, ignore_errors=True)

    print("docker VPN end-to-end validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
