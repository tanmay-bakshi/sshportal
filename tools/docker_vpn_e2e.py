#!/usr/bin/env python3

"""Run an isolated Linux end-to-end validation of sshportal VPN mode."""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
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


def run_checked(command: list[str]) -> None:
    """Run a command and fail if it exits unsuccessfully.

    :param command: Command and arguments to execute.
    """

    subprocess.run(command, cwd=PROJECT_ROOT, check=True)


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
            "echo.test",
            image_tag,
            "/bin/sh",
            "-lc",
            "printf '%s\\n' '#!/bin/sh' "
            "'printf \"HTTP/1.1 200 OK\\r\\nContent-Length: 11\\r\\n"
            "Connection: close\\r\\n\\r\\nvpn-tcp-ok\\n\"' "
            "> /tmp/http-response && "
            "chmod 0755 /tmp/http-response && "
            "nc -l -k -p 8081 -e /tmp/http-response & "
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


def start_server(image_tag: str) -> SpawnedProcess:
    """Start the privileged operator-side VPN server container.

    :param image_tag: Existing sshportal runtime image.
    :returns: Attached server process.
    """

    remove_container(SERVER_NAME)
    return spawn_pty_process(
        "VPN server",
        [
            "docker",
            "run",
            "--rm",
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
            "-it",
            image_tag,
            "/usr/local/bin/sshportal-server",
            "--listen",
            "0.0.0.0:8080",
            "--operator-name",
            "support-team",
            "--join-token",
            JOIN_TOKEN,
            "--vpn",
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


def run_probe(command: list[str], expected: str, label: str) -> None:
    """Run an operator-side probe and require expected output.

    :param command: Command to run inside the server container.
    :param expected: Required output fragment.
    :param label: Human-readable probe name.
    """

    output = command_output(["docker", "exec", SERVER_NAME, *command])
    if expected not in output:
        raise RuntimeError(f"{label} failed, expected {expected!r} in:\n{output}")


def run_vpn_session(image_tag: str, certificate_directory: Path) -> None:
    """Run the complete WSS, TUN, TCP, UDP, DNS, and cleanup test.

    :param image_tag: Existing sshportal runtime image.
    :param certificate_directory: Directory containing TLS test material.
    """

    echo_ip = start_echo_service(image_tag)
    server = start_server(image_tag)
    client: SpawnedProcess | None = None
    try:
        wait_for_text(server, "sshportal server listening on http://0.0.0.0:8080", 30.0)
        start_tls_proxy(certificate_directory)
        client = start_unprivileged_client(image_tag, certificate_directory)
        assert_client_is_unprivileged()
        wait_for_text(client, "VPN egress session approved", 30.0)
        server_transcript = wait_for_text(server, "VPN active on interface", 30.0)
        interface_match = re.search(r"VPN active on interface (\S+)", server_transcript)
        if interface_match is None:
            raise RuntimeError(f"could not identify VPN interface:\n{server_transcript}")
        interface_name = interface_match.group(1)

        run_probe(
            ["ip", "route", "get", echo_ip],
            f"dev {interface_name}",
            "TUN route",
        )
        run_probe(
            ["wget", "-qO-", "-T", "10", f"http://{echo_ip}:8081/"],
            "vpn-tcp-ok",
            "TCP tunnel",
        )
        run_probe(
            ["wget", "-qO-", "-T", "10", "http://echo.test:8081/"],
            "vpn-tcp-ok",
            "virtual DNS and client-side resolution",
        )
        run_probe(
            [
                "/bin/sh",
                "-lc",
                f"printf 'vpn-udp-ok' | nc -u -w 5 {echo_ip} 19090",
            ],
            "vpn-udp-ok",
            "UDP tunnel",
        )

        run_checked(["docker", "kill", "--signal", "INT", SERVER_NAME])
        server_exit_code = wait_for_process_exit(server, 30.0)
        read_available_output(server, 0.2)
        if server_exit_code != 0:
            raise RuntimeError(
                f"VPN server exited with {server_exit_code} during cleanup:\n{server.transcript}"
            )
        if "failed to restore VPN" in server.transcript:
            raise RuntimeError(f"VPN route cleanup failed:\n{server.transcript}")
    except RuntimeError as error:
        read_available_output(server, 0.2)
        client_transcript = ""
        if client is not None:
            read_available_output(client, 0.2)
            client_transcript = client.transcript
        raise RuntimeError(
            f"{error}\n\n"
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
        help="reuse an existing Docker image",
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

    certificate_directory = PROJECT_ROOT / ".tmp-docker-vpn-e2e"
    if certificate_directory.exists():
        shutil.rmtree(certificate_directory)
    certificate_directory.mkdir(parents=True)
    os.chmod(certificate_directory, 0o755)

    try:
        prepare_networks()
        generate_tls_material(certificate_directory)
        run_vpn_session(arguments.image_tag, certificate_directory)
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
