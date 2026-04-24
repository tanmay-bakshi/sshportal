#!/usr/bin/env python3

"""Run a Linux Docker-backed end-to-end validation of sshportal."""

import argparse
import fcntl
import http.client
import os
import platform as platform_module
import pty
import re
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import time
import termios
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
IMAGE_TAG: str = "sshportal:e2e"
NETWORK_NAME: str = "sshportal-e2e"
SERVER_NAME: str = "sshportal-e2e-server"
CLIENT_NAME: str = "sshportal-e2e-client"
HOST_PORT: int = 18080
HOST_SSH_PORT: int = 18222
READ_CHUNK_SIZE: int = 4096
DEFAULT_TERMINAL_ROWS: int = 40
DEFAULT_TERMINAL_COLS: int = 120


@dataclass
class SpawnedProcess:
    """Track a PTY-backed subprocess and its captured output.

    :ivar label: Human-readable name used in diagnostics.
    :ivar process: Child process handle.
    :ivar master_fd: PTY file descriptor used for both input and output.
    :ivar transcript: Raw text seen from the process so far.
    """

    label: str
    process: subprocess.Popen[bytes]
    master_fd: int
    transcript: str


def run_checked(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> None:
    """Run a subprocess and fail fast on errors.

    :param command: Command and arguments to execute.
    :param cwd: Optional working directory.
    :param env: Optional environment override.
    """

    subprocess.run(command, cwd=cwd, check=True, env=env)


def resolve_target_triple(requested_platform: str | None) -> str:
    """Resolve the Linux musl target triple for a Docker platform.

    :param requested_platform: Optional Docker platform such as ``linux/amd64``.
    :returns: Matching Rust target triple.
    :raises RuntimeError: If the platform or host architecture is unsupported.
    """

    if requested_platform is not None:
        if requested_platform == "linux/amd64":
            return "x86_64-unknown-linux-musl"
        if requested_platform == "linux/arm64":
            return "aarch64-unknown-linux-musl"
        raise RuntimeError(f"unsupported Docker platform: {requested_platform}")

    host_machine = platform_module.machine()
    if host_machine in ("x86_64", "amd64"):
        return "x86_64-unknown-linux-musl"
    if host_machine in ("arm64", "aarch64"):
        return "aarch64-unknown-linux-musl"
    raise RuntimeError(f"unsupported host architecture: {host_machine}")


def build_host_binaries(target_triple: str) -> None:
    """Build the static Linux binaries on the host before image assembly.

    :param target_triple: Rust target triple to build.
    """

    build_environment = resolve_build_environment(target_triple)
    run_checked(["rustup", "target", "add", target_triple], cwd=PROJECT_ROOT)
    run_checked(
        ["cargo", "build", "--release", "--target", target_triple, "--bins"],
        cwd=PROJECT_ROOT,
        env=build_environment,
    )


def resolve_build_environment(target_triple: str) -> dict[str, str]:
    """Resolve environment overrides needed for host-side target builds.

    :param target_triple: Rust target triple to build.
    :returns: Process environment for the build commands.
    :raises RuntimeError: If a required Linux musl toolchain is unavailable.
    """

    environment = os.environ.copy()
    if target_triple != "x86_64-unknown-linux-musl":
        return environment
    if platform_module.system() != "Linux":
        return environment
    if shutil.which("x86_64-linux-musl-gcc") is not None:
        return environment

    musl_gcc = shutil.which("musl-gcc")
    if musl_gcc is None:
        raise RuntimeError(
            "building x86_64-unknown-linux-musl requires a musl C toolchain; "
            "install musl-tools or provide x86_64-linux-musl-gcc"
        )

    environment["CC_x86_64_unknown_linux_musl"] = musl_gcc
    environment["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"] = musl_gcc
    return environment


def build_image(image_tag: str, platform: str | None) -> None:
    """Build the Docker runtime image for both binaries.

    :param image_tag: Image tag to build.
    :param platform: Optional Docker platform such as ``linux/amd64``.
    """

    target_triple = resolve_target_triple(platform)
    build_host_binaries(target_triple)
    command: list[str] = ["docker", "buildx", "build", "--load", "-t", image_tag]
    if platform is not None:
        command.extend(["--platform", platform])
    command.extend(["--build-arg", f"TARGET_TRIPLE={target_triple}"])
    command.append(".")
    run_checked(command, cwd=PROJECT_ROOT)


def remove_container(name: str) -> None:
    """Remove a leftover container if present.

    :param name: Container name.
    """

    subprocess.run(
        ["docker", "rm", "-f", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def recreate_network() -> None:
    """Create the dedicated Docker network for the test run."""

    subprocess.run(
        ["docker", "network", "rm", NETWORK_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    run_checked(["docker", "network", "create", NETWORK_NAME])


def spawn_pty_process(label: str, command: list[str]) -> SpawnedProcess:
    """Start a PTY-backed subprocess and capture its terminal output.

    :param label: Human-readable name used in diagnostics.
    :param command: Command and arguments to execute.
    :returns: Running process descriptor.
    """

    master_fd, slave_fd = pty.openpty()
    set_pty_window_size(slave_fd, DEFAULT_TERMINAL_ROWS, DEFAULT_TERMINAL_COLS)
    process = subprocess.Popen(
        command,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        text=False,
        cwd=PROJECT_ROOT,
        start_new_session=True,
    )
    os.close(slave_fd)
    return SpawnedProcess(label=label, process=process, master_fd=master_fd, transcript="")


def set_pty_window_size(fd: int, rows: int, cols: int) -> None:
    """Apply a terminal size to a PTY file descriptor.

    :param fd: PTY file descriptor.
    :param rows: Terminal row count.
    :param cols: Terminal column count.
    """

    packed = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)


def read_available_output(spawned: SpawnedProcess, timeout_seconds: float) -> str:
    """Read any PTY output currently available.

    :param spawned: Process descriptor.
    :param timeout_seconds: Maximum time to wait for new output.
    :returns: Newly read text.
    """

    selector = selectors.DefaultSelector()
    selector.register(spawned.master_fd, selectors.EVENT_READ)
    chunks: list[str] = []
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        events = selector.select(remaining)
        if len(events) == 0:
            break
        for _key, _mask in events:
            try:
                data = os.read(spawned.master_fd, READ_CHUNK_SIZE)
            except OSError:
                data = b""
            if len(data) == 0:
                break
            decoded = data.decode(errors="replace")
            chunks.append(decoded)
        if len(events) == 0:
            break
    output = "".join(chunks)
    if len(output) > 0:
        spawned.transcript += output
    return output


def wait_for_text(spawned: SpawnedProcess, expected: str, timeout_seconds: float) -> str:
    """Wait until a PTY transcript contains the expected text.

    :param spawned: Process descriptor.
    :param expected: Required substring.
    :param timeout_seconds: Maximum wait time.
    :returns: The full transcript observed so far.
    :raises RuntimeError: If the text does not appear in time.
    """

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        read_available_output(spawned, 0.2)
        if expected in spawned.transcript:
            return spawned.transcript
        if spawned.process.poll() is not None:
            raise RuntimeError(
                f"{spawned.label} exited early while waiting for {expected!r}\n"
                f"{spawned.transcript}"
            )
    raise RuntimeError(
        f"timed out waiting for {expected!r} from {spawned.label}\n{spawned.transcript}"
    )


def session_failure(message: str, server: SpawnedProcess, client: SpawnedProcess | None) -> RuntimeError:
    """Build a detailed session failure with both PTY transcripts.

    :param message: Human-readable error summary.
    :param server: Server process descriptor.
    :param client: Optional client process descriptor.
    :returns: Rich exception with attached transcripts.
    """

    client_transcript = ""
    if client is not None:
        client_transcript = client.transcript
    return RuntimeError(
        f"{message}\n\n"
        f"--- server transcript ---\n{server.transcript}\n\n"
        f"--- client transcript ---\n{client_transcript}"
    )


def send_input(spawned: SpawnedProcess, text: str) -> None:
    """Send raw keystrokes to a PTY-backed process.

    :param spawned: Process descriptor.
    :param text: Text to write.
    """

    normalized = text.replace("\n", "\r")
    os.write(spawned.master_fd, normalized.encode())


def wait_for_http(url: str, timeout_seconds: float) -> str:
    """Wait for an HTTP endpoint to become reachable.

    :param url: URL to fetch.
    :param timeout_seconds: Maximum wait time.
    :returns: Response body.
    :raises RuntimeError: If the endpoint never becomes reachable.
    """

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                body = response.read().decode()
                return body
        except (
            urllib.error.URLError,
            http.client.RemoteDisconnected,
            ConnectionResetError,
        ):
            time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for {url}")


def assert_http_unreachable(url: str, timeout_seconds: float) -> None:
    """Verify that an HTTP endpoint stops accepting connections.

    :param url: URL to probe.
    :param timeout_seconds: Maximum wait time.
    :raises RuntimeError: If the endpoint remains reachable.
    """

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0):
                time.sleep(0.2)
                continue
        except (
            urllib.error.URLError,
            http.client.RemoteDisconnected,
            ConnectionResetError,
        ):
            return
    raise RuntimeError(f"{url} stayed reachable after client attachment")


def run_shell_command(
    spawned: SpawnedProcess,
    command: str,
    marker_name: str,
    timeout_seconds: float,
) -> str:
    """Run a shell command through the attached server PTY and capture its output.

    :param spawned: Server process descriptor.
    :param command: Shell command to execute remotely.
    :param marker_name: Unique token used to detect completion.
    :param timeout_seconds: Maximum wait time.
    :returns: Command output between command echo and completion marker.
    """

    marker = f"__SSHPORTAL_{marker_name}__"
    before_length = len(spawned.transcript)
    send_input(spawned, f"{command}; printf '{marker}:%s\\n' \"$?\"\n")
    marker_pattern = re.compile(rf"(?:^|\r?\n)({re.escape(marker)}:\d+)")
    deadline = time.monotonic() + timeout_seconds
    after = ""
    marker_line = ""
    while time.monotonic() < deadline:
        read_available_output(spawned, 0.2)
        after = spawned.transcript[before_length:]
        match = marker_pattern.search(after)
        if match is None:
            if spawned.process.poll() is None:
                continue
            raise RuntimeError(
                f"{spawned.label} exited while waiting for remote command completion\n{after}"
            )
        marker_line = match.group(1)
        break
    if len(marker_line) == 0:
        raise RuntimeError(
            f"timed out waiting for remote command completion for {command!r}\n{after}"
        )
    if not marker_line.endswith(":0"):
        raise RuntimeError(
            f"remote command {command!r} failed with marker line {marker_line!r}\n{after}"
        )
    return after


def container_home_file(container_name: str, relative_path: str) -> str:
    """Read a file from a container and return its contents.

    :param container_name: Running container name.
    :param relative_path: Path relative to the container root.
    :returns: File contents.
    """

    completed = subprocess.run(
        ["docker", "exec", container_name, "cat", relative_path],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def generate_operator_key(directory: Path) -> Path:
    """Generate an SSH keypair for the persistent-access test.

    :param directory: Directory to place the keypair in.
    :returns: Private key path.
    """

    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        raise RuntimeError("ssh-keygen is required for the persistent-key test")
    private_key = directory / "operator_ed25519"
    run_checked(
        [
            ssh_keygen,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            str(private_key),
        ]
    )
    return private_key


def start_operator_shell(operator_key: Path) -> SpawnedProcess:
    """Launch a local SSH client against the published server-side proxy.

    :param operator_key: Private key path used for proxy authentication.
    :returns: Running operator shell descriptor.
    :raises RuntimeError: If the host ``ssh`` client is unavailable.
    """

    ssh_binary = shutil.which("ssh")
    if ssh_binary is None:
        raise RuntimeError("ssh is required for the Docker end-to-end harness")

    return spawn_pty_process(
        "operator",
        [
            "env",
            "TERM=xterm-256color",
            ssh_binary,
            "-tt",
            "-p",
            str(HOST_SSH_PORT),
            "-i",
            str(operator_key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "root@127.0.0.1",
        ],
    )


def terminate_process(spawned: SpawnedProcess) -> None:
    """Terminate a spawned PTY-backed process and close its PTY.

    :param spawned: Process descriptor.
    """

    if spawned.process.poll() is None:
        spawned.process.send_signal(signal.SIGTERM)
        try:
            spawned.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            spawned.process.kill()
            spawned.process.wait(timeout=5)
    os.close(spawned.master_fd)


def wait_for_process_exit(spawned: SpawnedProcess, timeout_seconds: float) -> int:
    """Wait for a PTY-backed process to exit while draining its output.

    :param spawned: Process descriptor.
    :param timeout_seconds: Maximum wait time.
    :returns: Process exit status.
    :raises RuntimeError: If the process does not exit in time.
    """

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        read_available_output(spawned, 0.2)
        exit_code = spawned.process.poll()
        if exit_code is None:
            continue
        return exit_code
    raise RuntimeError(f"{spawned.label} did not exit within {timeout_seconds} seconds")


def start_server(
    *,
    image_tag: str,
    operator_key: Path | None,
    persist_key: bool,
    platform: str | None,
) -> SpawnedProcess:
    """Launch the server container.

    :param image_tag: Docker image tag to run.
    :param operator_key: Optional private key path to mount into the container.
    :param persist_key: Whether the server should request key persistence.
    :param platform: Optional Docker platform such as ``linux/amd64``.
    :returns: Running server process descriptor.
    """

    remove_container(SERVER_NAME)
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        SERVER_NAME,
        "--network",
        NETWORK_NAME,
        "--network-alias",
        "server",
        "-p",
        f"{HOST_PORT}:8080",
        "-p",
        f"{HOST_SSH_PORT}:2222",
        "-it",
    ]
    if platform is not None:
        command.extend(["--platform", platform])
    if operator_key is not None:
        command.extend(
            [
                "-v",
                f"{operator_key}:{operator_key}:ro",
            ]
        )
    command.extend(
        [
            "-e",
            "SSHPORTAL_DEBUG=1",
            image_tag,
            "/usr/local/bin/sshportal-server",
            "--listen",
            "0.0.0.0:8080",
            "--operator-name",
            "support-team",
            "--ssh-listen",
            "0.0.0.0:2222",
        ]
    )
    if operator_key is not None:
        command.extend(["--operator-key", str(operator_key)])
    if persist_key:
        command.append("--persist-operator-key")
    return spawn_pty_process("server", command)


def support_client_url(server: SpawnedProcess) -> str:
    """Build the client connection URL from the server transcript.

    :param server: Running server process descriptor.
    :returns: WebSocket URL that targets the Docker network alias with the printed join token.
    :raises RuntimeError: If the server transcript does not contain the advertised endpoint.
    """

    endpoint_pattern = re.compile(r"support websocket endpoint: (ws://\S+)")
    match = endpoint_pattern.search(server.transcript)
    if match is None:
        raise RuntimeError("server transcript did not include a support websocket endpoint")

    parsed = urllib.parse.urlsplit(match.group(1))
    return urllib.parse.urlunsplit(
        (parsed.scheme, "server:8080", parsed.path, parsed.query, parsed.fragment)
    )


def start_client(*, image_tag: str, platform: str | None, server_url: str) -> SpawnedProcess:
    """Launch the client container.

    :param image_tag: Docker image tag to run.
    :param platform: Optional Docker platform such as ``linux/amd64``.
    :param server_url: Tokenized rendezvous URL for the client to connect to.
    :returns: Running client process descriptor.
    """

    remove_container(CLIENT_NAME)
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        CLIENT_NAME,
        "--network",
        NETWORK_NAME,
        "--network-alias",
        "client",
        "-w",
        "/support-workspace",
        "-e",
        "SSHPORTAL_DEBUG=1",
        "-e",
        "TERM=dumb",
        "-it",
    ]
    if platform is not None:
        command.extend(["--platform", platform])
    command.extend(
        [
            image_tag,
            "/usr/local/bin/sshportal-client",
            "--server",
            server_url,
        ]
    )
    return spawn_pty_process("client", command)


def run_session(
    *,
    image_tag: str,
    persist_key: bool,
    operator_key: Path | None,
    platform: str | None,
) -> None:
    """Run one complete server/client session and assert expected behavior.

    :param image_tag: Docker image tag to run.
    :param persist_key: Whether to test authorized_keys installation.
    :param operator_key: Optional persistent operator key path.
    :param platform: Optional Docker platform such as ``linux/amd64``.
    """

    server = start_server(
        image_tag=image_tag,
        operator_key=operator_key,
        persist_key=persist_key,
        platform=platform,
    )
    client: SpawnedProcess | None = None
    operator: SpawnedProcess | None = None
    try:
        try:
            wait_for_text(server, "sshportal server listening on http://0.0.0.0:8080", 30.0)
            health_body = wait_for_http(f"http://127.0.0.1:{HOST_PORT}/healthz", 15.0)
            if "\"phase\":\"waiting\"" not in health_body:
                raise RuntimeError(f"unexpected health response before connect: {health_body}")

            client = start_client(
                image_tag=image_tag,
                platform=platform,
                server_url=support_client_url(server),
            )
            wait_for_text(
                client,
                "Allow support-team to open SSH support sessions into this environment while this connection remains open?",
                30.0,
            )
            send_input(client, "y\n")
            read_available_output(client, 1.0)
            if persist_key:
                wait_for_text(
                    client,
                    "Persist support-team's SSH key into ~/.ssh/authorized_keys for future access?",
                    30.0,
                )
                send_input(client, "y\n")
                read_available_output(client, 1.0)

            assert_http_unreachable(f"http://127.0.0.1:{HOST_PORT}/healthz", 15.0)
            wait_for_text(server, "SSH proxy listening on 0.0.0.0:2222", 15.0)
            if operator_key is None:
                raise RuntimeError("run_session requires an operator key for proxy access")
            operator = start_operator_shell(operator_key)
            time.sleep(1.0)

            pwd_output = run_shell_command(operator, "pwd", "PWD", 15.0)
            if "/support-workspace" not in pwd_output:
                raise session_failure(
                    f"unexpected remote pwd output:\n{pwd_output}",
                    server,
                    client,
                )

            term_output = run_shell_command(operator, "printf '%s\\n' \"$TERM\"", "TERM", 15.0)
            if "xterm-256color" not in term_output:
                raise session_failure(
                    f"unexpected TERM output:\n{term_output}",
                    server,
                    client,
                )

            throughput_output = run_shell_command(
                operator,
                "dd if=/dev/zero bs=1024 count=256 2>/dev/null | wc -c",
                "THROUGHPUT",
                30.0,
            )
            if "262144" not in throughput_output:
                raise session_failure(
                    f"unexpected throughput output:\n{throughput_output}",
                    server,
                    client,
                )

            size_output = run_shell_command(operator, "stty size", "STTY", 15.0)
            expected_size = f"{DEFAULT_TERMINAL_ROWS} {DEFAULT_TERMINAL_COLS}"
            if expected_size not in size_output:
                raise session_failure(
                    f"terminal size was not propagated:\n{size_output}",
                    server,
                    client,
                )

            login_output = run_shell_command(
                operator,
                "shopt -q login_shell && printf 'login=yes\\n' || printf 'login=no\\n'",
                "LOGIN",
                15.0,
            )
            if "login=yes" not in login_output:
                raise session_failure(
                    f"shell is not a login shell:\n{login_output}",
                    server,
                    client,
                )

            utf8_output = run_shell_command(
                operator,
                "printf '\\xc3\\xa9\\xc3\\xa0\\xc3\\xbc\\xe2\\x9c\\x93\\n'",
                "UTF8",
                15.0,
            )
            if "\u00e9\u00e0\u00fc\u2713" not in utf8_output:
                raise session_failure(
                    f"UTF-8 characters were not preserved:\n{utf8_output}",
                    server,
                    client,
                )

            send_input(operator, "sleep 300\n")
            time.sleep(0.5)
            send_input(operator, "\x03")
            ctrlc_output = run_shell_command(
                operator,
                "printf 'ctrlc-ok\\n'",
                "CTRLC",
                15.0,
            )
            if "ctrlc-ok" not in ctrlc_output:
                raise session_failure(
                    f"shell did not survive Ctrl+C:\n{ctrlc_output}",
                    server,
                    client,
                )

            big_throughput_output = run_shell_command(
                operator,
                "dd if=/dev/zero bs=4096 count=256 2>/dev/null | wc -c",
                "BIGTHROUGHPUT",
                30.0,
            )
            if "1048576" not in big_throughput_output:
                raise session_failure(
                    f"1 MB throughput test failed:\n{big_throughput_output}",
                    server,
                    client,
                )

            time.sleep(40)
            idle_output = run_shell_command(operator, "printf 'idle-check\\n'", "IDLE", 15.0)
            if "idle-check" not in idle_output:
                raise session_failure(
                    f"interactive shell did not survive idle period:\n{idle_output}",
                    server,
                    client,
                )

            if persist_key:
                key_data = container_home_file(CLIENT_NAME, "/root/.ssh/authorized_keys")
                if "ssh-ed25519 " not in key_data:
                    raise session_failure(
                        "authorized_keys did not contain the persisted operator key",
                        server,
                        client,
                    )

            send_input(operator, "exit\n")
            read_available_output(operator, 1.0)
        except (RuntimeError, OSError) as error:
            raise session_failure(str(error), server, client) from error
    finally:
        if operator is not None:
            terminate_process(operator)
        if client is not None:
            terminate_process(client)
        terminate_process(server)
        remove_container(CLIENT_NAME)
        remove_container(SERVER_NAME)


def run_disconnect_test(*, image_tag: str, operator_key: Path, platform: str | None) -> None:
    """Verify that killing the client causes the server to exit cleanly.

    :param image_tag: Docker image tag to run.
    :param operator_key: Private key path used for proxy authentication.
    :param platform: Optional Docker platform such as ``linux/amd64``.
    """

    server = start_server(
        image_tag=image_tag,
        operator_key=operator_key,
        persist_key=False,
        platform=platform,
    )
    client: SpawnedProcess | None = None
    operator: SpawnedProcess | None = None
    try:
        wait_for_text(server, "sshportal server listening on http://0.0.0.0:8080", 30.0)
        wait_for_http(f"http://127.0.0.1:{HOST_PORT}/healthz", 15.0)

        client = start_client(
            image_tag=image_tag,
            platform=platform,
            server_url=support_client_url(server),
        )
        wait_for_text(
            client,
            "Allow support-team to open SSH support sessions into this environment while this connection remains open?",
            30.0,
        )
        send_input(client, "y\n")
        read_available_output(client, 1.0)

        wait_for_text(server, "SSH proxy listening on 0.0.0.0:2222", 15.0)
        operator = start_operator_shell(operator_key)
        time.sleep(1.0)
        run_shell_command(operator, "printf 'alive\\n'", "ALIVE", 15.0)

        subprocess.run(
            ["docker", "kill", CLIENT_NAME],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        server_exit_code = wait_for_process_exit(server, 30.0)
        if server_exit_code not in (0, 1):
            raise session_failure(
                f"server exited with unexpected code {server_exit_code} after client kill",
                server,
                client,
            )
    finally:
        if operator is not None:
            terminate_process(operator)
        if client is not None:
            terminate_process(client)
        terminate_process(server)
        remove_container(CLIENT_NAME)
        remove_container(SERVER_NAME)


def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments.

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
    """Program entrypoint.

    :returns: Process exit status.
    """

    arguments = parse_arguments()
    if arguments.skip_build is False:
        build_image(arguments.image_tag, arguments.platform)
    recreate_network()
    key_directory = PROJECT_ROOT / ".tmp-docker-e2e"
    if key_directory.exists():
        shutil.rmtree(key_directory)
    key_directory.mkdir(parents=True)
    operator_key = generate_operator_key(key_directory)
    try:
        run_session(
            image_tag=arguments.image_tag,
            persist_key=False,
            operator_key=operator_key,
            platform=arguments.platform,
        )
        run_session(
            image_tag=arguments.image_tag,
            persist_key=True,
            operator_key=operator_key,
            platform=arguments.platform,
        )
        run_disconnect_test(
            image_tag=arguments.image_tag,
            operator_key=operator_key,
            platform=arguments.platform,
        )
    finally:
        shutil.rmtree(key_directory, ignore_errors=True)
        subprocess.run(
            ["docker", "network", "rm", NETWORK_NAME],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    print("docker end-to-end validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
