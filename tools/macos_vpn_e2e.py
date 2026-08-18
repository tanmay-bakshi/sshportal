#!/usr/bin/env python3

"""Run a privileged native macOS end-to-end validation of system VPN mode."""

import argparse
import asyncio
import ipaddress
import json
import os
import platform as platform_module
import pty
import re
import selectors
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import FrameType


PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
RECOVERY_JOURNAL: Path = Path("/var/run/sshportal/network-state.jsonl")
TEST_DOMAIN: str = "localhost"
TEST_CIDR: str = "2001:db8:ffff::/48"
TEST_CIDR_ADDRESS: str = "2001:db8:ffff::1"
JOIN_TOKEN: str = "macos-vpn-e2e-token"
DNS_TYPE_A: int = 1
DNS_TYPE_AAAA: int = 28
DNS_CLASS_INTERNET: int = 1
DNS_HEADER_BYTES: int = 12
DNS_TIMEOUT_SECONDS: float = 15.0
PROCESS_TIMEOUT_SECONDS: float = 30.0
BUILD_TIMEOUT_SECONDS: float = 600.0
READ_CHUNK_BYTES: int = 4096
ECHO_PREFIX: bytes = b"sshportal-native-echo:"


@dataclass
class SpawnedProcess:
    """Track a PTY-backed subprocess and its captured output.

    :ivar label: Human-readable process name.
    :ivar process: Child process handle.
    :ivar master_fd: PTY file descriptor used to read process output.
    :ivar transcript: Output captured from the process.
    :ivar closed: Whether the PTY has been closed.
    """

    label: str
    process: subprocess.Popen[bytes]
    master_fd: int
    transcript: str
    closed: bool = False

    def read_available(self, timeout_seconds: float) -> str:
        """Read process output that becomes available before a deadline.

        :param timeout_seconds: Maximum time to wait for output.
        :returns: Newly captured output.
        """

        if self.closed:
            return ""
        selector = selectors.DefaultSelector()
        selector.register(self.master_fd, selectors.EVENT_READ)
        chunks: list[str] = []
        deadline = time.monotonic() + timeout_seconds
        try:
            while time.monotonic() < deadline:
                events = selector.select(deadline - time.monotonic())
                if len(events) == 0:
                    break
                try:
                    data = os.read(self.master_fd, READ_CHUNK_BYTES)
                except OSError:
                    data = b""
                if len(data) == 0:
                    break
                chunks.append(data.decode(errors="replace"))
        finally:
            selector.close()
        output = "".join(chunks)
        self.transcript += output
        return output

    def wait_for_text(self, expected: str, timeout_seconds: float) -> str:
        """Wait until the transcript contains expected text.

        :param expected: Text required in the process transcript.
        :param timeout_seconds: Maximum time to wait.
        :returns: Complete process transcript.
        :raises RuntimeError: If the process exits or the deadline expires.
        """

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            self.read_available(0.2)
            if expected in self.transcript:
                return self.transcript
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"{self.label} exited while waiting for {expected!r}:\n"
                    f"{self.transcript}"
                )
        raise RuntimeError(
            f"timed out waiting for {expected!r} from {self.label}:\n"
            f"{self.transcript}"
        )

    def wait(self, timeout_seconds: float) -> int:
        """Wait for process exit while continuing to drain output.

        :param timeout_seconds: Maximum time to wait.
        :returns: Process exit status.
        :raises RuntimeError: If the process misses its deadline.
        """

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            self.read_available(0.2)
            exit_code = self.process.poll()
            if exit_code is not None:
                self.read_available(0.1)
                return exit_code
        raise RuntimeError(f"{self.label} did not exit within {timeout_seconds} seconds")

    def signal_group(self, process_signal: signal.Signals) -> None:
        """Send a signal to the process and every child in its process group.

        :param process_signal: Signal to deliver.
        """

        if self.process.poll() is not None:
            return
        try:
            os.killpg(self.process.pid, process_signal)
        except ProcessLookupError:
            return

    def terminate(self) -> None:
        """Terminate the process group and close its PTY."""

        if self.process.poll() is None:
            self.signal_group(signal.SIGTERM)
            try:
                self.wait(5.0)
            except RuntimeError:
                self.signal_group(signal.SIGKILL)
                self.process.wait(timeout=5.0)
        self.close()

    def close(self) -> None:
        """Close the process PTY exactly once."""

        if self.closed:
            return
        os.close(self.master_fd)
        self.closed = True


class TlsForwarder:
    """Forward a loopback TLS listener to the server's plain WebSocket port."""

    certificate: Path
    private_key: Path
    backend_port: int
    port: int
    _failure: str | None
    _loop: asyncio.AbstractEventLoop | None
    _ready: threading.Event
    _stop_future: asyncio.Future[None] | None
    _thread: threading.Thread

    def __init__(self, certificate: Path, private_key: Path, backend_port: int) -> None:
        """Initialize a local TLS forwarder.

        :param certificate: PEM server certificate.
        :param private_key: PEM server private key.
        :param backend_port: Plain HTTP/WebSocket listener port.
        """

        self.certificate = certificate
        self.private_key = private_key
        self.backend_port = backend_port
        self.port = 0
        self._failure = None
        self._loop = None
        self._ready = threading.Event()
        self._stop_future = None
        self._thread = threading.Thread(
            target=self._run,
            name="sshportal-macos-vpn-tls",
            daemon=True,
        )

    def start(self) -> None:
        """Start the TLS listener and wait until it has bound a port.

        :raises RuntimeError: If the forwarder cannot start.
        """

        self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise RuntimeError("TLS forwarder did not become ready")
        if self._failure is not None:
            raise RuntimeError(f"TLS forwarder failed:\n{self._failure}")
        if self.port == 0:
            raise RuntimeError("TLS forwarder reported an invalid listener port")

    def stop(self) -> None:
        """Stop the TLS listener and wait for its thread."""

        loop = self._loop
        stop_future = self._stop_future
        if loop is not None and stop_future is not None and not stop_future.done():
            loop.call_soon_threadsafe(stop_future.set_result, None)
        if self._thread.is_alive():
            self._thread.join(timeout=10.0)
        if self._thread.is_alive():
            raise RuntimeError("TLS forwarder did not stop")

    def _run(self) -> None:
        """Own the asyncio event loop used by the forwarder thread."""

        try:
            asyncio.run(self._serve())
        except Exception:
            self._failure = traceback.format_exc()
            self._ready.set()

    async def _serve(self) -> None:
        """Serve TLS connections until the stop future is resolved."""

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.certificate, self.private_key)
        server = await asyncio.start_server(
            self._handle_connection,
            host="127.0.0.1",
            port=0,
            ssl=context,
        )
        sockets = server.sockets
        if sockets is None or len(sockets) != 1:
            server.close()
            await server.wait_closed()
            raise RuntimeError("TLS forwarder did not create exactly one listener")
        self.port = int(sockets[0].getsockname()[1])
        self._loop = asyncio.get_running_loop()
        self._stop_future = self._loop.create_future()
        self._ready.set()
        try:
            await self._stop_future
        finally:
            server.close()
            await server.wait_closed()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Relay one TLS connection to the plain backend.

        :param reader: Decrypted client stream.
        :param writer: Decrypted client stream writer.
        """

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                "127.0.0.1", self.backend_port
            )
        except OSError:
            writer.close()
            await writer.wait_closed()
            return

        async def relay(
            source: asyncio.StreamReader,
            destination: asyncio.StreamWriter,
        ) -> None:
            while True:
                data = await source.read(64 * 1024)
                if len(data) == 0:
                    try:
                        destination.write_eof()
                        await destination.drain()
                    except (OSError, RuntimeError):
                        pass
                    return
                destination.write(data)
                await destination.drain()

        tasks = {
            asyncio.create_task(relay(reader, upstream_writer)),
            asyncio.create_task(relay(upstream_reader, writer)),
        }
        try:
            _done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            upstream_writer.close()
            writer.close()
            await asyncio.gather(
                upstream_writer.wait_closed(),
                writer.wait_closed(),
                return_exceptions=True,
            )


class EchoServices:
    """Provide deterministic IPv4 and IPv6 TCP and UDP client-side endpoints."""

    tcp_ports: dict[int, int]
    udp_ports: dict[int, int]
    _failures: list[str]
    _failure_lock: threading.Lock
    _sockets: list[socket.socket]
    _stop: threading.Event
    _threads: list[threading.Thread]

    def __init__(self) -> None:
        """Create bound loopback sockets for every transport and address family."""

        self.tcp_ports = {}
        self.udp_ports = {}
        self._failures = []
        self._failure_lock = threading.Lock()
        self._sockets = []
        self._stop = threading.Event()
        self._threads = []
        for family, address in [
            (socket.AF_INET, "127.0.0.1"),
            (socket.AF_INET6, "::1"),
        ]:
            tcp = self._bind(family, socket.SOCK_STREAM, address)
            tcp.listen(8)
            self.tcp_ports[family] = int(tcp.getsockname()[1])
            udp = self._bind(family, socket.SOCK_DGRAM, address)
            self.udp_ports[family] = int(udp.getsockname()[1])
            self._start_thread(f"tcp-{family}", self._serve_tcp, tcp)
            self._start_thread(f"udp-{family}", self._serve_udp, udp)

    def _bind(self, family: int, kind: int, address: str) -> socket.socket:
        """Bind one loopback socket.

        :param family: Socket address family.
        :param kind: Socket transport kind.
        :param address: Loopback address to bind.
        :returns: Bound socket.
        """

        bound = socket.socket(family, kind)
        bound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            bound.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        bound.bind((address, 0))
        bound.settimeout(0.2)
        self._sockets.append(bound)
        return bound

    def _start_thread(
        self,
        label: str,
        target: Callable[[socket.socket], None],
        bound: socket.socket,
    ) -> None:
        """Start one echo worker thread.

        :param label: Thread label suffix.
        :param target: Bound worker method.
        :param bound: Socket owned by the worker.
        """

        thread = threading.Thread(
            target=target,
            args=(bound,),
            name=f"sshportal-macos-vpn-{label}",
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)

    def _serve_tcp(self, listener: socket.socket) -> None:
        """Echo each TCP request after observing its half-close.

        :param listener: Bound TCP listener.
        """

        while not self._stop.is_set():
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            except OSError as error:
                if not self._stop.is_set():
                    self._record_failure(f"TCP accept failed: {error}")
                return
            with connection:
                connection.settimeout(DNS_TIMEOUT_SECONDS)
                request = bytearray()
                try:
                    while True:
                        data = connection.recv(64 * 1024)
                        if len(data) == 0:
                            break
                        request.extend(data)
                    connection.sendall(ECHO_PREFIX + request)
                except OSError as error:
                    self._record_failure(f"TCP echo failed: {error}")

    def _serve_udp(self, endpoint: socket.socket) -> None:
        """Echo UDP datagrams without changing their boundaries.

        :param endpoint: Bound UDP socket.
        """

        while not self._stop.is_set():
            try:
                data, peer = endpoint.recvfrom(65_535)
            except TimeoutError:
                continue
            except OSError as error:
                if not self._stop.is_set():
                    self._record_failure(f"UDP receive failed: {error}")
                return
            try:
                endpoint.sendto(ECHO_PREFIX + data, peer)
            except OSError as error:
                self._record_failure(f"UDP echo failed: {error}")

    def _record_failure(self, message: str) -> None:
        """Record a worker failure for the main test thread.

        :param message: Failure description.
        """

        with self._failure_lock:
            self._failures.append(message)

    def assert_healthy(self) -> None:
        """Fail when an echo worker encountered an error.

        :raises RuntimeError: If any worker failed.
        """

        with self._failure_lock:
            failures = list(self._failures)
        if len(failures) > 0:
            raise RuntimeError("echo service failed: " + "; ".join(failures))

    def stop(self) -> None:
        """Stop every echo worker and close its socket."""

        self._stop.set()
        for bound in self._sockets:
            bound.close()
        for thread in self._threads:
            thread.join(timeout=5.0)
        if any(thread.is_alive() for thread in self._threads):
            raise RuntimeError("an echo service thread did not stop")
        self.assert_healthy()


def run_checked(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    timeout_seconds: float = PROCESS_TIMEOUT_SECONDS,
) -> None:
    """Run a command and require success.

    :param command: Command and arguments.
    :param env: Optional process environment.
    :param input_text: Optional standard input.
    :param timeout_seconds: Maximum command runtime.
    :raises RuntimeError: If the command exits unsuccessfully.
    """

    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=env,
            input=input_text,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"command exceeded {timeout_seconds} seconds: {' '.join(command)}"
        ) from error
    if completed.returncode != 0:
        raise RuntimeError(
            f"command exited with {completed.returncode}: {' '.join(command)}"
        )


def command_output(
    command: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
    timeout_seconds: float = PROCESS_TIMEOUT_SECONDS,
) -> str:
    """Run a command and return combined textual output.

    :param command: Command and arguments.
    :param check: Whether to require a zero exit status.
    :param input_text: Optional standard input.
    :param timeout_seconds: Maximum command runtime.
    :returns: Standard output followed by standard error.
    :raises RuntimeError: If a checked command exits unsuccessfully.
    """

    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"command exceeded {timeout_seconds} seconds: {' '.join(command)}"
        ) from error
    output = completed.stdout + completed.stderr
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command exited with {completed.returncode}: {' '.join(command)}\n{output}"
        )
    return output


def privileged_path_exists(path: Path) -> bool:
    """Check a root-owned path without weakening its permissions.

    :param path: Path to inspect through passwordless ``sudo``.
    :returns: Whether the path exists.
    :raises RuntimeError: If the privileged check cannot run reliably.
    """

    try:
        completed = subprocess.run(
            ["sudo", "-n", "/bin/test", "-e", str(path)],
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=PROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"privileged path check exceeded {PROCESS_TIMEOUT_SECONDS} seconds: {path}"
        ) from error
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    output = (completed.stdout + completed.stderr).strip()
    raise RuntimeError(
        f"privileged path check exited with {completed.returncode} for {path}: {output}"
    )


def spawn_process(
    label: str,
    command: list[str],
    *,
    env: dict[str, str] | None = None,
) -> SpawnedProcess:
    """Start a PTY-backed subprocess in a new process group.

    :param label: Human-readable process name.
    :param command: Command and arguments.
    :param env: Optional process environment.
    :returns: Spawned process descriptor.
    """

    master_fd, slave_fd = pty.openpty()
    try:
        process = subprocess.Popen(
            command,
            cwd=PROJECT_ROOT,
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            start_new_session=True,
        )
    finally:
        os.close(slave_fd)
    return SpawnedProcess(label, process, master_fd, "")


def choose_loopback_port() -> int:
    """Reserve and release one currently unused IPv4 loopback port.

    :returns: Available TCP port number.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temporary:
        temporary.bind(("127.0.0.1", 0))
        return int(temporary.getsockname()[1])


def generate_tls_material(directory: Path) -> tuple[Path, Path, Path]:
    """Generate a short-lived localhost certificate and its root.

    :param directory: Destination directory.
    :returns: Root certificate, server certificate, and server key paths.
    """

    root_certificate = directory / "ca.crt"
    root_key = directory / "ca.key"
    server_certificate = directory / "server.crt"
    server_key = directory / "server.key"
    server_request = directory / "server.csr"
    extensions = directory / "server.ext"
    extensions.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n"
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
            "/CN=SSHPortal macOS VPN E2E Ephemeral Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(root_key),
            "-out",
            str(root_certificate),
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
            "/CN=localhost",
            "-keyout",
            str(server_key),
            "-out",
            str(server_request),
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
            str(server_request),
            "-CA",
            str(root_certificate),
            "-CAkey",
            str(root_key),
            "-CAcreateserial",
            "-extfile",
            str(extensions),
            "-out",
            str(server_certificate),
        ]
    )
    return root_certificate, server_certificate, server_key


def vpn_dns_keys() -> set[str]:
    """Return SSHPortal DNS keys currently present in SystemConfiguration.

    :returns: Dynamic-store keys owned by SSHPortal sessions.
    """

    output = command_output(
        ["scutil"],
        input_text="list State:/Network/Service/SSHPortal-.*/DNS\nquit\n",
    )
    return set(re.findall(r"State:/Network/Service/SSHPortal-[0-9a-f]{32}/DNS", output))


def dynamic_store_value(key: str) -> str:
    """Read one SystemConfiguration dynamic-store value.

    :param key: Exact dynamic-store key.
    :returns: ``scutil`` dictionary rendering.
    """

    return command_output(["scutil"], input_text=f"show {key}\nquit\n")


def scutil_array(dictionary: str, field: str) -> list[str]:
    """Extract string values from one ``scutil`` array field.

    :param dictionary: Rendered SystemConfiguration dictionary.
    :param field: Array field name.
    :returns: Array values in their rendered order.
    :raises RuntimeError: If the field is absent or malformed.
    """

    match = re.search(
        rf"^\s*{re.escape(field)}\s*:\s*<array>\s*\{{\n(?P<body>.*?)^\s*\}}",
        dictionary,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise RuntimeError(f"SystemConfiguration DNS dictionary omitted {field}:\n{dictionary}")
    values = re.findall(r"^\s*\d+\s*:\s*(.*?)\s*$", match.group("body"), re.MULTILINE)
    if len(values) == 0:
        raise RuntimeError(f"SystemConfiguration DNS array {field} was empty")
    return values


def wait_for_dns_key(baseline: set[str], timeout_seconds: float) -> str:
    """Wait for exactly one new SSHPortal DNS key.

    :param baseline: Keys present before the session.
    :param timeout_seconds: Maximum time to wait.
    :returns: New session DNS key.
    :raises RuntimeError: If no unique key appears.
    """

    deadline = time.monotonic() + timeout_seconds
    observed: set[str] = set()
    while time.monotonic() < deadline:
        observed = vpn_dns_keys()
        added = observed - baseline
        if len(added) == 1:
            return next(iter(added))
        if len(added) > 1:
            break
        time.sleep(0.1)
    raise RuntimeError(
        "expected exactly one new SSHPortal DNS key, "
        f"baseline={sorted(baseline)}, observed={sorted(observed)}"
    )


def route_path(address: str) -> tuple[str, str]:
    """Return gateway and interface selected for an IP address.

    :param address: IPv4 or IPv6 destination.
    :returns: Gateway and interface strings.
    :raises RuntimeError: If the route cannot be inspected.
    """

    parsed = ipaddress.ip_address(address)
    family = "-inet" if isinstance(parsed, ipaddress.IPv4Address) else "-inet6"
    output = command_output(["route", "-n", "get", family, address])
    gateway_match = re.search(r"^\s*gateway:\s*(\S+)", output, re.MULTILINE)
    interface_match = re.search(r"^\s*interface:\s*(\S+)", output, re.MULTILINE)
    gateway = gateway_match.group(1) if gateway_match is not None else ""
    if interface_match is None:
        raise RuntimeError(f"route lookup omitted its interface for {address}:\n{output}")
    return gateway, interface_match.group(1)


def current_interfaces() -> set[str]:
    """Return the current macOS network-interface names.

    :returns: Interface-name set.
    """

    return set(command_output(["ifconfig", "-l"]).split())


def journal_owner_pid() -> int:
    """Read the active server PID from the recovery journal.

    :returns: Positive server process ID.
    :raises RuntimeError: If the journal header is unavailable or malformed.
    """

    try:
        first_line = command_output(
            ["sudo", "-n", "/bin/cat", str(RECOVERY_JOURNAL)]
        ).splitlines()[0]
        record: object = json.loads(first_line)
    except (OSError, IndexError, json.JSONDecodeError) as error:
        raise RuntimeError("failed to read the active VPN recovery journal") from error
    if not isinstance(record, dict) or record.get("record") != "header":
        raise RuntimeError("VPN recovery journal does not begin with a header")
    value = record.get("value")
    if not isinstance(value, dict):
        raise RuntimeError("VPN recovery journal header has no value object")
    owner_pid = value.get("owner_pid")
    if not isinstance(owner_pid, int) or owner_pid <= 0:
        raise RuntimeError("VPN recovery journal contains an invalid owner PID")
    return owner_pid


def encode_dns_query(transaction_id: int, name: str, record_type: int) -> bytes:
    """Encode one ordinary recursive DNS query.

    :param transaction_id: DNS transaction identifier.
    :param name: Fully qualified query name without the root label.
    :param record_type: Numeric DNS record type.
    :returns: Wire-format DNS message.
    """

    message = bytearray(
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    )
    for label in name.split("."):
        encoded = label.encode("ascii")
        if len(encoded) == 0 or len(encoded) > 63:
            raise RuntimeError(f"invalid DNS test label: {label!r}")
        message.append(len(encoded))
        message.extend(encoded)
    message.append(0)
    message.extend(struct.pack("!HH", record_type, DNS_CLASS_INTERNET))
    return bytes(message)


def skip_dns_name(message: bytes, offset: int) -> int:
    """Return the offset immediately after one DNS wire name.

    :param message: Complete DNS message.
    :param offset: Initial name offset.
    :returns: Offset following labels or a compression pointer.
    :raises RuntimeError: If the name is truncated or malformed.
    """

    labels = 0
    while True:
        if offset >= len(message):
            raise RuntimeError("DNS response ended inside a name")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(message):
                raise RuntimeError("DNS response ended inside a compression pointer")
            return offset + 2
        if length & 0xC0 != 0:
            raise RuntimeError("DNS response contains an unsupported label encoding")
        offset += 1
        if length == 0:
            return offset
        if length > 63 or offset + length > len(message):
            raise RuntimeError("DNS response contains an invalid label")
        offset += length
        labels += 1
        if labels > 127:
            raise RuntimeError("DNS response contains too many labels")


def parse_dns_answer(
    response: bytes,
    transaction_id: int,
    record_type: int,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Validate a DNS response and return its requested synthetic address.

    :param response: Wire-format DNS response.
    :param transaction_id: Expected DNS transaction identifier.
    :param record_type: Expected A or AAAA record type.
    :returns: Synthetic response address.
    :raises RuntimeError: If the response is invalid or has no matching answer.
    """

    if len(response) < DNS_HEADER_BYTES:
        raise RuntimeError("DNS response is shorter than its header")
    response_id, flags, questions, answers, _authority, _additional = struct.unpack(
        "!HHHHHH", response[:DNS_HEADER_BYTES]
    )
    if response_id != transaction_id:
        raise RuntimeError("DNS response transaction ID does not match")
    if flags & 0x8000 == 0 or flags & 0x000F != 0:
        raise RuntimeError(f"DNS response has unsuccessful flags 0x{flags:04x}")
    if questions != 1 or answers < 1:
        raise RuntimeError(
            f"DNS response has {questions} questions and {answers} answers"
        )
    offset = skip_dns_name(response, DNS_HEADER_BYTES)
    if offset + 4 > len(response):
        raise RuntimeError("DNS response ended inside its question")
    offset += 4
    for _index in range(answers):
        offset = skip_dns_name(response, offset)
        if offset + 10 > len(response):
            raise RuntimeError("DNS response ended inside an answer header")
        answer_type, answer_class, _ttl, data_length = struct.unpack(
            "!HHIH", response[offset : offset + 10]
        )
        offset += 10
        data_end = offset + data_length
        if data_end > len(response):
            raise RuntimeError("DNS response ended inside answer data")
        data = response[offset:data_end]
        offset = data_end
        if answer_type != record_type or answer_class != DNS_CLASS_INTERNET:
            continue
        if record_type == DNS_TYPE_A and data_length == 4:
            return ipaddress.IPv4Address(data)
        if record_type == DNS_TYPE_AAAA and data_length == 16:
            return ipaddress.IPv6Address(data)
        raise RuntimeError("DNS answer has an invalid address length")
    raise RuntimeError(f"DNS response contains no answer of type {record_type}")


def read_exact(endpoint: socket.socket, size: int) -> bytes:
    """Read exactly the requested byte count from a stream socket.

    :param endpoint: Connected stream socket.
    :param size: Required byte count.
    :returns: Received bytes.
    :raises RuntimeError: If the peer closes prematurely.
    """

    received = bytearray()
    while len(received) < size:
        chunk = endpoint.recv(size - len(received))
        if len(chunk) == 0:
            raise RuntimeError("stream closed before the expected payload arrived")
        received.extend(chunk)
    return bytes(received)


def query_dns(
    server: ipaddress.IPv4Address | ipaddress.IPv6Address,
    record_type: int,
    transport: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Query a synthetic resolver over UDP or TCP.

    :param server: Synthetic resolver address.
    :param record_type: A or AAAA record type.
    :param transport: ``udp`` or ``tcp``.
    :returns: Synthetic address from the answer.
    """

    transaction_id = int.from_bytes(os.urandom(2), "big")
    query = encode_dns_query(transaction_id, TEST_DOMAIN, record_type)
    family = socket.AF_INET if isinstance(server, ipaddress.IPv4Address) else socket.AF_INET6
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    with socket.socket(family, kind) as endpoint:
        endpoint.settimeout(DNS_TIMEOUT_SECONDS)
        endpoint.connect((str(server), 53))
        if transport == "udp":
            endpoint.sendall(query)
            response = endpoint.recv(65_535)
        elif transport == "tcp":
            endpoint.sendall(struct.pack("!H", len(query)) + query)
            response_length = struct.unpack("!H", read_exact(endpoint, 2))[0]
            response = read_exact(endpoint, response_length)
        else:
            raise RuntimeError(f"unsupported DNS transport {transport!r}")
    return parse_dns_answer(response, transaction_id, record_type)


def verify_dns_matrix(
    servers: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> dict[int, ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Exercise A and AAAA over UDP and TCP through both resolver families.

    :param servers: Synthetic IPv4 and IPv6 resolver addresses.
    :returns: Stable synthetic address for each tested record type.
    :raises RuntimeError: If answers are unstable or outside their pool.
    """

    expected: dict[int, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
    for server in servers:
        for transport in ["udp", "tcp"]:
            for record_type in [DNS_TYPE_A, DNS_TYPE_AAAA]:
                answer = query_dns(server, record_type, transport)
                previous = expected.setdefault(record_type, answer)
                if answer != previous:
                    raise RuntimeError(
                        f"synthetic DNS mapping changed from {previous} to {answer}"
                    )
    ipv4 = expected[DNS_TYPE_A]
    ipv6 = expected[DNS_TYPE_AAAA]
    if not isinstance(ipv4, ipaddress.IPv4Address) or ipv4 not in ipaddress.ip_network(
        "198.18.0.0/15"
    ):
        raise RuntimeError(f"A query returned non-synthetic address {ipv4}")
    ipv6_server = next(
        server for server in servers if isinstance(server, ipaddress.IPv6Address)
    )
    if not isinstance(ipv6, ipaddress.IPv6Address) or int(ipv6) >> 32 != int(ipv6_server) >> 32:
        raise RuntimeError(f"AAAA query returned address outside its synthetic /96: {ipv6}")
    return expected


def verify_tcp_tunnel(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
) -> None:
    """Verify bidirectional TCP and half-close propagation through the tunnel.

    :param address: Synthetic destination address.
    :param port: Matching client-side echo port.
    """

    payload = b"tcp-" + os.urandom(32)
    with socket.create_connection((str(address), port), timeout=DNS_TIMEOUT_SECONDS) as endpoint:
        endpoint.settimeout(DNS_TIMEOUT_SECONDS)
        endpoint.sendall(payload)
        endpoint.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = endpoint.recv(64 * 1024)
            if len(chunk) == 0:
                break
            response.extend(chunk)
    if bytes(response) != ECHO_PREFIX + payload:
        raise RuntimeError(f"TCP tunnel corrupted its payload through {address}")


def verify_udp_tunnel(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
) -> None:
    """Verify one bidirectional UDP datagram through the tunnel.

    :param address: Synthetic destination address.
    :param port: Matching client-side echo port.
    """

    family = socket.AF_INET if isinstance(address, ipaddress.IPv4Address) else socket.AF_INET6
    payload = b"udp-" + os.urandom(32)
    with socket.socket(family, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(DNS_TIMEOUT_SECONDS)
        endpoint.connect((str(address), port))
        endpoint.sendall(payload)
        response = endpoint.recv(65_535)
    if response != ECHO_PREFIX + payload:
        raise RuntimeError(f"UDP tunnel corrupted its payload through {address}")


def client_environment() -> dict[str, str]:
    """Return an environment that cannot proxy the local WSS fixture.

    :returns: Sanitized client environment.
    """

    environment = os.environ.copy()
    for name in [
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "all_proxy",
        "https_proxy",
        "http_proxy",
    ]:
        environment.pop(name, None)
    environment["NO_PROXY"] = "localhost,127.0.0.1,::1"
    environment["no_proxy"] = environment["NO_PROXY"]
    environment["TERM"] = "dumb"
    return environment


def start_session(
    server_binary: Path,
    client_binary: Path,
    root_certificate: Path,
    server_certificate: Path,
    server_key: Path,
    policy_arguments: list[str],
) -> tuple[SpawnedProcess, SpawnedProcess, TlsForwarder]:
    """Start one root server, local WSS proxy, and unprivileged client.

    :param server_binary: Built server executable.
    :param client_binary: Built client executable.
    :param root_certificate: PEM root trusted only by the fixture client.
    :param server_certificate: PEM certificate for the local WSS listener.
    :param server_key: PEM private key for the local WSS listener.
    :param policy_arguments: VPN include-selector arguments.
    :returns: Server, client, and TLS forwarder.
    """

    backend_port = choose_loopback_port()
    server = spawn_process(
        "macOS VPN server",
        [
            "sudo",
            "-n",
            str(server_binary),
            "--listen",
            f"127.0.0.1:{backend_port}",
            "--operator-name",
            "macos-vpn-e2e",
            "--join-token",
            JOIN_TOKEN,
            "--vpn",
            *policy_arguments,
        ],
    )
    client: SpawnedProcess | None = None
    forwarder = TlsForwarder(
        server_certificate,
        server_key,
        backend_port,
    )
    try:
        server.wait_for_text("sshportal server listening", PROCESS_TIMEOUT_SECONDS)
        forwarder.start()
        client = spawn_process(
            "macOS VPN client",
            [
                str(client_binary),
                "--server",
                f"https://localhost:{forwarder.port}/connect?token={JOIN_TOKEN}",
                "--tls-ca-certificate",
                str(root_certificate),
                "--approve-session",
            ],
            env=client_environment(),
        )
        client.wait_for_text("VPN egress session approved", PROCESS_TIMEOUT_SECONDS)
        server.wait_for_text("VPN active on interface", PROCESS_TIMEOUT_SECONDS)
        return server, client, forwarder
    except (KeyboardInterrupt, OSError, RuntimeError):
        try:
            if client is not None:
                client.terminate()
        finally:
            try:
                server.signal_group(signal.SIGINT)
                try:
                    server.wait(10.0)
                except RuntimeError:
                    server.terminate()
                else:
                    server.close()
            finally:
                forwarder.stop()
        raise


def active_interface(server: SpawnedProcess) -> str:
    """Extract the active TUN interface from server output.

    :param server: Active server process.
    :returns: ``utun`` interface name.
    :raises RuntimeError: If the transcript has no valid name.
    """

    match = re.search(r"VPN active on interface (utun[0-9]+)", server.transcript)
    if match is None:
        raise RuntimeError(f"server did not report its VPN interface:\n{server.transcript}")
    return match.group(1)


def verify_interface_configuration(interface: str) -> None:
    """Verify the native point-to-point interface's dual-stack shape.

    :param interface: Active ``utun`` name.
    """

    output = command_output(["ifconfig", interface])
    if re.search(
        r"^\s*inet\s+\S+\s+-->\s+\S+\s+netmask\s+0xfffffffc",
        output,
        re.MULTILINE,
    ) is None:
        raise RuntimeError(f"{interface} has no IPv4 /30 point-to-point address:\n{output}")
    if re.search(
        r"^\s*inet6\s+fd[0-9a-f:]+\s+-->\s+fd[0-9a-f:]+\s+prefixlen\s+128",
        output,
        re.MULTILINE | re.IGNORECASE,
    ) is None:
        raise RuntimeError(f"{interface} has no IPv6 /128 point-to-point peer:\n{output}")


def verify_supplemental_dns(
    baseline_dns: set[str],
    interface: str,
) -> tuple[str, list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    """Verify and decode the macOS supplemental resolver.

    :param baseline_dns: Dynamic-store keys present before the session.
    :param interface: Active VPN interface.
    :returns: Session DNS key and its two server addresses.
    """

    key = wait_for_dns_key(baseline_dns, 10.0)
    dictionary = dynamic_store_value(key)
    if f"InterfaceName : {interface}" not in dictionary:
        raise RuntimeError(f"supplemental DNS is not scoped to {interface}:\n{dictionary}")
    if "SupplementalMatchDomainsNoSearch : 1" not in dictionary:
        raise RuntimeError(f"supplemental DNS permits search-domain expansion:\n{dictionary}")
    domains = scutil_array(dictionary, "SupplementalMatchDomains")
    if domains != [TEST_DOMAIN]:
        raise RuntimeError(f"unexpected supplemental DNS domains: {domains}")
    raw_servers = scutil_array(dictionary, "ServerAddresses")
    try:
        servers = [ipaddress.ip_address(value) for value in raw_servers]
    except ValueError as error:
        raise RuntimeError(f"invalid synthetic DNS server list: {raw_servers}") from error
    if len(servers) != 2 or not any(
        isinstance(server, ipaddress.IPv4Address) for server in servers
    ) or not any(isinstance(server, ipaddress.IPv6Address) for server in servers):
        raise RuntimeError(f"supplemental DNS is not dual-stack: {servers}")
    for server in servers:
        _gateway, selected_interface = route_path(str(server))
        if selected_interface != interface:
            raise RuntimeError(
                f"synthetic resolver {server} routes over {selected_interface}, not {interface}"
            )
    resolver_inventory = command_output(["scutil", "--dns"])
    resolver_blocks = re.split(r"(?=^resolver #[0-9]+)", resolver_inventory, flags=re.MULTILINE)
    matching_blocks = [
        block
        for block in resolver_blocks
        if re.search(
            rf"^\s*domain\s*:\s*{re.escape(TEST_DOMAIN)}\s*$",
            block,
            re.MULTILINE,
        )
        is not None
        and re.search(r"^\s*flags\s*:.*\bSupplemental\b", block, re.MULTILINE)
        is not None
    ]
    if len(matching_blocks) != 1:
        raise RuntimeError(
            "the supplemental resolver is absent from macOS DNS selection:\n"
            f"{resolver_inventory}"
        )
    return key, servers


def graceful_shutdown(server: SpawnedProcess, client: SpawnedProcess) -> None:
    """Interrupt the server through its real PID and require clean exits.

    :param server: Active privileged server process.
    :param client: Active unprivileged client process.
    """

    owner_pid = journal_owner_pid()
    run_checked(["sudo", "-n", "kill", "-INT", str(owner_pid)])
    server_exit = server.wait(PROCESS_TIMEOUT_SECONDS)
    client_exit = client.wait(PROCESS_TIMEOUT_SECONDS)
    if server_exit != 0 or client_exit != 0:
        raise RuntimeError(
            f"graceful shutdown returned server={server_exit}, client={client_exit}"
        )
    if "failed to restore VPN" in server.transcript:
        raise RuntimeError(f"VPN cleanup reported an error:\n{server.transcript}")


def transport_failure_shutdown(server: SpawnedProcess, client: SpawnedProcess) -> None:
    """Break the client transport and require the server's failure path.

    :param server: Active privileged server process.
    :param client: Active unprivileged client process.
    """

    client.signal_group(signal.SIGTERM)
    client.wait(10.0)
    server_exit = server.wait(PROCESS_TIMEOUT_SECONDS)
    if server_exit == 0:
        raise RuntimeError("server treated forced client transport loss as a successful session")
    if "failed to restore VPN" in server.transcript:
        raise RuntimeError(f"VPN failure cleanup reported an error:\n{server.transcript}")


def wait_for_cleanup(
    baseline_dns: set[str],
    interface: str,
    routed_addresses: list[str],
) -> None:
    """Wait for all session-owned macOS network state to disappear.

    :param baseline_dns: DNS keys present before the session.
    :param interface: Session TUN interface.
    :param routed_addresses: Addresses that routed over the session interface.
    :raises RuntimeError: If cleanup remains incomplete.
    """

    deadline = time.monotonic() + 10.0
    state = ""
    while time.monotonic() < deadline:
        interfaces = current_interfaces()
        dns = vpn_dns_keys()
        journal_exists = privileged_path_exists(RECOVERY_JOURNAL)
        stale_routes: list[str] = []
        for address in routed_addresses:
            parsed_address = ipaddress.ip_address(address)
            family = (
                "-inet"
                if isinstance(parsed_address, ipaddress.IPv4Address)
                else "-inet6"
            )
            output = command_output(
                [
                    "route",
                    "-n",
                    "get",
                    family,
                    address,
                ],
                check=False,
            )
            if re.search(
                rf"^\s*interface:\s*{re.escape(interface)}\s*$",
                output,
                re.MULTILINE,
            ) is not None:
                stale_routes.append(address)
        if (
            interface not in interfaces
            and dns == baseline_dns
            and not journal_exists
            and len(stale_routes) == 0
        ):
            return
        state = (
            f"interfaces={sorted(interfaces)}, dns={sorted(dns)}, "
            f"journal={journal_exists}, stale_routes={stale_routes}"
        )
        time.sleep(0.1)
    raise RuntimeError(f"VPN host-network state survived shutdown: {state}")


def cleanup_processes(
    server: SpawnedProcess,
    client: SpawnedProcess,
    forwarder: TlsForwarder,
) -> None:
    """Best-effort cleanup for one session fixture.

    :param server: Server process.
    :param client: Client process.
    :param forwarder: TLS proxy.
    """

    try:
        if client.process.poll() is None:
            client.terminate()
        else:
            client.close()
    finally:
        try:
            if server.process.poll() is None:
                server.signal_group(signal.SIGINT)
                try:
                    server.wait(10.0)
                except RuntimeError:
                    server.terminate()
                else:
                    server.close()
            else:
                server.close()
        finally:
            forwarder.stop()


def run_domain_session(
    server_binary: Path,
    client_binary: Path,
    root_certificate: Path,
    server_certificate: Path,
    server_key: Path,
    echoes: EchoServices,
    baseline_route: tuple[str, str],
) -> None:
    """Exercise native DNS, dual-stack TUN, TCP, UDP, and graceful cleanup.

    :param server_binary: Built server executable.
    :param client_binary: Built client executable.
    :param root_certificate: PEM root trusted only by the fixture client.
    :param server_certificate: PEM certificate for the local WSS listener.
    :param server_key: PEM private key for the local WSS listener.
    :param echoes: Client-side loopback echo services.
    :param baseline_route: Normal route for unmatched internet traffic.
    """

    baseline_dns = vpn_dns_keys()
    baseline_interfaces = current_interfaces()
    server, client, forwarder = start_session(
        server_binary,
        client_binary,
        root_certificate,
        server_certificate,
        server_key,
        ["--vpn-include-domain", TEST_DOMAIN],
    )
    routed_addresses: list[str] = []
    try:
        interface = active_interface(server)
        if interface in baseline_interfaces:
            raise RuntimeError(f"VPN reused pre-existing interface {interface}")
        verify_interface_configuration(interface)
        if route_path("1.1.1.1") != baseline_route:
            raise RuntimeError("domain-selective VPN changed unmatched IPv4 routing")
        _dns_key, dns_servers = verify_supplemental_dns(baseline_dns, interface)
        answers = verify_dns_matrix(dns_servers)
        ipv4 = answers[DNS_TYPE_A]
        ipv6 = answers[DNS_TYPE_AAAA]
        if not isinstance(ipv4, ipaddress.IPv4Address) or not isinstance(
            ipv6, ipaddress.IPv6Address
        ):
            raise RuntimeError("synthetic DNS returned the wrong address families")
        routed_addresses.extend([str(server) for server in dns_servers])
        routed_addresses.extend([str(ipv4), str(ipv6)])
        verify_tcp_tunnel(ipv4, echoes.tcp_ports[socket.AF_INET])
        verify_tcp_tunnel(ipv6, echoes.tcp_ports[socket.AF_INET6])
        verify_udp_tunnel(ipv4, echoes.udp_ports[socket.AF_INET])
        verify_udp_tunnel(ipv6, echoes.udp_ports[socket.AF_INET6])
        echoes.assert_healthy()
        graceful_shutdown(server, client)
        wait_for_cleanup(
            baseline_dns,
            interface,
            routed_addresses,
        )
    except (OSError, RuntimeError) as error:
        server.read_available(0.2)
        client.read_available(0.2)
        raise RuntimeError(
            f"domain-selective macOS VPN session failed: {error}\n\n"
            f"--- server transcript ---\n{server.transcript}\n\n"
            f"--- client transcript ---\n{client.transcript}"
        ) from error
    finally:
        cleanup_processes(server, client, forwarder)


def run_cidr_failure_session(
    server_binary: Path,
    client_binary: Path,
    root_certificate: Path,
    server_certificate: Path,
    server_key: Path,
    baseline_route: tuple[str, str],
) -> None:
    """Exercise DNS-free readiness and cleanup after transport failure.

    :param server_binary: Built server executable.
    :param client_binary: Built client executable.
    :param root_certificate: PEM root trusted only by the fixture client.
    :param server_certificate: PEM certificate for the local WSS listener.
    :param server_key: PEM private key for the local WSS listener.
    :param baseline_route: Normal route for unmatched internet traffic.
    """

    baseline_dns = vpn_dns_keys()
    baseline_interfaces = current_interfaces()
    server, client, forwarder = start_session(
        server_binary,
        client_binary,
        root_certificate,
        server_certificate,
        server_key,
        ["--vpn-include-cidr", TEST_CIDR],
    )
    try:
        interface = active_interface(server)
        verify_interface_configuration(interface)
        if vpn_dns_keys() != baseline_dns:
            raise RuntimeError("CIDR-only VPN unexpectedly installed DNS policy")
        if route_path("1.1.1.1") != baseline_route:
            raise RuntimeError("CIDR-only VPN changed unmatched IPv4 routing")
        _gateway, selected_interface = route_path(TEST_CIDR_ADDRESS)
        if selected_interface != interface:
            raise RuntimeError(
                f"selected CIDR routes over {selected_interface}, not {interface}"
            )
        transport_failure_shutdown(server, client)
        wait_for_cleanup(
            baseline_dns,
            interface,
            [TEST_CIDR_ADDRESS],
        )
    except (OSError, RuntimeError) as error:
        server.read_available(0.2)
        client.read_available(0.2)
        raise RuntimeError(
            f"CIDR-selective macOS VPN session failed: {error}\n\n"
            f"--- server transcript ---\n{server.transcript}\n\n"
            f"--- client transcript ---\n{client.transcript}"
        ) from error
    finally:
        cleanup_processes(server, client, forwarder)


def preflight() -> None:
    """Refuse to run when the host cannot be safely isolated.

    :raises RuntimeError: If prerequisites or a clean baseline are missing.
    """

    if platform_module.system() != "Darwin":
        raise RuntimeError("the native macOS VPN harness runs only on macOS")
    for program in ["cargo", "ifconfig", "openssl", "route", "scutil", "sudo"]:
        if shutil.which(program) is None:
            raise RuntimeError(f"required program is unavailable: {program}")
    run_checked(["sudo", "-n", "true"])
    if privileged_path_exists(RECOVERY_JOURNAL):
        raise RuntimeError(
            f"refusing to replace active or recoverable VPN state at {RECOVERY_JOURNAL}"
        )
    dns = vpn_dns_keys()
    if len(dns) > 0:
        raise RuntimeError(f"another SSHPortal VPN DNS session is active: {sorted(dns)}")
    processes = command_output(["ps", "ax", "-o", "command="])
    active_servers = [
        line
        for line in processes.splitlines()
        if "sshportal-server" in line and re.search(r"(?:^|\s)--vpn(?:\s|$)", line) is not None
    ]
    if len(active_servers) > 0:
        raise RuntimeError(
            "another SSHPortal system VPN server is active:\n" + "\n".join(active_servers)
        )


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    :returns: Parsed arguments.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="reuse target/release binaries instead of rebuilding them",
    )
    return parser.parse_args()


def handle_termination(_signal_number: int, _frame: FrameType | None) -> None:
    """Turn process termination into normal Python unwinding.

    :param _signal_number: Delivered signal number.
    :param _frame: Interrupted Python frame.
    :raises KeyboardInterrupt: Always, so fixture cleanup runs.
    """

    raise KeyboardInterrupt


def main() -> int:
    """Run native domain and CIDR system-VPN sessions.

    :returns: Process exit status.
    """

    arguments = parse_arguments()
    preflight()
    if arguments.skip_build is False:
        run_checked(
            ["cargo", "build", "--locked", "--release", "--bins"],
            timeout_seconds=BUILD_TIMEOUT_SECONDS,
        )
    server_binary = PROJECT_ROOT / "target/release/sshportal-server"
    client_binary = PROJECT_ROOT / "target/release/sshportal-client"
    for binary in [server_binary, client_binary]:
        if not binary.is_file():
            raise RuntimeError(f"required release binary is missing: {binary}")

    signal.signal(signal.SIGTERM, handle_termination)
    baseline_route = route_path("1.1.1.1")
    with tempfile.TemporaryDirectory(prefix="sshportal-macos-vpn-e2e-") as raw_directory:
        directory = Path(raw_directory)
        root_certificate, server_certificate, server_key = generate_tls_material(directory)
        echoes = EchoServices()
        try:
            run_domain_session(
                server_binary,
                client_binary,
                root_certificate,
                server_certificate,
                server_key,
                echoes,
                baseline_route,
            )
            run_cidr_failure_session(
                server_binary,
                client_binary,
                root_certificate,
                server_certificate,
                server_key,
                baseline_route,
            )
        finally:
            echoes.stop()

    print("native macOS VPN end-to-end validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
