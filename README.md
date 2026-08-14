# sshportal

`sshportal` turns one user-approved WebSocket attachment into a temporary remote-support session. The operator chooses exactly one session mode, and the client user sees and approves that capability before it becomes active.

| Mode | Operator-side interface | Client-side privilege | Traffic carried |
| --- | --- | --- | --- |
| SSH | Local SSH listener | None | Shells, commands, and optional SSH dynamic forwarding |
| SOCKS | Local SOCKS5 listener | None | TCP `CONNECT` and UDP `ASSOCIATE` |
| VPN | System TUN interface | None | Internet-bound IPv4/IPv6 TCP, UDP, and DNS |
| macOS per-app VPN | One signed app and its helper processes | None | TCP and UDP flows from that app |

The project ships two binaries:

- `sshportal-server` hosts the one-time rendezvous endpoint and exposes the selected capability on the operator's machine.
- `sshportal-client` connects back, presents the requested capability for consent, and provides network or shell access from the client environment.

The server accepts one client at a time. Once the consent handshake succeeds, it closes the HTTP listener and keeps only that session's WebSocket alive. There is no persistent client daemon, background control plane, or multi-session broker.

## SSH Mode

SSH is the default mode:

```bash
sshportal-server \
  --listen 0.0.0.0:8080 \
  --operator-name support-team \
  --ssh-listen 127.0.0.1:2222
```

Give the printed tokenized URL to the client user:

```bash
sshportal-client \
  --server "http://server-host:8080?token=<printed-token>"
```

After approval, connect to the local operator-side listener:

```bash
ssh -p 2222 client-username@127.0.0.1
```

If `--ssh-listen` is omitted, the server chooses a free loopback port and prints it after the session is established.

### Persistent operator keys

Sessions are ephemeral by default. To separately request permission to install an existing operator key on a POSIX client:

```bash
sshportal-server \
  --operator-key /path/to/id_ed25519 \
  --persist-operator-key
```

Windows clients keep SSH sessions ephemeral because persistent `authorized_keys` installation is not supported there.

When consent has already been handled out of band, the client can use `--approve-session` and, for a requested persistent key, `--approve-key-install`.

### SSH-backed SOCKS forwarding

SSH mode can expose an additional SOCKS5 listener backed by SSH `direct-tcpip` channels:

```bash
sshportal-server \
  --ssh-listen 127.0.0.1:2222 \
  --dynamic-forward 127.0.0.1:1080
```

This listener supports TCP `CONNECT`, like `ssh -D`. The SSH listener and SOCKS listener remain available for the same approved session.

## SOCKS Mode

`--socks-only` skips SSH entirely and multiplexes SOCKS traffic directly over the WebSocket:

```bash
sshportal-server \
  --listen 0.0.0.0:8080 \
  --operator-name support-team \
  --socks-only 127.0.0.1:1080
```

The client connects normally. Once the user approves the SOCKS-specific prompt, applications on the operator machine can use the listener:

```bash
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

SOCKS mode supports TCP `CONNECT` and UDP `ASSOCIATE`. Destination names are resolved from the client environment, so both protocols use the client's network path. It does not generate SSH keys, launch a shell, start an SSH server, or place traffic inside SSH channels.

The listener is unauthenticated. Keep it on loopback unless other machines should deliberately be able to use the client's network. SOCKS mode warns when it is negotiated over plain WS because its confidentiality then depends entirely on the surrounding network.

## VPN Mode

### System-wide VPN

System-wide VPN mode gives ordinary applications on the operator machine a path through the client without requiring proxy configuration in each application:

```text
operator applications
        |
        v
operator TUN -> in-process TCP/UDP endpoint -> bounded HTTP/2 session
             -> approved WebSocket -> client sockets and system resolver
```

The TUN interface and routes exist only on the operator side. SSHPortal terminates TCP locally with
`smoltcp`, and it does not complete an application's TCP handshake until the client has opened the
real destination. TCP streams use HTTP/2 `CONNECT`; UDP flows use Extended CONNECT and
RFC 9297/9298 capsules. All network streams share one bounded HTTP/2 connection carried inside the
already-approved WebSocket. The client opens ordinary outbound sockets and requires no
administrator privileges, kernel extension, TUN driver, or route changes.

Start the server as root on Linux or macOS, or from an elevated terminal on Windows:

```bash
sudo sshportal-server \
  --listen 127.0.0.1:8080 \
  --operator-name support-team \
  --vpn
```

With no selectors, `--vpn` is a full tunnel. Supplying any include selector changes it to an
allowlist split tunnel. Repeat either option as needed; CIDR and domain selectors have union
semantics:

```bash
sudo sshportal-server \
  --listen 127.0.0.1:8080 \
  --operator-name support-team \
  --vpn \
  --vpn-include-cidr 10.20.0.0/16 \
  --vpn-include-cidr 2001:db8:1200::/48 \
  --vpn-include-domain elevancehealth.com \
  --vpn-include-domain anthem.com
```

A domain selector includes its apex and every subdomain, so `anthem.com` also selects
`login.anthem.com`; wildcard syntax is not accepted. Domain names are normalized to lowercase
ASCII/IDNA form, and CIDRs are normalized to their network address. Everything that matches none
of the selectors continues over the operator machine's normal network path.

Domain routing uses the operating system's split-DNS facility rather than resolving a hostname
once and pinning its current addresses. Queries for selected suffixes go to session-specific
virtual IPv4 and IPv6 resolvers. Over dedicated bounded HTTP/2 streams, SSHPortal asks the client's
platform resolver whether the original fully qualified name has an address in the requested
family. This preserves macOS scoped resolvers, Windows NRPT, corporate VPN DNS, hosts-file entries,
and other native resolver policy. The client sends back only a positive or negative result and a
short synthetic TTL, never the real addresses or aliases. SSHPortal returns a stable synthetic
address directly at the original queried name; a later connection is reversed to that same
hostname before the client resolves and opens it. Connections through an A-derived synthetic
address remain IPv4-only, and connections through an AAAA-derived address remain IPv6-only. Real
destination addresses therefore never need to become routes on the operator machine, and a CNAME
cannot escape the approved suffix by becoming a separately routable synthetic name.

The IPv4 synthetic pool is a collision-checked `/16` selected from the RFC 2544 benchmarking range
(`198.18.0.0/16` or `198.19.0.0/16`); the IPv6 pool is a session-specific ULA `/96`. SSHPortal
refuses to start domain or full-tunnel DNS when it cannot allocate non-conflicting pools. In
selective mode, unselected DNS queries continue to use the operator's normal resolvers. A
CIDR-only policy allocates no synthetic pools and does not change DNS configuration.

VPN mode requires an HTTPS/WSS URL. `sshportal-server` deliberately remains a small HTTP/WS server,
so terminate TLS with a reverse proxy and forward the WebSocket to its listener over a trusted
backend hop:

```text
sshportal-client -> wss://support.example/connect -> TLS reverse proxy
                 -> private backend hop -> ws://operator-host:8080/connect
```

For VPN routing, SSHPortal trusts only the address of the TCP socket that actually carries its
WebSocket. It installs a physical-path exception for that immediate peer and deliberately ignores
`Forwarded` and `X-Forwarded-For`; client-controlled headers must never be allowed to create host
route exceptions. An off-host TLS proxy works naturally because it is the immediate socket peer.
A proxy on the operator machine needs its client-facing connection independently excluded from a
full-tunnel route, so an off-host proxy is the simpler full-tunnel topology. Selective policies do
not need an extra exception when the local proxy's peer is outside every selected prefix. Keep an
off-host proxy's unencrypted backend hop on a trusted private network or inside a separate encrypted
tunnel.

Use the token printed by the server with the public HTTPS origin:

```bash
sshportal-client \
  --server "https://support.example?token=<printed-token>"
```

The client refuses a VPN offer received through `http://` or `ws://`, including when
`--approve-session` is present. WSS servers and HTTPS proxies are verified against the platform
trust policy. On Windows and macOS, that includes locally installed enterprise roots and
operating-system distrust decisions; copying the same executable to another machine does not carry
a private bundled CA snapshot with it.

The approved capability is enforced again for every client-side network stream before DNS or
socket creation. SOCKS and macOS per-app sessions permit arbitrary TCP and UDP destinations but no
resolver streams. Full system VPN permits arbitrary destinations and resolver names. A selective
system VPN permits literal addresses only inside its approved CIDRs and hostnames or resolver names
only inside its approved suffixes; a CIDR-only session cannot use the resolver endpoint.

### macOS per-app VPN

On macOS 15 or later, `--vpn-app` routes only a selected signed application through the client. The
server process does not need root privileges, does not install routes, and does not create a TUN
interface:

```text
selected app and helpers -> SSHPortal app proxy -> private authenticated SOCKS5
                         -> bounded HTTP/2 session -> approved WebSocket
                         -> client TCP/UDP egress

all other applications  -> normal macOS network path
```

Install the signed companion in `/Applications`, then select the target `.app` bundle:

```bash
sshportal-server \
  --listen 127.0.0.1:8080 \
  --operator-name support-team \
  --vpn-app /Applications/Firefox.app \
  --vpn-companion /Applications/SSHPortal.app
```

The client connects through the same HTTPS/WSS URL and sees a consent prompt naming the selected
application. That name describes the scope requested and enforced by the operator's macOS
companion. The client cannot attest the originating process across the WebSocket, so approving an
application session authorizes arbitrary outbound TCP and UDP requested through that session. The
first operator-side run asks macOS to approve the SSHPortal system extension and VPN configuration.
System policy may require an administrator to approve that installation, but `sshportal-server`
itself must remain an ordinary user process.

The rule matches the selected executable by signing identifier, designated requirement, and path. macOS also includes helper processes spawned by that application, which covers normal browser renderer, networking, and GPU helpers. It does not identify one PID: another instance of the same signed application at the same path is in scope too. Existing connections retain their existing path; new TCP and UDP flows use the tunnel until the WebSocket closes or the server stops. Other applications keep their normal route.

The companion owns no remote transport. It forwards native Network Extension flows into a random,
username/password-protected loopback SOCKS endpoint owned by `sshportal-server`. That endpoint uses
the same bounded HTTP/2 network session as SOCKS and system VPN modes, so client consent, egress,
flow limits, and teardown have one implementation. Normal shutdown, transport loss, startup
failure, Ctrl-C, SIGTERM, SIGHUP, or loss of the companion control pipe removes the per-app VPN
configuration.

### Routing behavior

Full-tunnel system VPN mode installs IPv4 and IPv6 split-default routes through the TUN and makes
both virtual resolvers the system's default DNS path. Selective mode installs only the requested
CIDR routes plus the virtual IPv4 and IPv6 pools when domain selectors are present. Both modes pin
the WebSocket's immediate socket peer to its original physical path; broader selected CIDRs are
safe because that host route is more specific, but an exact `/32` or `/128` selector for the peer
is rejected. Existing directly attached networks and loopback remain local unless a more-specific
selected route deliberately covers them.

This is intentionally a TCP/UDP application tunnel rather than a general IP router. Its important
boundaries are:

- ICMP, multicast, raw IP, and unsolicited inbound listeners are not carried. `ping`, service
  discovery, and protocols built directly on IP do not behave as they do on WireGuard or IPsec.
- The client creates new outbound sockets, so the destination observes the client's source address,
  not the operator's. Existing flows cannot resume after WebSocket or HTTP/2 transport loss.
- UDP datagram boundaries and FIFO order are preserved, but HTTP/2 makes delivery ordered rather
  than native-UDP unordered. Bounded queues may discard UDP under sustained pressure; TCP applies
  backpressure instead.
- One session admits at most 256 aggregate TCP and UDP flows. Excess VPN packets that would create
  another flow are discarded until capacity returns; DNS resolver streams have separate reserved
  capacity so long-lived flows cannot starve name resolution.
- The family-independent UDP payload limit is 65,507 bytes, the largest payload representable in a
  minimum-header IPv4 datagram. Larger IPv6 UDP payloads are also rejected so every layer of the
  tunnel enforces the same portable contract.
- IPv4 options and IPv6 extension-header chains other than supported fragmentation are rejected.
  Fragment reassembly accepts at most 64 fragments per datagram, 64 concurrent datagrams, and 4
  MiB of buffered fragment state. A datagram identity that exceeds the fragment limit is kept
  poisoned until its 60-second expiry, so a sustained train of tiny fragments cannot restart the
  same assembly or retain additional payload memory.
- The synthetic resolver is designed around address discovery. It synthesizes A and AAAA directly
  at the original queried name after the client's native resolver confirms that address family.
  CNAME, HTTPS, and SVCB receive alias-free NODATA, and unsupported record types receive NOTIMP;
  arbitrary DNS records are not proxied.
- Platform `getaddrinfo` errors do not reliably distinguish NXDOMAIN from family-specific NODATA:
  `dns-lookup` can report either as `NoName`. SSHPortal conservatively returns NOERROR/NODATA in
  both cases instead of allowing one failed family lookup to suppress a valid lookup for the other
  family. Consequently, synthetic DNS does not preserve authoritative NXDOMAIN semantics.

Routes and split-DNS state are registered transactionally and restored after Ctrl-C (or Ctrl-Break
on Windows), transport loss, setup failure, or normal exit. DNS policy is removed before TUN
routes. Unix also handles SIGTERM and SIGHUP. A private recovery journal lets the next privileged
run remove resources left by a crashed owner, and active sessions periodically reconcile their
routes and DNS after host-network changes. Avoid forcibly terminating the process while it owns the
TUN; the journal cannot compensate for every third-party network manager retaining stale state.
The journal recovery logic has deterministic unit coverage, but an actual privileged SIGKILL and
restart remains a manual integration test rather than a CI test.

Hostname selection necessarily has a few edges:

- Application-controlled DNS-over-HTTPS or DNS-over-TLS bypasses operating-system suffix routing.
  Disable the application's private DNS mode or use CIDR selectors for the resulting destinations;
  routing only the encrypted resolver does not recover the queried hostname.
- Literal IP connections and real addresses already cached by an application carry no hostname to
  match. Restart the application or clear its DNS cache after changing a policy.
- A selected site can depend on identity, API, or CDN names under unrelated domains. Those suffixes
  need their own selectors.
- Synthetic answers are unsigned, and SSHPortal does not proxy the DNSSEC records needed to
  authenticate them. Strict operator-side DNSSEC validation can therefore reject selected names.
- One of `198.18.0.0/16` and `198.19.0.0/16` is reserved for SSHPortal's virtual names while domain
  selection is active, so that selected `/16` cannot simultaneously represent real destinations.

### Platform requirements

- Linux needs root, access to `/dev/net/tun`, `CAP_NET_ADMIN`, and the `ip` command from `iproute2`.
  `CAP_NET_ADMIN` alone is insufficient because SSHPortal also owns private crash-recovery state
  under `/var/run`. Full tunnel and domain-selective policies additionally require
  systemd-resolved and `resolvectl`; SSHPortal fails closed instead of silently sending tunneled
  DNS to the normal resolver when they are unavailable.
- macOS needs root privileges to configure the `utun` routes. Full tunnel and domain-selective
  policies use a process-session-scoped resolver in the SystemConfiguration dynamic store.
- Windows requires Windows 10 version 1607 or later. System VPN mode needs an elevated terminal
  and the signed `wintun.dll` beside `sshportal-server.exe`.
  Full tunnel and domain-selective policies use a session-unique local NRPT rule. Official Windows
  release archives include the DLL and its redistribution license. Before loading Wintun,
  SSHPortal checks the bundled DLL against a pinned architecture-specific SHA-256, stages a fresh
  copy under `%ProgramData%\SSHPortal` with a protected Administrators-and-SYSTEM-only ACL, and
  locks both the directory and file against replacement. It verifies the exact locked file's hash,
  Authenticode trust, and `WireGuard LLC` publisher, and holds those locks until the Windows loader
  has opened the DLL.

Only the operator-side server needs these privileges and platform components. A Windows machine running only `sshportal-client.exe` does not need elevation or `wintun.dll`.

## Build and test

The minimum supported Rust version is 1.91.

The Rust client and the SOCKS and system-VPN server modes build natively on Linux, macOS, and
Windows. The macOS 15-or-later per-app mode additionally needs the Swift companion and system
extension. CI compiles and tests the Rust code on all three operating systems, builds both
architectures of the macOS companion without signing, cross-builds the static-CRT Windows package
from macOS, and runs the privileged system-VPN end-to-end path in Linux containers.

```bash
cargo build --bins
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
```

The native macOS targets and their protocol tests can be built without signing:

```bash
ruby macos/Support/generate_project.rb
xcodebuild \
  -project macos/SSHPortal.xcodeproj \
  -scheme SSHPortal \
  -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath target/macos-derived \
  CODE_SIGNING_ALLOWED=NO \
  test
```

[`macos/Support/build_universal.sh`](macos/Support/build_universal.sh) builds arm64 and x86-64 Rust binaries plus a universal companion and embedded system extension. Its unsigned mode is useful for compilation and packaging checks, but macOS will not activate an unsigned network extension:

```bash
macos/Support/build_universal.sh --unsigned
```

The output is `target/sshportal-macos-universal.zip` with a neighboring SHA-256 checksum file.

#### macOS signing and notarization

Native per-app VPN requires a paid Apple Developer Program team with the Network Extensions and System Extension capabilities. A Personal Team cannot create the required profiles.

For local development, let Xcode create Apple Development profiles after selecting the paid team:

```bash
xcodebuild \
  -project macos/SSHPortal.xcodeproj \
  -scheme SSHPortal \
  -configuration Debug \
  -destination 'generic/platform=macOS' \
  -derivedDataPath target/macos-development-derived \
  -allowProvisioningUpdates \
  DEVELOPMENT_TEAM='<paid-team-id>' \
  build
```

The account must have an unexpired Apple Development certificate whose private key is present in the login keychain.

For Developer ID distribution, create and install two manual provisioning profiles:

- The `com.tanmaybakshi.sshportal.macos` profile grants Network Extensions and System Extension installation.
- The `com.tanmaybakshi.sshportal.macos.AppProxyExtension` profile grants Network Extensions.

The keychain must also contain the matching Developer ID Application certificate and its private key. Build a signed universal package with the profile names shown in the developer portal:

```bash
export SSHPORTAL_DEVELOPMENT_TEAM='<paid-team-id>'
export SSHPORTAL_APP_PROFILE='<containing-app-profile-name>'
export SSHPORTAL_EXTENSION_PROFILE='<app-proxy-profile-name>'
export SSHPORTAL_DEVELOPER_IDENTITY='Developer ID Application: Example Name (TEAMID)'
macos/Support/build_universal.sh --developer-id
```

To notarize in the same build, first store notary credentials using `xcrun notarytool store-credentials`, then set `SSHPORTAL_NOTARY_PROFILE` to that keychain profile name. The build submits the archive, staples the companion app, and recreates the final zip.

The Docker-backed Linux end-to-end harnesses are [`tools/docker_e2e.py`](tools/docker_e2e.py) for
SSH and [`tools/docker_vpn_e2e.py`](tools/docker_vpn_e2e.py) for the isolated
WSS/TUN/TCP/UDP/DNS path. The VPN fixture runs a real DBus and systemd-resolved control plane and
checks full-tunnel, CIDR-selective, and domain-selective routing. Its `echo.test` name exists only
on the client network, so the domain case verifies resolver suffix routing, synthetic-address
hostname reversal, and both TCP and UDP client-side name resolution.

### Static Linux binaries

Build fully static musl binaries for x86-64:

```bash
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --locked --release --target x86_64-unknown-linux-musl --bins
```

For ARM64, replace the target with `aarch64-unknown-linux-musl` and the variable suffix with `aarch64_unknown_linux_musl`. Native Linux builds can use `musl-gcc`. Cross-builds need the target-prefixed compiler, such as `aarch64-linux-musl-gcc`. The Docker test harness selects an installed compiler automatically.

### Static-CRT Windows binaries

On macOS, install the pinned cross-compiler and Rust target, then run the release builder:

```bash
brew install llvm lld jq
rustup toolchain install 1.91.0 \
  --profile minimal \
  --target x86_64-pc-windows-msvc
cargo install --locked --version 0.21.4 cargo-xwin
tools/build_windows_release.sh
```

`cargo-xwin` downloads Microsoft CRT and Windows SDK files. Using it accepts [Microsoft's license for those files](https://go.microsoft.com/fwlink/?LinkId=2086102).

The builder compiles both executables with the MSVC ABI and static CRT, verifies their x86-64 PE headers, rejects imports outside the Windows system DLL set, verifies the pinned Wintun DLL, and writes a zip plus its SHA-256 file under `dist/`. This also catches accidental dynamic dependencies on the Visual C++, UCRT, MinGW, or other third-party runtimes.

The equivalent native build from Windows PowerShell is:

```powershell
rustup target add x86_64-pc-windows-msvc
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --locked --release --target x86_64-pc-windows-msvc --bins
```

Rust and C/C++ runtime code is statically linked where Windows permits it. Normal Windows system DLLs remain dynamic dependencies, and VPN mode requires the separately packaged `wintun.dll` beside `sshportal-server.exe`. Wintun retains its upstream Authenticode signature and is verified again by the server before loading. The SSHPortal executables themselves remain unsigned unless they are signed separately after the build.

## Container image

The [`Dockerfile`](Dockerfile) packages prebuilt static Linux binaries into a small Alpine image:

```bash
CC_x86_64_unknown_linux_musl=musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --locked --release --target x86_64-unknown-linux-musl --bins
docker buildx build \
  --platform linux/amd64 \
  --build-arg TARGET_TRIPLE=x86_64-unknown-linux-musl \
  --load \
  -t sshportal:amd64 .
```

To run VPN mode in a container, also pass `/dev/net/tun` and `CAP_NET_ADMIN`.

## Releases

Pushing a `vX.Y.Z` tag publishes archives for static x86-64 and ARM64 Linux binaries plus static-CRT x86-64 Windows binaries. The Windows archive also contains the signed Wintun DLL and [`WINTUN-LICENSE.txt`](licenses/WINTUN.txt). Every archive has a SHA-256 checksum file.

The tagged workflow does not publish an unsigned macOS per-app companion as though it were usable.
Build the universal macOS package with the signing and optional notarization procedure above; the
standalone Rust binaries remain sufficient for system VPN, SOCKS, and SSH modes on macOS.

## License

`sshportal` is licensed under Apache 2.0. See [`LICENSE`](LICENSE). The separately distributed Wintun binary is governed by its bundled license.
