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
operator TUN -> in-process tun-to-SOCKS -> existing WebSocket -> client TCP/UDP egress
```

The TUN interface and routes exist only on the operator side. The client opens ordinary outbound TCP and UDP sockets and requires no administrator privileges, kernel extension, TUN driver, or route changes.

Start the server as root on Linux or macOS, or from an elevated terminal on Windows:

```bash
sudo sshportal-server \
  --listen 127.0.0.1:8080 \
  --operator-name support-team \
  --vpn
```

VPN mode requires an HTTPS/WSS URL. `sshportal-server` deliberately remains a small HTTP/WS server, so terminate TLS with a reverse proxy and forward the WebSocket to its local listener:

```text
sshportal-client -> wss://support.example/connect -> TLS reverse proxy -> ws://127.0.0.1:8080/connect
```

The reverse proxy must append its immediate peer address to `X-Forwarded-For`, as standard proxy-add behavior does. When the proxy connects from loopback, the server pins the rightmost address in that header so the live TLS transport keeps its original physical route. In a multi-proxy chain, that address is the adjacent external hop, not necessarily the original client. Requests arriving from non-loopback peers cannot inject route bypasses through this header.

Use the token printed by the server with the public HTTPS origin:

```bash
sshportal-client \
  --server "https://support.example?token=<printed-token>"
```

The client refuses a VPN offer received through `http://` or `ws://`, including when `--approve-session` is present.

### macOS per-app VPN

On macOS 13 or later, `--vpn-app` routes only a selected signed application through the client. The server process does not need root privileges, does not install routes, and does not create a TUN interface:

```text
selected app and helpers -> SSHPortal app proxy -> private authenticated SOCKS5
                         -> existing WebSocket -> client TCP/UDP egress

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

The client connects through the same HTTPS/WSS URL and sees a consent prompt naming the selected application. The first operator-side run asks macOS to approve the SSHPortal system extension and VPN configuration. System policy may require an administrator to approve that installation, but `sshportal-server` itself must remain an ordinary user process.

The rule matches the selected executable by signing identifier, designated requirement, and path. macOS also includes helper processes spawned by that application, which covers normal browser renderer, networking, and GPU helpers. It does not identify one PID: another instance of the same signed application at the same path is in scope too. Existing connections retain their existing path; new TCP and UDP flows use the tunnel until the WebSocket closes or the server stops. Other applications keep their normal route.

The companion owns no remote transport. It forwards native Network Extension flows into a random, username/password-protected loopback SOCKS endpoint owned by `sshportal-server`; Rust keeps ownership of client consent, the WebSocket, TCP/UDP multiplexing, and teardown. Normal shutdown, transport loss, startup failure, Ctrl-C, SIGTERM, SIGHUP, or loss of the companion control pipe removes the per-app VPN configuration.

### Routing behavior

VPN mode installs IPv4 and IPv6 split-default routes through the TUN and pins the established WebSocket peer to its original physical path. Existing directly attached networks and loopback remain local. Existing system DNS servers receive explicit TUN routes, and virtual DNS keeps hostname resolution on the client side instead of leaking names through the operator's upstream resolver.

This is intentionally a TCP/UDP application tunnel rather than a general IP router. ICMP, multicast, and other IP protocols are not carried. Applications that need ping or raw sockets will not behave like they do on WireGuard or IPsec.

Routes are registered transactionally and restored in reverse order after Ctrl-C (or Ctrl-Break on Windows), transport loss, setup failure, or normal exit. Unix also handles SIGTERM and SIGHUP. Avoid forcibly terminating the process while it owns the TUN. The route entries are non-persistent, but a reboot may be required if the operating system or a third-party network manager retains stale state after an unclean termination.

### Platform requirements

- Linux needs `/dev/net/tun`, root or `CAP_NET_ADMIN`, and the `ip` command from `iproute2`.
- macOS needs root privileges to configure the `utun` routes.
- Windows needs an elevated terminal and the signed `wintun.dll` beside `sshportal-server.exe`. Official Windows release archives include the DLL and its redistribution license. The binary verifies the DLL's Authenticode signature before loading it.

Only the operator-side server needs these privileges and platform components. A Windows machine running only `sshportal-client.exe` does not need elevation or `wintun.dll`.

## Build and test

The minimum supported Rust version is 1.90.

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

The Docker-backed Linux end-to-end harnesses are [`tools/docker_e2e.py`](tools/docker_e2e.py) for SSH and [`tools/docker_vpn_e2e.py`](tools/docker_vpn_e2e.py) for the isolated WSS/TUN/TCP/UDP/DNS path.

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
rustup toolchain install 1.90.0 \
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

## License

`sshportal` is licensed under Apache 2.0. See [`LICENSE`](LICENSE). The separately distributed Wintun binary is governed by its bundled license.
