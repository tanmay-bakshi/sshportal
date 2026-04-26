# sshportal

`sshportal` is a Rust remote-support tool that turns a single, user-approved WebSocket attachment into an SSH-accessible shell session. It is built for cases where an operator needs shell access into a user environment without pre-provisioning an always-on agent, VPN, or inbound SSH listener.

The project ships two binaries:

- `sshportal-server`: hosts the rendezvous endpoint, prints a one-time join token, and exposes a local SSH proxy once a client connects.
- `sshportal-client`: connects back to the server, presents environment metadata, prompts the local user for consent, and serves the approved shell session.

## What It Does

- Opens a temporary support session through an HTTP or WebSocket front door.
- Requires the client-side user to approve shell access before the session becomes active.
- Reuses the established transport for repeated SSH sessions during the same support window.
- Optionally exposes a local SOCKS5 proxy on the server side by forwarding `direct-tcpip` channels through the client.
- Optionally installs a persistent operator SSH key on POSIX clients when both sides request and approve that action.

## Operating Model

`sshportal` is intentionally small and single-purpose:

1. The server listens for exactly one client attachment at a time.
2. The server prints a one-time join token.
3. The client connects with that token and receives the operator identity and SSH public key.
4. The local user approves or declines the support session.
5. If approved, the server shuts down the HTTP listener and keeps only the upgraded transport alive for the active session.
6. The operator reaches the client by SSHing to the local proxy listener that the server binds.

This keeps the trust model easy to inspect. There is no long-lived daemon on the client side, no background control plane, and no multi-session broker.

## Quick Start

Start the server:

```bash
cargo run --bin sshportal-server -- \
  --listen 0.0.0.0:8080 \
  --operator-name support-team \
  --ssh-listen 127.0.0.1:2222
```

The server prints a join token and the exact connection URL to hand to the client.

Connect from the client:

```bash
cargo run --bin sshportal-client -- \
  --server "http://server-host:8080?token=<printed-token>"
```

After the client user approves the prompt, open a shell from the server side:

```bash
ssh -p 2222 client-username@127.0.0.1
```

If the server starts without `--ssh-listen`, it binds `127.0.0.1:0` and prints the selected port once the client transport is established.

## Session Approval And Persistence

By default, the client asks only for approval to open the live support session.

To request persistent future access with an existing operator key:

```bash
cargo run --bin sshportal-server -- \
  --listen 0.0.0.0:8080 \
  --operator-name support-team \
  --operator-key /path/to/id_ed25519 \
  --persist-operator-key
```

On POSIX clients, the user is then prompted separately before the key is appended to `~/.ssh/authorized_keys`. Windows clients keep the session ephemeral and report that persistent key installation is unsupported.

When approval has already been handled out of band, the client can skip prompts:

```bash
cargo run --bin sshportal-client -- \
  --server "http://server-host:8080?token=<printed-token>" \
  --approve-session \
  --approve-key-install
```

## Dynamic Forwarding

To expose a local SOCKS5 proxy on the server side for the lifetime of the session:

```bash
cargo run --bin sshportal-server -- \
  --listen 0.0.0.0:8080 \
  --operator-name support-team \
  --ssh-listen 127.0.0.1:2222 \
  --dynamic-forward 127.0.0.1:1080
```

The SOCKS5 listener accepts unauthenticated `CONNECT` requests, matching the forwarding model of `ssh -D`.
Destinations are opened from the approved client environment, so the proxy uses the client network on Linux, macOS, and Windows.

## Build

Build both binaries locally:

```bash
cargo build --bins
```

Run the standard local validation loop:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

The Linux Docker-backed end-to-end harness lives at [`tools/docker_e2e.py`](tools/docker_e2e.py). It builds static musl binaries on the host, assembles the runtime image, and verifies the interactive shell contract inside Docker.

## Static Linux Builds

Build fully static musl binaries for `x86_64`:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --bins
```

Build fully static musl binaries for `aarch64`:

```bash
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl --bins
```

This repository pins `rust-lld` for both musl targets in [`.cargo/config.toml`](.cargo/config.toml), which allows the same commands to work cleanly from macOS hosts.

## Release Tags

Pushing a tag that matches `vX.X.X` publishes a GitHub Release with fully static Linux musl archives for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
Each archive contains `sshportal-client`, `sshportal-server`, `README.md`, and `LICENSE`, and each archive is published with a `.sha256` checksum file.

## Container Image

The [`Dockerfile`](Dockerfile) packages prebuilt static binaries from `target/<triple>/release` into a small Alpine runtime image:

```bash
cargo build --release --target x86_64-unknown-linux-musl --bins
docker buildx build \
  --platform linux/amd64 \
  --build-arg TARGET_TRIPLE=x86_64-unknown-linux-musl \
  --load \
  -t sshportal:amd64 .
```

The same pattern applies to `aarch64-unknown-linux-musl`.

## License

`sshportal` is licensed under Apache 2.0. See [`LICENSE`](LICENSE).
