#![forbid(unsafe_code)]

mod control;
mod debug;
mod keys;
#[cfg(target_os = "macos")]
mod macos;
mod platform;
mod proxy;
mod shell;
mod socks;
mod vpn;
mod websocket;

pub use control::{
    ClientDecision, ClientHello, ClientMetadata, ControlPacket, OfferedSession, ServerOffer,
    VpnScope, recv_packet, send_packet, validate_protocol_version,
};
pub use keys::{
    AuthorizedKeySupport, AuthorizedKeyTarget, OperatorKeyMaterial, authorized_key_support,
    load_operator_key, parse_public_key,
};
#[cfg(target_os = "macos")]
pub use macos::MacosPerAppVpn;
pub use platform::{OperatingSystem, Platform, ShellLaunch};
pub use proxy::{run_client_network_proxy, run_operator_socks_proxy};
pub use shell::{run_client_session_proxy, run_remote_shell_server};
pub use vpn::run_operator_vpn;
pub use websocket::{
    AsyncStream, ClientWebSocketStream, WebSocketClientTransport, connect_async_with_env_proxy,
    normalize_websocket_url, websocket_to_io,
};

pub fn install_default_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub const DEFAULT_CONNECT_PATH: &str = "/connect";
pub const DEFAULT_HEALTH_PATH: &str = "/healthz";
pub const PROTOCOL_VERSION: u32 = 5;
