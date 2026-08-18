#![forbid(unsafe_code)]

mod control;
mod debug;
mod keys;
#[cfg(target_os = "macos")]
mod macos;
mod network;
mod platform;
mod shell;
mod socks;
mod vpn;
mod websocket;

pub use control::{
    ClientDecision, ClientHello, ClientMetadata, ControlPacket, OfferedSession, ServerOffer,
    VpnScope, recv_packet, send_packet,
};
pub use keys::{
    AuthorizedKeySupport, AuthorizedKeyTarget, OperatorKeyMaterial, authorized_key_support,
    load_operator_key, parse_public_key,
};
#[cfg(target_os = "macos")]
pub use macos::MacosPerAppVpn;
pub use network::{run_client_network_proxy, run_operator_socks_proxy};
pub use platform::{OperatingSystem, Platform, ShellLaunch};
pub use shell::{run_client_session_proxy, run_remote_shell_server};
pub use vpn::{SystemVpnPolicy, run_operator_vpn};
pub use websocket::{
    AsyncStream, ClientWebSocketStream, WebSocketClientTransport, connect_async_with_env_proxy,
    connect_async_with_env_proxy_and_extra_roots, normalize_websocket_url, websocket_config,
    websocket_to_io,
};

pub fn install_default_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub const DEFAULT_CONNECT_PATH: &str = "/connect";
pub const DEFAULT_HEALTH_PATH: &str = "/healthz";
pub const PROTOCOL_VERSION: u32 = 7;
pub(crate) const NETWORK_SESSION_FLOW_LIMIT: usize = 256;
pub(crate) const MAX_NETWORK_UDP_DATAGRAM_BYTES: usize = u16::MAX as usize - 20 - 8;

/// Hardens the platform's default dynamic-library resolution before application startup.
pub fn harden_dynamic_library_search() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    wintun_security::restrict_process_dll_search_to_system32()?;
    Ok(())
}
