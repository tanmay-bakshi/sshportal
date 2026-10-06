use std::fmt;
use std::io;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::Args;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Error as WebSocketError;

/// Controls recovery of a connection while the two endpoint processes remain running.
#[derive(Args, Clone, Debug, Default)]
pub struct ReconnectOptions {
    /// Enable bounded automatic reconnection. Enable this on both endpoints.
    #[arg(long)]
    pub reconnect: bool,
    /// Seconds between reconnect attempts (default: 5).
    #[arg(long, value_name = "SECONDS", requires = "reconnect", value_parser = clap::value_parser!(u64).range(1..=86_400))]
    pub reconnect_interval_seconds: Option<u64>,
    /// Maximum seconds to recover each lost connection (default: 300).
    #[arg(long, value_name = "SECONDS", requires = "reconnect", value_parser = clap::value_parser!(u64).range(1..=86_400))]
    pub reconnect_timeout_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectSettings {
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
}

impl ReconnectOptions {
    pub fn settings(&self) -> Result<Option<ReconnectSettings>> {
        if !self.reconnect {
            return Ok(None);
        }
        let settings = ReconnectSettings {
            interval_seconds: self.reconnect_interval_seconds.unwrap_or(5),
            timeout_seconds: self.reconnect_timeout_seconds.unwrap_or(300),
        };
        settings.validate()?;
        Ok(Some(settings))
    }
}

impl ReconnectSettings {
    pub fn validate(self) -> Result<()> {
        if !(1..=86_400).contains(&self.interval_seconds)
            || !(1..=86_400).contains(&self.timeout_seconds)
            || self.interval_seconds >= self.timeout_seconds
        {
            bail!(
                "reconnect durations must be between 1 and 86400 seconds, with interval < timeout"
            );
        }
        Ok(())
    }

    pub fn negotiate(self, peer: Self) -> Result<Self> {
        self.validate()?;
        peer.validate()?;
        let settings = Self {
            interval_seconds: self.interval_seconds.max(peer.interval_seconds),
            timeout_seconds: self.timeout_seconds.min(peer.timeout_seconds),
        };
        settings.validate()?;
        Ok(settings)
    }
}

/// A process-scoped resume credential. Debug output deliberately hides its bytes.
#[derive(Clone, Deserialize, Eq, Serialize)]
#[serde(transparent)]
pub struct ReconnectSecret([u8; 32]);

impl ReconnectSecret {
    pub fn generate() -> Self {
        Self(rand::random())
    }
}

impl PartialEq for ReconnectSecret {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for ReconnectSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReconnectSecret(<redacted>)")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectHello {
    pub client_identity: ReconnectSecret,
    pub server_identity: Option<ReconnectSecret>,
    pub settings: ReconnectSettings,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectOffer {
    pub server_identity: ReconnectSecret,
    pub settings: ReconnectSettings,
}

/// One absolute deadline covers delays and connection attempts during an outage.
pub struct ReconnectWindow {
    pub deadline: Instant,
    interval: Duration,
}

impl ReconnectWindow {
    pub fn new(settings: ReconnectSettings) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(settings.timeout_seconds),
            interval: Duration::from_secs(settings.interval_seconds),
        }
    }

    pub async fn wait(&self) -> Result<()> {
        let next_attempt = Instant::now() + self.interval;
        if next_attempt >= self.deadline {
            tokio::time::sleep_until(self.deadline).await;
            bail!("automatic reconnection window expired");
        }
        tokio::time::sleep_until(next_attempt).await;
        if Instant::now() >= self.deadline {
            bail!("automatic reconnection window expired");
        }
        Ok(())
    }
}

/// Distinguishes transport loss from local configuration, consent, and protocol failures.
pub fn is_connection_loss(error: &anyhow::Error) -> bool {
    if error.chain().any(|cause| cause.is::<FatalSessionFailure>()) {
        return false;
    }
    error.chain().any(|cause| {
        if let Some(error) = cause.downcast_ref::<TcpConnectFailure>() {
            return !matches!(error.0.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput);
        }
        if let Some(error) = cause.downcast_ref::<ProxyConnectFailure>() {
            return retryable_http_status(error.0);
        }
        if let Some(error) = cause.downcast_ref::<io::Error>() {
            return is_io_connection_loss(error);
        }
        if let Some(error) = cause.downcast_ref::<WebSocketError>() {
            return match error {
                WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed => true,
                WebSocketError::Protocol(
                    tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake
                    | tokio_tungstenite::tungstenite::error::ProtocolError::HandshakeIncomplete,
                ) => true,
                WebSocketError::Http(response) => retryable_http_status(response.status().as_u16()),
                _ => false,
            };
        }
        if let Some(error) = cause.downcast_ref::<h2::Error>() {
            return error.get_io().is_some_and(is_io_connection_loss);
        }
        if let Some(error) = cause.downcast_ref::<russh::Error>() {
            return match error {
                russh::Error::Disconnect | russh::Error::KeepaliveTimeout => true,
                russh::Error::IO(error) => is_io_connection_loss(error),
                _ => false,
            };
        }
        cause.is::<tokio::time::error::Elapsed>()
    })
}

fn is_io_connection_loss(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::AddrNotAvailable
    )
}

fn retryable_http_status(status: u16) -> bool {
    (500..=599).contains(&status) || matches!(status, 408 | 409 | 429)
}

/// Identifies the socket/DNS phase separately from TLS and protocol validation.
#[derive(Debug)]
pub(crate) struct TcpConnectFailure(pub(crate) io::Error);

impl fmt::Display for TcpConnectFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for TcpConnectFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug)]
pub(crate) struct ProxyConnectFailure(pub(crate) u16);

impl fmt::Display for ProxyConnectFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "proxy CONNECT failed with HTTP status {:03}",
            self.0
        )
    }
}

impl std::error::Error for ProxyConnectFailure {}

#[derive(Debug)]
pub(crate) struct FatalSessionFailure(pub(crate) anyhow::Error);

impl fmt::Display for FatalSessionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for FatalSessionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_negotiation_obey_both_endpoints() {
        assert!(ReconnectOptions::default().settings().unwrap().is_none());
        let settings = ReconnectOptions {
            reconnect: true,
            ..Default::default()
        }
        .settings()
        .unwrap()
        .unwrap();
        assert_eq!(
            settings,
            ReconnectSettings {
                interval_seconds: 5,
                timeout_seconds: 300
            }
        );
        assert_eq!(
            settings
                .negotiate(ReconnectSettings {
                    interval_seconds: 10,
                    timeout_seconds: 60,
                })
                .unwrap(),
            ReconnectSettings {
                interval_seconds: 10,
                timeout_seconds: 60
            }
        );
        assert!(
            settings
                .negotiate(ReconnectSettings {
                    interval_seconds: 1,
                    timeout_seconds: 2,
                })
                .is_err()
        );
    }

    #[test]
    fn resume_secrets_do_not_appear_in_debug_output() {
        assert_eq!(
            format!("{:?}", ReconnectSecret::generate()),
            "ReconnectSecret(<redacted>)"
        );
    }

    #[test]
    fn only_connection_failures_are_recoverable() {
        assert!(is_connection_loss(
            &io::Error::from(io::ErrorKind::ConnectionReset).into()
        ));
        assert!(!is_connection_loss(
            &io::Error::from(io::ErrorKind::PermissionDenied).into()
        ));
        assert!(is_connection_loss(
            &russh::Error::IO(io::Error::from(io::ErrorKind::BrokenPipe)).into()
        ));
        assert!(!is_connection_loss(
            &russh::Error::IO(io::Error::from(io::ErrorKind::InvalidData)).into()
        ));
        assert!(!is_connection_loss(
            &h2::Error::from(h2::Reason::PROTOCOL_ERROR).into()
        ));
        assert!(!is_connection_loss(&anyhow::anyhow!(
            "local user declined the session"
        )));
        assert!(is_connection_loss(
            &TcpConnectFailure(io::Error::other("DNS resolver unavailable")).into()
        ));
        assert!(is_connection_loss(&ProxyConnectFailure(503).into()));
        assert!(!is_connection_loss(&ProxyConnectFailure(403).into()));
        assert!(!is_connection_loss(&anyhow::Error::new(
            FatalSessionFailure(io::Error::from(io::ErrorKind::ConnectionReset).into(),)
        )));
        assert!(is_connection_loss(
            &WebSocketError::Protocol(
                tokio_tungstenite::tungstenite::error::ProtocolError::HandshakeIncomplete,
            )
            .into()
        ));
        assert!(!is_connection_loss(
            &WebSocketError::Http(Box::new(
                http::Response::builder().status(404).body(None).unwrap()
            ),)
            .into()
        ));
    }

    #[tokio::test]
    async fn retry_delays_stop_at_the_original_deadline() {
        let window = ReconnectWindow {
            deadline: Instant::now() + Duration::from_millis(40),
            interval: Duration::from_millis(10),
        };
        window.wait().await.unwrap();
        tokio::time::sleep_until(window.deadline).await;
        assert!(window.wait().await.is_err());
    }
}
