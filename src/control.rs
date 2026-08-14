use std::fmt;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

use crate::PROTOCOL_VERSION;
use crate::platform::Platform;
use crate::vpn::SystemVpnPolicy;

const MAX_DISPLAY_LABEL_BYTES: usize = 256;
const MAX_DECISION_NOTE_BYTES: usize = 2 * 1024;
const MAX_WEBSOCKET_CLOSE_REASON_BYTES: usize = 123;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientMetadata {
    pub hostname: String,
    pub username: String,
    pub working_directory: String,
    pub platform: Platform,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    pub protocol_version: u32,
    pub metadata: ClientMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerOffer {
    pub protocol_version: u32,
    pub operator_name: String,
    pub session: OfferedSession,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum OfferedSession {
    Ssh {
        ssh_public_key: String,
        persist_key_requested: bool,
    },
    Socks {},
    Vpn {
        scope: VpnScope,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VpnScope {
    System { policy: SystemVpnPolicy },
    Application { application: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientDecision {
    pub session_allowed: bool,
    pub key_installed: bool,
    pub note: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlPacket {
    ClientHello(ClientHello),
    ServerOffer(ServerOffer),
    ClientDecision(ClientDecision),
}

impl fmt::Debug for ControlPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClientHello(_) => "ClientHello",
            Self::ServerOffer(_) => "ServerOffer",
            Self::ClientDecision(_) => "ClientDecision",
        })
    }
}

impl ControlPacket {
    fn validate(&self) -> Result<()> {
        match self {
            Self::ClientHello(hello) => {
                validate_protocol_version(hello.protocol_version)?;
                validate_terminal_text(
                    "client username",
                    &hello.metadata.username,
                    MAX_DISPLAY_LABEL_BYTES,
                    true,
                )
            }
            Self::ServerOffer(offer) => {
                validate_protocol_version(offer.protocol_version)?;
                validate_terminal_text(
                    "server offer operator name",
                    &offer.operator_name,
                    MAX_DISPLAY_LABEL_BYTES,
                    true,
                )?;
                if let OfferedSession::Vpn {
                    scope: VpnScope::Application { application },
                } = &offer.session
                {
                    validate_terminal_text(
                        "application VPN name",
                        application,
                        MAX_DISPLAY_LABEL_BYTES,
                        true,
                    )?;
                }
                Ok(())
            }
            Self::ClientDecision(decision) => {
                if decision.key_installed && !decision.session_allowed {
                    bail!("a denied client decision cannot report an installed operator key");
                }
                if let Some(note) = &decision.note {
                    validate_terminal_text(
                        "client decision note",
                        note,
                        MAX_DECISION_NOTE_BYTES,
                        true,
                    )?;
                }
                Ok(())
            }
        }
    }
}

fn validate_terminal_text(
    field: &str,
    value: &str,
    maximum_bytes: usize,
    must_not_be_blank: bool,
) -> Result<()> {
    if value.len() > maximum_bytes {
        bail!("{field} exceeds {maximum_bytes} UTF-8 bytes");
    }
    if must_not_be_blank && value.trim().is_empty() {
        bail!("{field} must not be blank");
    }
    if value.chars().any(is_unsafe_terminal_character) {
        bail!("{field} contains a terminal control or bidirectional formatting character");
    }
    Ok(())
}

fn is_unsafe_terminal_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

pub async fn send_packet<S>(
    websocket: &mut WebSocketStream<S>,
    packet: &ControlPacket,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    packet.validate().context("invalid control packet")?;
    let bytes: Vec<u8> =
        serde_json::to_vec(packet).context("failed to serialize control packet")?;
    websocket
        .send(Message::Binary(bytes.into()))
        .await
        .context("failed to send control packet")?;
    Ok(())
}

pub async fn recv_packet<S>(websocket: &mut WebSocketStream<S>) -> Result<ControlPacket>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let next_message = websocket
            .next()
            .await
            .ok_or_else(|| anyhow!("peer closed the websocket before completing the handshake"))?;
        match next_message.context("websocket read failed during handshake")? {
            Message::Binary(bytes) => {
                let packet: ControlPacket =
                    serde_json::from_slice(bytes.as_ref()).map_err(control_packet_decode_error)?;
                packet
                    .validate()
                    .context("received invalid control packet")?;
                return Ok(packet);
            }
            Message::Text(text) => {
                let packet: ControlPacket =
                    serde_json::from_str(text.as_ref()).map_err(control_packet_decode_error)?;
                packet
                    .validate()
                    .context("received invalid control packet")?;
                return Ok(packet);
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            Message::Close(frame) => {
                let Some(close_frame) = frame else {
                    bail!("peer closed the websocket without a reason");
                };
                let reason = close_frame.reason.as_ref();
                if validate_terminal_text(
                    "websocket close reason",
                    reason,
                    MAX_WEBSOCKET_CLOSE_REASON_BYTES,
                    false,
                )
                .is_err()
                {
                    bail!("peer closed the websocket with an unsafe reason");
                }
                bail!("peer closed the websocket: {reason}");
            }
        }
    }
}

fn control_packet_decode_error(error: serde_json::Error) -> anyhow::Error {
    anyhow!(
        "failed to decode control packet at line {} column {}",
        error.line(),
        error.column()
    )
}

fn validate_protocol_version(version: u32) -> Result<()> {
    if version != PROTOCOL_VERSION {
        bail!("protocol version mismatch: local={PROTOCOL_VERSION} remote={version}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ClientDecision, ClientHello, ClientMetadata, ControlPacket, MAX_DECISION_NOTE_BYTES,
        MAX_DISPLAY_LABEL_BYTES, OfferedSession, ServerOffer, VpnScope, recv_packet, send_packet,
    };
    use crate::PROTOCOL_VERSION;
    use crate::platform::Platform;
    use crate::vpn::SystemVpnPolicy;
    use futures_util::SinkExt;
    use tokio::io::{DuplexStream, duplex};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    async fn websocket_pair() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (left, right) = duplex(16 * 1024);
        tokio::join!(
            WebSocketStream::from_raw_socket(left, Role::Client, None),
            WebSocketStream::from_raw_socket(right, Role::Server, None),
        )
    }

    async fn round_trip(packet: &ControlPacket) -> ControlPacket {
        let (mut sender, mut receiver) = websocket_pair().await;
        let (send_result, receive_result) =
            tokio::join!(send_packet(&mut sender, packet), recv_packet(&mut receiver));
        send_result.unwrap();
        receive_result.unwrap()
    }

    fn application_offer(operator_name: &str, application: &str) -> ControlPacket {
        ControlPacket::ServerOffer(ServerOffer {
            protocol_version: PROTOCOL_VERSION,
            operator_name: operator_name.to_string(),
            session: OfferedSession::Vpn {
                scope: VpnScope::Application {
                    application: application.to_string(),
                },
            },
        })
    }

    #[test]
    fn system_vpn_offer_identifies_its_scope() {
        let packet = ControlPacket::ServerOffer(ServerOffer {
            protocol_version: PROTOCOL_VERSION,
            operator_name: "support".to_string(),
            session: OfferedSession::Vpn {
                scope: VpnScope::System {
                    policy: SystemVpnPolicy::default(),
                },
            },
        });

        let encoded = serde_json::to_value(packet).unwrap();

        assert_eq!(encoded["type"], "server_offer");
        assert_eq!(encoded["session"]["mode"], "vpn");
        assert_eq!(encoded["session"]["scope"]["kind"], "system");
        assert_eq!(
            encoded["session"]["scope"]["policy"]["include_cidrs"],
            serde_json::json!([])
        );
        assert_eq!(
            encoded["session"]["scope"]["policy"]["include_domains"],
            serde_json::json!([])
        );
    }

    #[test]
    fn application_vpn_offer_names_the_scoped_application() {
        let packet = ControlPacket::ServerOffer(ServerOffer {
            protocol_version: PROTOCOL_VERSION,
            operator_name: "support".to_string(),
            session: OfferedSession::Vpn {
                scope: VpnScope::Application {
                    application: "Firefox".to_string(),
                },
            },
        });

        let encoded = serde_json::to_value(packet).unwrap();

        assert_eq!(encoded["session"]["mode"], "vpn");
        assert_eq!(encoded["session"]["scope"]["kind"], "application");
        assert_eq!(encoded["session"]["scope"]["application"], "Firefox");
    }

    #[tokio::test]
    async fn legitimate_unicode_display_text_round_trips() {
        let hello = ControlPacket::ClientHello(ClientHello {
            protocol_version: PROTOCOL_VERSION,
            metadata: ClientMetadata {
                hostname: "workstation".to_string(),
                username: "工程師".to_string(),
                working_directory: "/workspace".to_string(),
                platform: Platform::current().unwrap(),
            },
        });
        let received_hello = round_trip(&hello).await;
        assert_eq!(
            serde_json::to_value(received_hello).unwrap(),
            serde_json::to_value(hello).unwrap()
        );

        let offer = application_offer("فريق الدعم", "Firefox 火狐");
        let received_offer = round_trip(&offer).await;
        assert_eq!(
            serde_json::to_value(received_offer).unwrap(),
            serde_json::to_value(offer).unwrap()
        );

        let decision = ControlPacket::ClientDecision(ClientDecision {
            session_allowed: false,
            key_installed: false,
            note: Some("用户已拒绝该会话。".to_string()),
        });
        let received_decision = round_trip(&decision).await;
        assert_eq!(
            serde_json::to_value(received_decision).unwrap(),
            serde_json::to_value(decision).unwrap()
        );
    }

    #[test]
    fn display_labels_must_be_nonblank_and_bounded() {
        let blank_operator = application_offer("\u{2003}\u{2003}", "Firefox");
        assert!(
            blank_operator
                .validate()
                .unwrap_err()
                .to_string()
                .contains("operator name must not be blank")
        );

        let blank_application = application_offer("support", " \t ");
        assert!(
            blank_application
                .validate()
                .unwrap_err()
                .to_string()
                .contains("application VPN name must not be blank")
        );

        let long_operator = "a".repeat(MAX_DISPLAY_LABEL_BYTES + 1);
        assert!(
            application_offer(&long_operator, "Firefox")
                .validate()
                .is_err()
        );

        let long_application = "火".repeat(MAX_DISPLAY_LABEL_BYTES / 3 + 1);
        assert!(
            application_offer("support", &long_application)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn terminal_controls_and_bidirectional_formatting_are_rejected() {
        for unsafe_character in ['\n', '\u{1b}', '\u{2028}', '\u{202e}', '\u{2066}'] {
            let operator = format!("support{unsafe_character}spoof");
            assert!(application_offer(&operator, "Firefox").validate().is_err());

            let application = format!("Fire{unsafe_character}fox");
            assert!(
                application_offer("support", &application)
                    .validate()
                    .is_err()
            );

            let decision = ControlPacket::ClientDecision(ClientDecision {
                session_allowed: false,
                key_installed: false,
                note: Some(format!("declined{unsafe_character}spoof")),
            });
            assert!(decision.validate().is_err());
        }
    }

    #[test]
    fn present_decision_notes_must_be_nonblank_and_bounded() {
        let blank = ControlPacket::ClientDecision(ClientDecision {
            session_allowed: false,
            key_installed: false,
            note: Some("  ".to_string()),
        });
        assert!(blank.validate().is_err());

        let long = ControlPacket::ClientDecision(ClientDecision {
            session_allowed: false,
            key_installed: false,
            note: Some("n".repeat(MAX_DECISION_NOTE_BYTES + 1)),
        });
        assert!(long.validate().is_err());
    }

    #[test]
    fn denied_decisions_cannot_report_an_installed_key() {
        let decision = ControlPacket::ClientDecision(ClientDecision {
            session_allowed: false,
            key_installed: true,
            note: Some("local user declined the support session".to_string()),
        });

        let error = decision.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("denied client decision cannot report an installed operator key")
        );
    }

    #[test]
    fn hello_and_offer_versions_are_validated_at_the_packet_boundary() {
        let hello = ControlPacket::ClientHello(ClientHello {
            protocol_version: PROTOCOL_VERSION + 1,
            metadata: ClientMetadata {
                hostname: "workstation".to_string(),
                username: "engineer".to_string(),
                working_directory: "/workspace".to_string(),
                platform: Platform::current().unwrap(),
            },
        });
        let offer = ControlPacket::ServerOffer(ServerOffer {
            protocol_version: PROTOCOL_VERSION + 1,
            operator_name: "support".to_string(),
            session: OfferedSession::Socks {},
        });

        for packet in [hello, offer] {
            assert!(
                packet
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("protocol version mismatch")
            );
        }
    }

    #[test]
    fn every_control_packet_layer_rejects_unknown_fields() {
        let cases = [
            (
                "control packet",
                serde_json::json!({
                    "type": "client_decision",
                    "session_allowed": true,
                    "key_installed": false,
                    "note": null,
                    "unexpected": true,
                }),
            ),
            (
                "client metadata",
                serde_json::json!({
                    "type": "client_hello",
                    "protocol_version": PROTOCOL_VERSION,
                    "metadata": {
                        "hostname": "workstation",
                        "username": "engineer",
                        "working_directory": "/workspace",
                        "platform": {
                            "operating_system": "linux",
                            "architecture": "x86_64",
                        },
                        "unexpected": true,
                    },
                }),
            ),
            (
                "platform",
                serde_json::json!({
                    "type": "client_hello",
                    "protocol_version": PROTOCOL_VERSION,
                    "metadata": {
                        "hostname": "workstation",
                        "username": "engineer",
                        "working_directory": "/workspace",
                        "platform": {
                            "operating_system": "linux",
                            "architecture": "x86_64",
                            "unexpected": true,
                        },
                    },
                }),
            ),
            (
                "offered session",
                serde_json::json!({
                    "type": "server_offer",
                    "protocol_version": PROTOCOL_VERSION,
                    "operator_name": "support",
                    "session": {
                        "mode": "socks",
                        "unexpected": true,
                    },
                }),
            ),
            (
                "VPN scope",
                serde_json::json!({
                    "type": "server_offer",
                    "protocol_version": PROTOCOL_VERSION,
                    "operator_name": "support",
                    "session": {
                        "mode": "vpn",
                        "scope": {
                            "kind": "application",
                            "application": "Firefox",
                            "unexpected": true,
                        },
                    },
                }),
            ),
            (
                "system VPN policy",
                serde_json::json!({
                    "type": "server_offer",
                    "protocol_version": PROTOCOL_VERSION,
                    "operator_name": "support",
                    "session": {
                        "mode": "vpn",
                        "scope": {
                            "kind": "system",
                            "policy": {
                                "include_cidrs": [],
                                "include_domains": [],
                                "unexpected": true,
                            },
                        },
                    },
                }),
            ),
        ];

        for (layer, encoded) in cases {
            assert!(
                serde_json::from_value::<ControlPacket>(encoded).is_err(),
                "{layer} accepted an unknown field"
            );
        }
    }

    #[test]
    fn displayed_client_username_must_be_nonblank_bounded_and_terminal_safe() {
        for username in [
            " ".to_string(),
            "user\nspoof".to_string(),
            "user\u{202e}spoof".to_string(),
            "u".repeat(MAX_DISPLAY_LABEL_BYTES + 1),
        ] {
            let packet = ControlPacket::ClientHello(ClientHello {
                protocol_version: PROTOCOL_VERSION,
                metadata: ClientMetadata {
                    hostname: "workstation".to_string(),
                    username,
                    working_directory: "/workspace".to_string(),
                    platform: Platform::current().unwrap(),
                },
            });
            assert!(packet.validate().is_err());
        }
    }

    #[tokio::test]
    async fn send_packet_rejects_invalid_display_text_before_writing() {
        let (mut sender, _receiver) = websocket_pair().await;
        let packet = application_offer("support\u{202e}hidden", "Firefox");

        let error = send_packet(&mut sender, &packet).await.unwrap_err();

        assert!(error.to_string().contains("invalid control packet"));
    }

    #[tokio::test]
    async fn recv_packet_rejects_invalid_display_text_before_returning_it() {
        let (mut sender, mut receiver) = websocket_pair().await;
        let encoded = serde_json::json!({
            "type": "server_offer",
            "protocol_version": PROTOCOL_VERSION,
            "operator_name": "support\u{001b}[2J",
            "session": { "mode": "socks" },
        })
        .to_string();
        sender.send(Message::Text(encoded.into())).await.unwrap();

        let error = recv_packet(&mut receiver).await.unwrap_err();

        assert!(
            format!("{error:#}").contains("server offer operator name contains a terminal control")
        );
    }

    #[tokio::test]
    async fn decode_errors_do_not_echo_attacker_controlled_values() {
        let (mut sender, mut receiver) = websocket_pair().await;
        let attacker_value = "\u{001b}[2Jattacker";
        let encoded = serde_json::json!({ "type": attacker_value }).to_string();
        sender.send(Message::Text(encoded.into())).await.unwrap();

        let error = recv_packet(&mut receiver).await.unwrap_err();
        let displayed = format!("{error:#}");

        assert!(displayed.contains("failed to decode control packet at line 1 column"));
        assert!(!displayed.contains(attacker_value));
    }

    #[test]
    fn control_packet_debug_output_does_not_render_unvalidated_metadata() {
        let attacker_value = "workstation\u{202e}hidden";
        let packet = ControlPacket::ClientHello(ClientHello {
            protocol_version: PROTOCOL_VERSION,
            metadata: ClientMetadata {
                hostname: attacker_value.to_string(),
                username: "engineer".to_string(),
                working_directory: "/workspace".to_string(),
                platform: Platform::current().unwrap(),
            },
        });

        let displayed = format!("{packet:?}");

        assert_eq!(displayed, "ClientHello");
        assert!(!displayed.contains(attacker_value));
    }

    #[tokio::test]
    async fn unsafe_websocket_close_reasons_are_not_echoed() {
        let (mut sender, mut receiver) = websocket_pair().await;
        let unsafe_reason = "closing\u{001b}[2Jspoof";
        sender
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: unsafe_reason.into(),
            })))
            .await
            .unwrap();

        let error = recv_packet(&mut receiver).await.unwrap_err();
        let displayed = format!("{error:#}");

        assert!(displayed.contains("peer closed the websocket with an unsafe reason"));
        assert!(!displayed.contains(unsafe_reason));
    }
}
