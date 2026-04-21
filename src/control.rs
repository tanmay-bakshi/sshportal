use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

use crate::PROTOCOL_VERSION;
use crate::platform::Platform;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientMetadata {
    pub hostname: String,
    pub username: String,
    pub working_directory: String,
    pub preferred_shell: String,
    pub platform: Platform,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientHello {
    pub protocol_version: u32,
    pub metadata: ClientMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerOffer {
    pub protocol_version: u32,
    pub operator_name: String,
    pub ssh_public_key: String,
    pub persist_key_requested: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientDecision {
    pub session_allowed: bool,
    pub key_installed: bool,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlPacket {
    ClientHello(ClientHello),
    ServerOffer(ServerOffer),
    ClientDecision(ClientDecision),
}

pub async fn send_packet<S>(
    websocket: &mut WebSocketStream<S>,
    packet: &ControlPacket,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
                let packet: ControlPacket = serde_json::from_slice(bytes.as_ref())
                    .context("failed to decode control packet")?;
                return Ok(packet);
            }
            Message::Text(text) => {
                let packet: ControlPacket = serde_json::from_str(text.as_ref())
                    .context("failed to decode text control packet")?;
                return Ok(packet);
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            Message::Close(frame) => {
                let reason: String = frame
                    .map(|close_frame| close_frame.reason.to_string())
                    .unwrap_or_else(|| "no close reason supplied".to_string());
                bail!("peer closed the websocket: {reason}");
            }
        }
    }
}

pub fn validate_protocol_version(version: u32) -> Result<()> {
    if version != PROTOCOL_VERSION {
        bail!("protocol version mismatch: local={PROTOCOL_VERSION} remote={version}");
    }
    Ok(())
}
