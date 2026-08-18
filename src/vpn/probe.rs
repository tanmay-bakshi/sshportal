use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::UdpSocket;

use super::configuration::VpnNetworkConfiguration;
use super::policy::SystemVpnPolicy;

const DNS_HEADER_BYTES: usize = 12;
const DNS_TYPE_A: u16 = 1;
const DNS_CLASS_INTERNET: u16 = 1;
const DNS_RESPONSE: u16 = 0x8000;
const DNS_OPCODE: u16 = 0x7800;
const DNS_RESPONSE_CODE: u16 = 0x000f;
const HEALTH_PAYLOAD_BYTES: usize = 32;
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const FULL_TUNNEL_PROBE_NAME: &str = "sshportal-health-check.invalid";

pub(super) async fn verify_data_plane(
    network: VpnNetworkConfiguration,
    policy: &SystemVpnPolicy,
) -> Result<()> {
    verify_tun_round_trip(IpAddr::V4(network.gateway_ipv4)).await?;
    if policy.requires_ipv6_tunnel() {
        verify_tun_round_trip(IpAddr::V6(network.gateway_ipv6)).await?;
    }
    let Some(synthetic) = network.synthetic else {
        return Ok(());
    };
    let name = policy
        .include_domains()
        .first()
        .map(String::as_str)
        .unwrap_or(FULL_TUNNEL_PROBE_NAME);
    verify_udp_dns(synthetic.ipv4_dns, name).await
}

async fn verify_tun_round_trip(server: IpAddr) -> Result<()> {
    let bind_address = match server {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let destination = SocketAddr::new(server, super::DATA_PLANE_HEALTH_PORT);
    let socket = UdpSocket::bind(bind_address)
        .await
        .with_context(|| format!("failed to bind the {server} VPN health probe"))?;
    socket
        .connect(destination)
        .await
        .with_context(|| format!("failed to connect the VPN health probe to {destination}"))?;
    let mut payload = [0_u8; HEALTH_PAYLOAD_BYTES];
    rand::fill(&mut payload);
    socket
        .send(&payload)
        .await
        .with_context(|| format!("failed to send the VPN health probe to {destination}"))?;
    let mut response = [0_u8; HEALTH_PAYLOAD_BYTES + 1];
    let size = tokio::time::timeout(HEALTH_PROBE_TIMEOUT, socket.recv(&mut response))
        .await
        .with_context(|| format!("VPN health probe to {destination} timed out"))?
        .with_context(|| format!("failed to receive the VPN health response from {destination}"))?;
    if response[..size] != payload {
        bail!("VPN health response from {destination} did not preserve its probe payload");
    }
    Ok(())
}

async fn verify_udp_dns(server: Ipv4Addr, name: &str) -> Result<()> {
    let transaction_id = rand::random();
    let query = encode_query(transaction_id, name)?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("failed to bind the VPN readiness probe")?;
    let destination = SocketAddr::from((server, 53));
    socket
        .connect(destination)
        .await
        .with_context(|| format!("failed to connect the VPN readiness probe to {destination}"))?;
    socket
        .send(&query)
        .await
        .context("failed to send the VPN readiness DNS query")?;
    let mut response = [0_u8; 1_232];
    let size = tokio::time::timeout(PROBE_TIMEOUT, socket.recv(&mut response))
        .await
        .context("VPN data-plane readiness probe timed out")?
        .context("failed to receive the VPN readiness DNS response")?;
    validate_response(&response[..size], &query)
        .context("VPN data-plane readiness probe received an invalid DNS response")
}

fn encode_query(transaction_id: u16, name: &str) -> Result<Vec<u8>> {
    if name.len() > 253 {
        bail!("DNS probe name exceeds 253 bytes");
    }
    let mut query = Vec::with_capacity(DNS_HEADER_BYTES + name.len() + 6);
    query.extend_from_slice(&transaction_id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in name.split('.') {
        let label_length = u8::try_from(label.len()).context("DNS probe label is too long")?;
        if label_length == 0 || label_length > 63 {
            bail!("DNS probe name contains an invalid label");
        }
        query.push(label_length);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    query.extend_from_slice(&DNS_CLASS_INTERNET.to_be_bytes());
    Ok(query)
}

fn validate_response(response: &[u8], query: &[u8]) -> Result<()> {
    if query.len() < DNS_HEADER_BYTES {
        bail!("DNS readiness query is shorter than its header");
    }
    if response.len() < DNS_HEADER_BYTES {
        bail!("DNS response is shorter than its header");
    }
    let response_id = u16::from_be_bytes([response[0], response[1]]);
    let transaction_id = u16::from_be_bytes([query[0], query[1]]);
    if response_id != transaction_id {
        bail!("DNS response transaction ID does not match the readiness query");
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & DNS_RESPONSE == 0 {
        bail!("DNS readiness response is marked as a query");
    }
    if flags & DNS_OPCODE != 0 {
        bail!("DNS readiness response has a non-standard opcode");
    }
    if flags & DNS_RESPONSE_CODE != 0 {
        bail!(
            "DNS readiness response returned failure code {}",
            flags & DNS_RESPONSE_CODE
        );
    }
    if u16::from_be_bytes([response[4], response[5]]) != 1 {
        bail!("DNS readiness response does not contain exactly one question");
    }
    let question = &query[DNS_HEADER_BYTES..];
    if response.len() < DNS_HEADER_BYTES + question.len()
        || response[DNS_HEADER_BYTES..DNS_HEADER_BYTES + question.len()] != *question
    {
        bail!("DNS readiness response does not repeat the readiness question");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DNS_HEADER_BYTES, encode_query, validate_response};

    #[test]
    fn query_encoder_preserves_labels_and_record_type() {
        let query = encode_query(0x1234, "jira.elevancehealth.com").unwrap();

        assert_eq!(
            &query[..DNS_HEADER_BYTES],
            &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert!(query.ends_with(&[0, 0, 1, 0, 1]));
    }

    #[test]
    fn response_validator_requires_a_successful_matching_response() {
        let query = encode_query(0x1234, "localhost").unwrap();
        let mut response = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        response.extend_from_slice(&query[DNS_HEADER_BYTES..]);

        validate_response(&response, &query).unwrap();
        let mismatched_query = encode_query(0x4321, "localhost").unwrap();
        assert!(validate_response(&response, &mismatched_query).is_err());

        let mut failure = response.clone();
        failure[3] = 0x82;
        assert!(validate_response(&failure, &query).is_err());

        let different_question = encode_query(0x1234, "different.invalid").unwrap();
        assert!(validate_response(&response, &different_question).is_err());
    }

    #[test]
    fn query_encoder_rejects_invalid_labels() {
        assert!(encode_query(1, "bad..example").is_err());
        assert!(encode_query(1, &format!("{}.example", "a".repeat(64))).is_err());
        assert!(encode_query(1, &format!("{}.example", "a".repeat(254))).is_err());
    }
}
