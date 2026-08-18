use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use anyhow::anyhow;
#[cfg(target_os = "macos")]
use anyhow::bail;
use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun::AbstractDevice;
#[cfg(target_os = "windows")]
use wintun_security::VerifiedWintun;

use super::configuration::VpnNetworkConfiguration;

pub(super) struct SystemTun {
    device: Option<tun::AsyncDevice>,
    pub(super) name: String,
    pub(super) index: i32,
    #[cfg(target_os = "windows")]
    _verified_wintun: VerifiedWintun,
}

pub(super) struct RawIpReader<R> {
    inner: R,
}

pub(super) struct RawIpWriter<W> {
    inner: W,
}

impl SystemTun {
    pub(super) fn create(network: VpnNetworkConfiguration) -> Result<Self> {
        let mut configuration = tun::Configuration::default();
        configuration
            .address(network.interface_ipv4)
            .destination(network.gateway_ipv4)
            .netmask(network.point_to_point_ipv4.netmask())
            .mtu(super::VPN_MTU)
            .up();

        #[cfg(target_os = "macos")]
        configuration.platform_config(|platform| {
            // A kernel-control utun always carries a four-byte address-family
            // header. `tun` removes and restores it when this is enabled, so
            // the rest of SSHPortal sees the same raw-IP contract on every OS.
            platform.packet_information(true);
        });

        #[cfg(target_os = "windows")]
        let verified_wintun = {
            configuration.tun_name("sshportal");
            let bundled_wintun = wintun_path()?;
            let verified_wintun = VerifiedWintun::prepare(&bundled_wintun)
                .context("failed to stage and verify the bundled Wintun DLL")?;
            configuration.platform_config(|platform| {
                platform.device_guid(0x8973_6870_6f72_7461_6c00_0000_0000_0001);
                platform.wintun_file(verified_wintun.path());
            });
            verified_wintun
        };

        let device = tun::create_as_async(&configuration).context("TUN device creation failed")?;
        validate_platform_contract(&device)?;
        let name = device
            .tun_name()
            .context("failed to read TUN interface name")?;
        let index = device
            .tun_index()
            .context("failed to read TUN interface index")?;
        Ok(Self {
            device: Some(device),
            name,
            index,
            #[cfg(target_os = "windows")]
            _verified_wintun: verified_wintun,
        })
    }

    pub(super) fn split(
        &mut self,
    ) -> Result<(
        RawIpReader<tun::DeviceReader>,
        RawIpWriter<tun::DeviceWriter>,
    )> {
        let device = self
            .device
            .take()
            .context("VPN interface has already been split")?;
        let (writer, reader) = device
            .split()
            .context("failed to split the VPN interface for asynchronous I/O")?;
        Ok((RawIpReader::new(reader), RawIpWriter::new(writer)))
    }
}

impl<R> RawIpReader<R> {
    fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<W> RawIpWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for RawIpReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let initial_length = output.filled().len();
        match Pin::new(&mut self.inner).poll_read(context, output) {
            Poll::Ready(Ok(())) => {
                let packet = &output.filled()[initial_length..];
                if packet.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(validate_raw_ip_packet(packet))
            }
            result => result,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for RawIpWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        packet: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = validate_raw_ip_packet(packet) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(context, packet)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn validate_raw_ip_packet(packet: &[u8]) -> io::Result<()> {
    let Some(first_byte) = packet.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TUN delivered an empty packet",
        ));
    };
    if matches!(first_byte >> 4, 4 | 6) {
        return Ok(());
    }
    if packet.len() >= 4 {
        let family = u32::from_be_bytes(packet[..4].try_into().expect("four-byte prefix"));
        if family == 2 || family == 30 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TUN packet-information header crossed the normalized raw-IP boundary",
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "TUN delivered an unsupported IP version {}",
            first_byte >> 4
        ),
    ))
}

#[cfg(target_os = "macos")]
fn validate_platform_contract(device: &tun::AsyncDevice) -> Result<()> {
    if !device.packet_information() {
        bail!(
            "macOS utun packet-information normalization is disabled; refusing to start with an incompatible packet boundary"
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn validate_platform_contract(_device: &tun::AsyncDevice) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn wintun_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("failed to locate sshportal-server.exe")?;
    let directory = executable
        .parent()
        .context("sshportal-server.exe has no parent directory")?;
    let path = directory.join("wintun.dll");
    if !path.is_file() {
        return Err(anyhow!(
            "{} is missing; place the signed Wintun DLL beside sshportal-server.exe",
            path.display()
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{RawIpReader, RawIpWriter, validate_raw_ip_packet};

    #[test]
    fn raw_ip_contract_accepts_ipv4_and_ipv6() {
        validate_raw_ip_packet(&[0x45, 0, 0, 20]).unwrap();
        validate_raw_ip_packet(&[0x60, 0, 0, 0]).unwrap();
    }

    #[test]
    fn raw_ip_contract_identifies_darwin_family_headers() {
        for family in [2_u32, 30] {
            let mut packet = family.to_be_bytes().to_vec();
            packet.extend_from_slice(&[0x45, 0, 0, 20]);
            let error = validate_raw_ip_packet(&packet).unwrap_err();

            assert!(error.to_string().contains("packet-information header"));
        }
    }

    #[test]
    fn raw_ip_contract_rejects_empty_and_unknown_packets() {
        assert!(validate_raw_ip_packet(&[]).is_err());
        assert!(validate_raw_ip_packet(&[0x70, 0, 0, 0]).is_err());
    }

    #[tokio::test]
    async fn reader_rejects_a_leaked_platform_header() {
        let (mut source, destination) = tokio::io::duplex(64);
        let mut reader = RawIpReader::new(destination);
        source
            .write_all(&[0, 0, 0, 2, 0x45, 0, 0, 20])
            .await
            .unwrap();
        let mut packet = [0_u8; 64];

        let error = reader.read(&mut packet).await.unwrap_err();

        assert!(error.to_string().contains("packet-information header"));
    }

    #[tokio::test]
    async fn writer_enforces_and_preserves_the_raw_ip_contract() {
        let (destination, mut sink) = tokio::io::duplex(64);
        let mut writer = RawIpWriter::new(destination);
        let packet = [0x45, 0, 0, 20];

        writer.write_all(&packet).await.unwrap();
        let mut received = [0_u8; 4];
        sink.read_exact(&mut received).await.unwrap();
        assert_eq!(received, packet);

        assert!(writer.write_all(&[0, 0, 0, 2]).await.is_err());
    }
}
