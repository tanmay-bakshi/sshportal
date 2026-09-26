use std::collections::VecDeque;

use bytes::Bytes;
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QueueError {
    Full,
    PacketTooLarge,
}

#[derive(Debug)]
struct PacketQueue {
    packets: VecDeque<Bytes>,
    bytes: usize,
    max_packets: usize,
    max_bytes: usize,
}

impl PacketQueue {
    fn new(max_packets: usize, max_bytes: usize) -> Self {
        Self {
            packets: VecDeque::with_capacity(max_packets),
            bytes: 0,
            max_packets,
            max_bytes,
        }
    }

    fn can_push(&self, packet_count: usize, byte_count: usize) -> bool {
        self.packets.len().saturating_add(packet_count) <= self.max_packets
            && self.bytes.saturating_add(byte_count) <= self.max_bytes
    }

    fn push(&mut self, packet: Bytes) -> Result<(), QueueError> {
        if !self.can_push(1, packet.len()) {
            return Err(QueueError::Full);
        }
        self.bytes += packet.len();
        self.packets.push_back(packet);
        Ok(())
    }

    fn push_front(&mut self, packet: Bytes) -> Result<(), QueueError> {
        if !self.can_push(1, packet.len()) {
            return Err(QueueError::Full);
        }
        self.bytes += packet.len();
        self.packets.push_front(packet);
        Ok(())
    }

    fn push_batch(&mut self, packets: Vec<Bytes>) -> Result<(), QueueError> {
        let byte_count = packets.iter().try_fold(0_usize, |total, packet| {
            total.checked_add(packet.len()).ok_or(QueueError::Full)
        })?;
        if !self.can_push(packets.len(), byte_count) {
            return Err(QueueError::Full);
        }
        self.bytes += byte_count;
        self.packets.extend(packets);
        Ok(())
    }

    fn pop(&mut self) -> Option<Bytes> {
        let packet = self.packets.pop_front()?;
        self.bytes -= packet.len();
        Some(packet)
    }
}

/// A deterministic, byte-bounded smoltcp device.
///
/// The live TUN adapter feeds and drains this device from its own actor. smoltcp
/// never owns the operating-system handle and cannot create hidden queues.
pub(super) struct QueueDevice {
    ingress: PacketQueue,
    egress: PacketQueue,
    mtu: usize,
    max_ingress_packet_bytes: usize,
}

impl QueueDevice {
    pub(super) fn new(
        mtu: usize,
        max_ingress_packets: usize,
        max_ingress_bytes: usize,
        max_egress_packets: usize,
        max_egress_bytes: usize,
        max_ingress_packet_bytes: usize,
    ) -> Self {
        Self {
            ingress: PacketQueue::new(max_ingress_packets, max_ingress_bytes),
            egress: PacketQueue::new(max_egress_packets, max_egress_bytes),
            mtu,
            max_ingress_packet_bytes,
        }
    }

    pub(super) fn push_ingress(&mut self, packet: Bytes) -> Result<(), (QueueError, Bytes)> {
        if packet.len() > self.max_ingress_packet_bytes {
            return Err((QueueError::PacketTooLarge, packet));
        }
        if !self.ingress.can_push(1, packet.len()) {
            return Err((QueueError::Full, packet));
        }
        self.ingress
            .push(packet)
            .expect("preflighted ingress packet must fit");
        Ok(())
    }

    pub(super) fn push_ingress_front(&mut self, packet: Bytes) -> Result<(), (QueueError, Bytes)> {
        if packet.len() > self.max_ingress_packet_bytes {
            return Err((QueueError::PacketTooLarge, packet));
        }
        if !self.ingress.can_push(1, packet.len()) {
            return Err((QueueError::Full, packet));
        }
        self.ingress
            .push_front(packet)
            .expect("preflighted ingress packet must fit");
        Ok(())
    }

    pub(super) fn push_egress_batch(&mut self, packets: Vec<Bytes>) -> Result<(), QueueError> {
        if packets.iter().any(|packet| packet.len() > self.mtu) {
            return Err(QueueError::PacketTooLarge);
        }
        if !self.can_push_egress_batch(&packets) {
            return Err(QueueError::Full);
        }
        self.egress.push_batch(packets)
    }

    pub(super) fn can_push_egress_batch(&self, packets: &[Bytes]) -> bool {
        if packets.iter().any(|packet| packet.len() > self.mtu) {
            return false;
        }
        let Some(byte_count) = packets
            .iter()
            .try_fold(0_usize, |total, packet| total.checked_add(packet.len()))
        else {
            return false;
        };
        self.egress.can_push(packets.len(), byte_count)
    }

    pub(super) fn pop_egress(&mut self) -> Option<Bytes> {
        self.egress.pop()
    }

    pub(super) fn pop_ingress(&mut self) -> Option<Bytes> {
        // Receiving can produce an immediate response. Engine inspection and
        // smoltcp share the same requirement for one MTU-sized egress slot.
        if !self.egress.can_push(1, self.mtu) {
            return None;
        }
        self.ingress.pop()
    }
}

pub(super) struct QueueRxToken {
    packet: Bytes,
}

impl RxToken for QueueRxToken {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(&self.packet)
    }
}

pub(super) struct QueueTxToken<'a> {
    egress: &'a mut PacketQueue,
    mtu: usize,
}

impl TxToken for QueueTxToken<'_> {
    fn consume<R, F>(self, length: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(
            length <= self.mtu,
            "smoltcp emitted a packet larger than the configured MTU"
        );
        let mut packet = vec![0_u8; length];
        let result = function(&mut packet);
        let push_result = self.egress.push(Bytes::from(packet));
        assert!(
            push_result.is_ok(),
            "smoltcp transmitted after its bounded device reported backpressure"
        );
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = QueueRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.pop_ingress()?;
        Some((
            QueueRxToken { packet },
            QueueTxToken {
                egress: &mut self.egress,
                mtu: self.mtu,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if !self.egress.can_push(1, self.mtu) {
            return None;
        }
        Some(QueueTxToken {
            egress: &mut self.egress,
            mtu: self.mtu,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use smoltcp::phy::{Device, RxToken, TxToken};
    use smoltcp::time::Instant;

    use super::{QueueDevice, QueueError};

    #[test]
    fn ingress_and_egress_are_bounded_by_packets_and_bytes() {
        let mut device = QueueDevice::new(1280, 2, 8, 2, 2560, 8);

        assert_eq!(device.push_ingress(Bytes::from_static(b"1234")), Ok(()));
        assert_eq!(device.push_ingress(Bytes::from_static(b"5678")), Ok(()));
        assert_eq!(
            device.push_ingress(Bytes::from_static(b"x")),
            Err((QueueError::Full, Bytes::from_static(b"x")))
        );
        assert_eq!(
            device.push_ingress(Bytes::from_static(b"123456789")),
            Err((QueueError::PacketTooLarge, Bytes::from_static(b"123456789")))
        );

        let token = device.transmit(Instant::ZERO).unwrap();
        token.consume(16, |packet| packet.copy_from_slice(&[7_u8; 16]));
        assert_eq!(device.pop_egress().unwrap(), Bytes::from(vec![7_u8; 16]));
    }

    #[test]
    fn owned_ingress_and_smoltcp_share_backpressure_and_accounting() {
        for (egress_packets, egress_bytes) in [(1, 16), (2, 8)] {
            let mut device = QueueDevice::new(8, 3, 8, egress_packets, egress_bytes, 8);
            let first = Bytes::from(vec![1_u8; 4]);
            let first_pointer = first.as_ptr();
            device.push_ingress(first).unwrap();
            device.push_ingress(Bytes::from_static(b"next")).unwrap();
            device
                .push_egress_batch(vec![Bytes::from_static(b"x")])
                .unwrap();

            assert!(device.pop_ingress().is_none());
            assert!(device.receive(Instant::ZERO).is_none());
            assert_eq!(
                device.push_ingress(Bytes::from_static(b"!")),
                Err((QueueError::Full, Bytes::from_static(b"!")))
            );

            assert_eq!(device.pop_egress().unwrap(), b"x".as_slice());
            let packet = device.pop_ingress().unwrap();
            assert_eq!(packet.as_ptr(), first_pointer);
            assert_eq!(packet, [1_u8; 4].as_slice());
            device.push_ingress(Bytes::from_static(b"last")).unwrap();

            let (received, _) = device.receive(Instant::ZERO).unwrap();
            received.consume(|packet| assert_eq!(packet, b"next"));
            device
                .push_ingress_front(Bytes::from_static(b"head"))
                .unwrap();
            assert_eq!(device.pop_ingress().unwrap(), b"head".as_slice());
            let (received, _) = device.receive(Instant::ZERO).unwrap();
            received.consume(|packet| assert_eq!(packet, b"last"));
            assert!(device.pop_ingress().is_none());
            device
                .push_ingress(Bytes::from_static(b"12345678"))
                .unwrap();
        }
    }

    #[test]
    fn egress_batch_is_atomic() {
        let mut device = QueueDevice::new(1280, 1, 1280, 2, 20, 1280);
        let rejected = vec![
            Bytes::from_static(b"1234567890"),
            Bytes::from_static(b"abcdefghijk"),
        ];

        assert_eq!(device.push_egress_batch(rejected), Err(QueueError::Full));
        assert!(device.pop_egress().is_none());
    }
}
