use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;

use super::ip::{FragmentKey, FragmentTemplate, IpFragment, ParseError, rebuild_fragmented_packet};

#[derive(Clone, Copy, Debug)]
pub(crate) struct FragmentLimits {
    pub(super) max_datagrams: usize,
    pub(super) max_fragments_per_datagram: usize,
    pub(super) max_buffered_bytes: usize,
    pub(super) max_unfragmentable_header_bytes: usize,
    pub(super) timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FragmentDropReason {
    Capacity,
    ConflictingFinalLength,
    MissingFirstHeader,
    Overlap,
    TooManyFragments,
    TooLarge,
}

#[derive(Debug)]
pub(super) enum ReassemblyResult {
    Pending,
    Complete(Bytes),
    Dropped(FragmentDropReason),
}

#[derive(Debug)]
struct FragmentPiece {
    offset: usize,
    data: Bytes,
}

impl FragmentPiece {
    fn end(&self) -> usize {
        self.offset + self.data.len()
    }
}

#[derive(Debug)]
enum AssemblyState {
    Collecting {
        pieces: Vec<FragmentPiece>,
        template: Option<FragmentTemplate>,
        protocol: Option<u8>,
        total_size: Option<usize>,
        accounted_bytes: usize,
    },
    Rejected,
}

#[derive(Debug)]
struct Assembly {
    expires_at: Duration,
    state: AssemblyState,
}

/// Strict, memory-bounded IP fragment reassembly.
///
/// Any overlap poisons the complete fragment identity until expiry. This avoids
/// choosing between conflicting bytes and prevents a later fragment subset from
/// resurrecting an ambiguous datagram.
pub(super) struct FragmentReassembler {
    limits: FragmentLimits,
    assemblies: HashMap<FragmentKey, Assembly>,
    buffered_bytes: usize,
}

impl FragmentReassembler {
    pub(super) fn new(limits: FragmentLimits) -> Self {
        Self {
            limits,
            assemblies: HashMap::with_capacity(limits.max_datagrams),
            buffered_bytes: 0,
        }
    }

    pub(super) fn ingest(&mut self, now: Duration, fragment: IpFragment) -> ReassemblyResult {
        self.expire(now);
        if !self.assemblies.contains_key(&fragment.key) {
            if self.assemblies.len() >= self.limits.max_datagrams {
                return ReassemblyResult::Dropped(FragmentDropReason::Capacity);
            }
            self.assemblies.insert(
                fragment.key.clone(),
                Assembly {
                    expires_at: now.saturating_add(self.limits.timeout),
                    state: AssemblyState::Collecting {
                        pieces: Vec::new(),
                        template: None,
                        protocol: None,
                        total_size: None,
                        accounted_bytes: 0,
                    },
                },
            );
        }

        let key = fragment.key.clone();
        let result = self.add_fragment(&key, fragment);
        match result {
            AddResult::Pending => ReassemblyResult::Pending,
            AddResult::Reject(reason) => {
                if reason == FragmentDropReason::Capacity {
                    self.remove(&key);
                } else {
                    self.reject(&key);
                }
                ReassemblyResult::Dropped(reason)
            }
            AddResult::Complete => self.complete(&key),
        }
    }

    pub(super) fn expire(&mut self, now: Duration) {
        let expired: Vec<_> = self
            .assemblies
            .iter()
            .filter_map(|(key, assembly)| (assembly.expires_at <= now).then_some(key.clone()))
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }

    pub(super) fn next_expiry(&self) -> Option<Duration> {
        self.assemblies
            .values()
            .map(|assembly| assembly.expires_at)
            .min()
    }

    #[cfg(test)]
    pub(super) fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    fn add_fragment(&mut self, key: &FragmentKey, fragment: IpFragment) -> AddResult {
        let assembly = self
            .assemblies
            .get_mut(key)
            .expect("fragment assembly must exist before insertion");
        let AssemblyState::Collecting {
            pieces,
            template,
            protocol,
            total_size,
            accounted_bytes,
        } = &mut assembly.state
        else {
            return AddResult::Pending;
        };

        if let Some(known_protocol) = *protocol {
            if known_protocol != fragment.protocol {
                return AddResult::Reject(FragmentDropReason::Overlap);
            }
        } else {
            *protocol = Some(fragment.protocol);
        }
        if fragment
            .template
            .as_ref()
            .is_some_and(|template| fragment_template_protocol(template) != Some(fragment.protocol))
        {
            return AddResult::Reject(FragmentDropReason::Overlap);
        }
        if pieces.len() >= self.limits.max_fragments_per_datagram {
            return AddResult::Reject(FragmentDropReason::TooManyFragments);
        }
        let end = match fragment.offset.checked_add(fragment.data.len()) {
            Some(end) => end,
            None => return AddResult::Reject(FragmentDropReason::TooLarge),
        };
        if pieces
            .iter()
            .any(|piece| fragment.offset < piece.end() && piece.offset < end)
        {
            return AddResult::Reject(FragmentDropReason::Overlap);
        }
        if let Some(known_total) = *total_size
            && end > known_total
        {
            return AddResult::Reject(FragmentDropReason::ConflictingFinalLength);
        }
        if !fragment.more {
            if let Some(known_total) = *total_size
                && known_total != end
            {
                return AddResult::Reject(FragmentDropReason::ConflictingFinalLength);
            }
            *total_size = Some(end);
        }

        let header_bytes = fragment
            .template
            .as_ref()
            .map(fragment_template_bytes)
            .unwrap_or(0);
        if header_bytes > self.limits.max_unfragmentable_header_bytes {
            return AddResult::Reject(FragmentDropReason::TooLarge);
        }
        let additional_bytes = fragment.data.len().saturating_add(header_bytes);
        if self.buffered_bytes.saturating_add(additional_bytes) > self.limits.max_buffered_bytes {
            return AddResult::Reject(FragmentDropReason::Capacity);
        }
        if let Some(fragment_template) = fragment.template {
            if template.is_some() {
                return AddResult::Reject(FragmentDropReason::Overlap);
            }
            *template = Some(fragment_template);
        }

        self.buffered_bytes += additional_bytes;
        *accounted_bytes += additional_bytes;
        pieces.push(FragmentPiece {
            offset: fragment.offset,
            data: fragment.data,
        });
        pieces.sort_unstable_by_key(|piece| piece.offset);

        let Some(total_size) = *total_size else {
            return AddResult::Pending;
        };
        if template.is_none() {
            return AddResult::Pending;
        }
        let mut covered = 0_usize;
        for piece in pieces {
            if piece.offset != covered {
                return AddResult::Pending;
            }
            covered = piece.end();
        }
        if covered == total_size {
            AddResult::Complete
        } else {
            AddResult::Pending
        }
    }

    fn complete(&mut self, key: &FragmentKey) -> ReassemblyResult {
        let Some(assembly) = self.assemblies.remove(key) else {
            return ReassemblyResult::Dropped(FragmentDropReason::Capacity);
        };
        let AssemblyState::Collecting {
            pieces,
            template,
            protocol: _,
            total_size,
            accounted_bytes,
        } = assembly.state
        else {
            return ReassemblyResult::Dropped(FragmentDropReason::Overlap);
        };
        self.buffered_bytes -= accounted_bytes;
        let Some(template) = template else {
            return ReassemblyResult::Dropped(FragmentDropReason::MissingFirstHeader);
        };
        let Some(total_size) = total_size else {
            return ReassemblyResult::Pending;
        };
        let mut payload = Vec::with_capacity(total_size);
        for piece in pieces {
            payload.extend_from_slice(&piece.data);
        }
        match rebuild_fragmented_packet(template, &payload) {
            Ok(packet) => ReassemblyResult::Complete(packet),
            Err(
                ParseError::Malformed
                | ParseError::InvalidChecksum
                | ParseError::UnsupportedExtension,
            ) => ReassemblyResult::Dropped(FragmentDropReason::TooLarge),
        }
    }

    fn reject(&mut self, key: &FragmentKey) {
        let Some(assembly) = self.assemblies.get_mut(key) else {
            return;
        };
        if let AssemblyState::Collecting {
            accounted_bytes, ..
        } = &assembly.state
        {
            self.buffered_bytes -= *accounted_bytes;
        }
        assembly.state = AssemblyState::Rejected;
    }

    fn remove(&mut self, key: &FragmentKey) {
        let Some(assembly) = self.assemblies.remove(key) else {
            return;
        };
        if let AssemblyState::Collecting {
            accounted_bytes, ..
        } = assembly.state
        {
            self.buffered_bytes -= accounted_bytes;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddResult {
    Pending,
    Complete,
    Reject(FragmentDropReason),
}

fn fragment_template_bytes(template: &FragmentTemplate) -> usize {
    match template {
        FragmentTemplate::Ipv4(header) => header.len(),
        FragmentTemplate::Ipv6 { header, .. } => header.len(),
    }
}

fn fragment_template_protocol(template: &FragmentTemplate) -> Option<u8> {
    match template {
        FragmentTemplate::Ipv4(header) => header.get(9).copied(),
        FragmentTemplate::Ipv6 { protocol, .. } => Some(*protocol),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use bytes::Bytes;

    use super::{FragmentDropReason, FragmentLimits, FragmentReassembler, ReassemblyResult};
    use crate::vpn::packet::ip::{FragmentKey, FragmentTemplate, IpFragment};

    fn limits() -> FragmentLimits {
        FragmentLimits {
            max_datagrams: 2,
            max_fragments_per_datagram: 4,
            max_buffered_bytes: 128,
            max_unfragmentable_header_bytes: 60,
            timeout: Duration::from_secs(30),
        }
    }

    fn key(identification: u16) -> FragmentKey {
        FragmentKey::Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            target: "198.51.100.2".parse().unwrap(),
            protocol: 17,
            identification,
        }
    }

    fn ipv4_header() -> Bytes {
        let mut header = vec![0_u8; 20];
        header[0] = 0x45;
        header[8] = 64;
        header[9] = 17;
        header[12..16].copy_from_slice(&[192, 0, 2, 1]);
        header[16..20].copy_from_slice(&[198, 51, 100, 2]);
        Bytes::from(header)
    }

    fn ipv6_key(identification: u32) -> FragmentKey {
        FragmentKey::Ipv6 {
            source: Ipv6Addr::LOCALHOST,
            target: "2001:db8::1".parse().unwrap(),
            identification,
        }
    }

    fn ipv6_header(protocol: u8) -> FragmentTemplate {
        let mut header = vec![0_u8; 40];
        header[0] = 0x60;
        header[6] = 44;
        header[7] = 64;
        header[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        header[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        FragmentTemplate::Ipv6 {
            header: Bytes::from(header),
            protocol,
        }
    }

    #[test]
    fn out_of_order_fragments_reassemble_when_the_gap_closes() {
        let mut reassembler = FragmentReassembler::new(limits());
        let later = IpFragment {
            key: key(1),
            protocol: 17,
            offset: 8,
            more: false,
            data: Bytes::from_static(b"ijkl"),
            template: None,
        };
        assert!(matches!(
            reassembler.ingest(Duration::ZERO, later),
            ReassemblyResult::Pending
        ));
        let first = IpFragment {
            key: key(1),
            protocol: 17,
            offset: 0,
            more: true,
            data: Bytes::from_static(b"abcdefgh"),
            template: Some(FragmentTemplate::Ipv4(ipv4_header())),
        };
        let ReassemblyResult::Complete(packet) = reassembler.ingest(Duration::from_secs(1), first)
        else {
            panic!("expected reassembly");
        };
        assert_eq!(&packet[20..], b"abcdefghijkl");
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

    #[test]
    fn overlap_poisons_the_identity_until_expiry() {
        let mut reassembler = FragmentReassembler::new(limits());
        let first = IpFragment {
            key: key(2),
            protocol: 17,
            offset: 0,
            more: true,
            data: Bytes::from_static(b"abcdefgh"),
            template: Some(FragmentTemplate::Ipv4(ipv4_header())),
        };
        assert!(matches!(
            reassembler.ingest(Duration::ZERO, first.clone()),
            ReassemblyResult::Pending
        ));
        let overlap = IpFragment {
            offset: 4,
            more: false,
            data: Bytes::from_static(b"overlap!"),
            template: None,
            ..first.clone()
        };
        assert!(matches!(
            reassembler.ingest(Duration::ZERO, overlap),
            ReassemblyResult::Dropped(FragmentDropReason::Overlap)
        ));
        assert!(matches!(
            reassembler.ingest(Duration::from_secs(1), first),
            ReassemblyResult::Pending
        ));
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

    #[test]
    fn conflicting_ipv6_next_headers_poison_one_fragment_identity() {
        let mut reassembler = FragmentReassembler::new(limits());
        let udp_final = IpFragment {
            key: ipv6_key(9),
            protocol: 17,
            offset: 8,
            more: false,
            data: Bytes::from_static(b"ijkl"),
            template: None,
        };
        assert!(matches!(
            reassembler.ingest(Duration::ZERO, udp_final.clone()),
            ReassemblyResult::Pending
        ));
        let tcp_first = IpFragment {
            key: ipv6_key(9),
            protocol: 6,
            offset: 0,
            more: true,
            data: Bytes::from_static(b"abcdefgh"),
            template: Some(ipv6_header(6)),
        };

        assert!(matches!(
            reassembler.ingest(Duration::ZERO, tcp_first),
            ReassemblyResult::Dropped(FragmentDropReason::Overlap)
        ));
        assert!(matches!(
            reassembler.ingest(Duration::from_secs(1), udp_final),
            ReassemblyResult::Pending
        ));
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

    #[test]
    fn global_byte_budget_is_released_on_expiry() {
        let mut configured = limits();
        configured.max_buffered_bytes = 28;
        let mut reassembler = FragmentReassembler::new(configured);
        let fragment = IpFragment {
            key: key(3),
            protocol: 17,
            offset: 0,
            more: true,
            data: Bytes::from_static(b"abcdefgh"),
            template: Some(FragmentTemplate::Ipv4(ipv4_header())),
        };
        assert!(matches!(
            reassembler.ingest(Duration::ZERO, fragment.clone()),
            ReassemblyResult::Pending
        ));
        assert_eq!(reassembler.buffered_bytes(), 28);
        reassembler.expire(Duration::from_secs(31));
        assert_eq!(reassembler.buffered_bytes(), 0);

        let next = IpFragment {
            key: key(4),
            ..fragment
        };
        assert!(matches!(
            reassembler.ingest(Duration::from_secs(31), next),
            ReassemblyResult::Pending
        ));
    }

    #[test]
    fn transient_capacity_pressure_does_not_poison_a_datagram_identity() {
        let mut configured = limits();
        configured.max_buffered_bytes = 32;
        let mut reassembler = FragmentReassembler::new(configured);
        let occupying_first = IpFragment {
            key: key(30),
            protocol: 17,
            offset: 0,
            more: true,
            data: Bytes::from_static(b"abcdefgh"),
            template: Some(FragmentTemplate::Ipv4(ipv4_header())),
        };
        assert!(matches!(
            reassembler.ingest(Duration::ZERO, occupying_first),
            ReassemblyResult::Pending
        ));

        let rejected = IpFragment {
            key: key(31),
            protocol: 17,
            offset: 0,
            more: true,
            data: Bytes::from_static(b"abcdefgh"),
            template: Some(FragmentTemplate::Ipv4(ipv4_header())),
        };
        assert!(matches!(
            reassembler.ingest(Duration::ZERO, rejected.clone()),
            ReassemblyResult::Dropped(FragmentDropReason::Capacity)
        ));

        let occupying_final = IpFragment {
            key: key(30),
            protocol: 17,
            offset: 8,
            more: false,
            data: Bytes::from_static(b"ijkl"),
            template: None,
        };
        assert!(matches!(
            reassembler.ingest(Duration::from_secs(1), occupying_final),
            ReassemblyResult::Complete(_)
        ));
        assert_eq!(reassembler.buffered_bytes(), 0);

        assert!(matches!(
            reassembler.ingest(Duration::from_secs(2), rejected),
            ReassemblyResult::Pending
        ));
        assert_eq!(reassembler.buffered_bytes(), 28);
    }

    #[test]
    fn tiny_fragment_train_is_poisoned_after_the_fragment_limit() {
        let mut reassembler = FragmentReassembler::new(limits());
        for index in 0..4 {
            let fragment = IpFragment {
                key: key(5),
                protocol: 17,
                offset: index * 8,
                more: true,
                data: Bytes::from_static(b"abcdefgh"),
                template: (index == 0).then(|| FragmentTemplate::Ipv4(ipv4_header())),
            };
            assert!(matches!(
                reassembler.ingest(Duration::ZERO, fragment),
                ReassemblyResult::Pending
            ));
        }

        let excess = IpFragment {
            key: key(5),
            protocol: 17,
            offset: 32,
            more: true,
            data: Bytes::from_static(b"abcdefgh"),
            template: None,
        };
        assert!(matches!(
            reassembler.ingest(Duration::ZERO, excess),
            ReassemblyResult::Dropped(FragmentDropReason::TooManyFragments)
        ));
        assert_eq!(reassembler.buffered_bytes(), 0);

        for index in 0..1_000 {
            let fragment = IpFragment {
                key: key(5),
                protocol: 17,
                offset: 40 + index * 8,
                more: true,
                data: Bytes::from_static(b"abcdefgh"),
                template: None,
            };
            assert!(matches!(
                reassembler.ingest(Duration::from_secs(1), fragment),
                ReassemblyResult::Pending
            ));
        }
        assert_eq!(reassembler.buffered_bytes(), 0);

        let replacement = IpFragment {
            key: key(5),
            protocol: 17,
            offset: 0,
            more: false,
            data: Bytes::from_static(b"done"),
            template: Some(FragmentTemplate::Ipv4(ipv4_header())),
        };
        assert!(matches!(
            reassembler.ingest(Duration::from_secs(31), replacement),
            ReassemblyResult::Complete(_)
        ));
    }
}
