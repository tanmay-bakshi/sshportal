use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

const POINT_TO_POINT_IPV4_PREFIX: u8 = 30;
const POINT_TO_POINT_IPV6_PREFIX: u8 = 126;
const SYNTHETIC_IPV4_PREFIX: u8 = 16;
const SYNTHETIC_IPV6_PREFIX: u8 = 96;
const MAX_POINT_TO_POINT_ATTEMPTS_PER_RANGE: u32 = 256;

const POINT_TO_POINT_IPV4_RANGES: [Ipv4Net; 4] = [
    Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16),
    Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10),
];

const SYNTHETIC_IPV4_RANGES: [Ipv4Net; 2] = [
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), SYNTHETIC_IPV4_PREFIX),
    Ipv4Net::new_assert(Ipv4Addr::new(198, 19, 0, 0), SYNTHETIC_IPV4_PREFIX),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VpnNetworkConfiguration {
    pub(super) point_to_point_ipv4: Ipv4Net,
    pub(super) interface_ipv4: Ipv4Addr,
    pub(super) gateway_ipv4: Ipv4Addr,
    pub(super) point_to_point_ipv6: Ipv6Net,
    pub(super) interface_ipv6: Ipv6Addr,
    pub(super) gateway_ipv6: Ipv6Addr,
    pub(super) synthetic: Option<SyntheticNetworkConfiguration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SyntheticNetworkConfiguration {
    pub(super) ipv4: Ipv4Net,
    pub(super) ipv4_dns: Ipv4Addr,
    pub(super) ipv4_first: Ipv4Addr,
    pub(super) ipv4_last: Ipv4Addr,
    pub(super) ipv6: Ipv6Net,
    pub(super) ipv6_dns: Ipv6Addr,
    pub(super) ipv6_first: Ipv6Addr,
    pub(super) ipv6_last: Ipv6Addr,
}

impl VpnNetworkConfiguration {
    pub(super) fn select(
        existing_routes: &[IpNet],
        entropy: [u8; 16],
        synthetic_dns_enabled: bool,
    ) -> Result<Self> {
        let point_to_point_ipv4 = select_point_to_point_ipv4(existing_routes, entropy)?;
        let point_to_point_ipv6 = select_unique_local_network(
            existing_routes,
            entropy,
            0x49,
            POINT_TO_POINT_IPV6_PREFIX,
            "point-to-point",
        )?;
        let synthetic = if synthetic_dns_enabled {
            let mut occupied_routes = existing_routes.to_vec();
            occupied_routes.push(IpNet::V4(point_to_point_ipv4));
            occupied_routes.push(IpNet::V6(point_to_point_ipv6));
            Some(select_synthetic_networks(&occupied_routes, entropy)?)
        } else {
            None
        };

        let ipv4_base = u32::from(point_to_point_ipv4.network());
        let ipv6_base = u128::from(point_to_point_ipv6.network());
        Ok(Self {
            point_to_point_ipv4,
            gateway_ipv4: Ipv4Addr::from(ipv4_base + 1),
            interface_ipv4: Ipv4Addr::from(ipv4_base + 2),
            point_to_point_ipv6,
            gateway_ipv6: Ipv6Addr::from(ipv6_base + 1),
            interface_ipv6: Ipv6Addr::from(ipv6_base + 2),
            synthetic,
        })
    }
}

impl SyntheticNetworkConfiguration {
    pub(super) fn routes(self) -> [IpNet; 2] {
        [IpNet::V4(self.ipv4), IpNet::V6(self.ipv6)]
    }

    pub(super) fn dns_servers(self) -> [IpAddr; 2] {
        [IpAddr::V4(self.ipv4_dns), IpAddr::V6(self.ipv6_dns)]
    }
}

fn select_synthetic_networks(
    existing_routes: &[IpNet],
    entropy: [u8; 16],
) -> Result<SyntheticNetworkConfiguration> {
    let ipv4 = SYNTHETIC_IPV4_RANGES
        .into_iter()
        .find(|candidate| route_is_available(IpNet::V4(*candidate), existing_routes))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "both RFC 2544 synthetic IPv4 ranges overlap existing routes; remove the conflict or use CIDR-only VPN routing"
            )
        })?;
    let ipv6 = select_unique_local_network(
        existing_routes,
        entropy,
        0x53,
        SYNTHETIC_IPV6_PREFIX,
        "synthetic DNS",
    )?;

    let ipv4_base = u32::from(ipv4.network());
    let ipv6_base = u128::from(ipv6.network());
    Ok(SyntheticNetworkConfiguration {
        ipv4,
        ipv4_dns: Ipv4Addr::from(ipv4_base + 1),
        ipv4_first: Ipv4Addr::from(ipv4_base + 2),
        ipv4_last: Ipv4Addr::from(ipv4_base + u16::MAX as u32 - 1),
        ipv6,
        ipv6_dns: Ipv6Addr::from(ipv6_base + 1),
        ipv6_first: Ipv6Addr::from(ipv6_base + 2),
        ipv6_last: Ipv6Addr::from(ipv6_base + u32::MAX as u128 - 1),
    })
}

fn select_point_to_point_ipv4(existing_routes: &[IpNet], entropy: [u8; 16]) -> Result<Ipv4Net> {
    let entropy = u32::from_be_bytes(entropy[..4].try_into().expect("four-byte entropy prefix"));
    for (range_index, range) in POINT_TO_POINT_IPV4_RANGES.into_iter().enumerate() {
        let subnet_bits = u32::from(POINT_TO_POINT_IPV4_PREFIX - range.prefix_len());
        let subnet_count = 1_u32 << subnet_bits;
        let range_base = u32::from(range.network());
        let start =
            entropy.wrapping_add((range_index as u32).wrapping_mul(0x9e37_79b9)) % subnet_count;
        let mut stride = entropy
            .rotate_left(13)
            .wrapping_add((range_index as u32).wrapping_mul(0x85eb_ca6b))
            | 1;
        stride %= subnet_count;
        if stride == 0 {
            stride = 1;
        }
        for attempt in 0..MAX_POINT_TO_POINT_ATTEMPTS_PER_RANGE.min(subnet_count) {
            let subnet_index = start.wrapping_add(attempt.wrapping_mul(stride)) % subnet_count;
            let subnet_base = range_base | subnet_index << (32 - POINT_TO_POINT_IPV4_PREFIX);
            let candidate =
                Ipv4Net::new_assert(Ipv4Addr::from(subnet_base), POINT_TO_POINT_IPV4_PREFIX);
            if route_is_available(IpNet::V4(candidate), existing_routes) {
                return Ok(candidate);
            }
        }
    }
    bail!(
        "could not select a collision-free point-to-point IPv4 subnet from the private and shared address ranges"
    )
}

fn select_unique_local_network(
    existing_routes: &[IpNet],
    entropy: [u8; 16],
    discriminator: u8,
    prefix_len: u8,
    purpose: &str,
) -> Result<Ipv6Net> {
    for attempt in 0_u8..16 {
        let mut bytes = [0_u8; 16];
        bytes[0] = 0xfd;
        for index in 1..16 {
            bytes[index] = entropy[(index + usize::from(discriminator)) % entropy.len()]
                ^ discriminator.wrapping_mul(index as u8)
                ^ attempt.wrapping_mul(0x5b);
        }
        let candidate = Ipv6Net::new_assert(Ipv6Addr::from(bytes), prefix_len).trunc();
        if route_is_available(IpNet::V6(candidate), existing_routes) {
            return Ok(candidate);
        }
    }
    bail!(
        "could not select a collision-free session-specific {purpose} IPv6 subnet; retry the VPN session"
    )
}

fn route_is_available(candidate: IpNet, existing_routes: &[IpNet]) -> bool {
    existing_routes
        .iter()
        .filter(|route| route.prefix_len() > 0)
        .all(|route| !networks_overlap(candidate, *route))
}

fn networks_overlap(left: IpNet, right: IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V6(left), IpNet::V6(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V4(_), IpNet::V6(_)) | (IpNet::V6(_), IpNet::V4(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnet::IpNet;

    use super::{VpnNetworkConfiguration, networks_overlap};

    #[test]
    fn selection_avoids_whole_subnet_and_synthetic_route_conflicts() {
        let existing = [
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "198.18.0.0/16".parse().unwrap(),
        ];

        let selected = VpnNetworkConfiguration::select(&existing, [7; 16], true).unwrap();
        let synthetic = selected.synthetic.unwrap();

        assert!(!existing[0].contains(&IpAddr::V4(selected.interface_ipv4)));
        assert!(!existing[0].contains(&IpAddr::V4(selected.gateway_ipv4)));
        assert!(
            selected
                .point_to_point_ipv4
                .contains(&selected.interface_ipv4)
        );
        assert!(
            selected
                .point_to_point_ipv4
                .contains(&selected.gateway_ipv4)
        );
        assert_eq!(selected.point_to_point_ipv4.prefix_len(), 30);
        assert_eq!(synthetic.ipv4.to_string(), "198.19.0.0/16");
        assert_eq!(synthetic.ipv4_dns, Ipv4Addr::new(198, 19, 0, 1));
        assert_eq!(synthetic.ipv4_first, Ipv4Addr::new(198, 19, 0, 2));
        assert_eq!(synthetic.ipv4_last, Ipv4Addr::new(198, 19, 255, 254));
    }

    #[test]
    fn defaults_do_not_make_every_candidate_appear_occupied() {
        let existing = [
            "0.0.0.0/0".parse::<IpNet>().unwrap(),
            "::/0".parse().unwrap(),
        ];

        VpnNetworkConfiguration::select(&existing, [11; 16], true).unwrap();
    }

    #[test]
    fn selection_rejects_a_partial_point_to_point_overlap() {
        let baseline = VpnNetworkConfiguration::select(&[], [17; 16], false).unwrap();
        let occupied_host = IpNet::new(IpAddr::V4(baseline.gateway_ipv4), 32).unwrap();

        let selected = VpnNetworkConfiguration::select(&[occupied_host], [17; 16], false).unwrap();

        assert_ne!(selected.point_to_point_ipv4, baseline.point_to_point_ipv4);
    }

    #[test]
    fn overlapping_subnets_are_detected_in_either_direction() {
        let broad = "198.18.0.0/15".parse().unwrap();
        let narrow = "198.19.4.0/24".parse().unwrap();

        assert!(networks_overlap(broad, narrow));
        assert!(networks_overlap(narrow, broad));
        assert!(!networks_overlap(
            "198.18.0.0/16".parse().unwrap(),
            "198.19.0.0/16".parse().unwrap()
        ));
    }

    #[test]
    fn synthetic_ipv6_network_is_session_specific_and_has_bounded_pool() {
        let first = VpnNetworkConfiguration::select(&[], [1; 16], true)
            .unwrap()
            .synthetic
            .unwrap();
        let second = VpnNetworkConfiguration::select(&[], [2; 16], true)
            .unwrap()
            .synthetic
            .unwrap();

        assert_ne!(first.ipv6, second.ipv6);
        assert!(first.ipv6.contains(&first.ipv6_dns));
        assert!(first.ipv6.contains(&first.ipv6_first));
        assert!(first.ipv6.contains(&first.ipv6_last));
        assert_eq!(first.routes().len(), 2);
        assert_eq!(first.dns_servers().len(), 2);
    }

    #[test]
    fn point_to_point_ipv6_network_is_disjoint_from_synthetic_ipv6() {
        let selected = VpnNetworkConfiguration::select(&[], [23; 16], true).unwrap();
        let synthetic = selected.synthetic.unwrap();

        assert!(!networks_overlap(
            IpNet::V6(selected.point_to_point_ipv6),
            IpNet::V6(synthetic.ipv6)
        ));
        assert_eq!(selected.point_to_point_ipv6.prefix_len(), 126);
    }

    #[test]
    fn cidr_only_configuration_does_not_claim_synthetic_ranges() {
        let existing = ["198.18.0.0/15".parse::<IpNet>().unwrap()];

        let selected = VpnNetworkConfiguration::select(&existing, [13; 16], false).unwrap();

        assert!(selected.synthetic.is_none());
    }
}
