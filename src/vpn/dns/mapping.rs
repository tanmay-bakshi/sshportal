use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use super::name::DnsName;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug)]
pub struct Ipv4Pool {
    inner: NumericPool,
}

impl Ipv4Pool {
    pub fn new(
        first: Ipv4Addr,
        last: Ipv4Addr,
        maximum_allocations: usize,
        reserved: impl IntoIterator<Item = Ipv4Addr>,
    ) -> Result<Self, PoolConfigurationError> {
        Ok(Self {
            inner: NumericPool::new(
                u32::from(first).into(),
                u32::from(last).into(),
                maximum_allocations,
                reserved
                    .into_iter()
                    .map(|address| u32::from(address).into()),
                AddressFamily::Ipv4,
            )?,
        })
    }
}

#[derive(Debug)]
pub struct Ipv6Pool {
    inner: NumericPool,
}

impl Ipv6Pool {
    pub fn new(
        first: Ipv6Addr,
        last: Ipv6Addr,
        maximum_allocations: usize,
        reserved: impl IntoIterator<Item = Ipv6Addr>,
    ) -> Result<Self, PoolConfigurationError> {
        Ok(Self {
            inner: NumericPool::new(
                u128::from(first),
                u128::from(last),
                maximum_allocations,
                reserved.into_iter().map(u128::from),
                AddressFamily::Ipv6,
            )?,
        })
    }
}

#[derive(Debug)]
struct NumericPool {
    next: Option<u128>,
    last: u128,
    maximum_allocations: usize,
    allocations: usize,
    reserved: HashSet<u128>,
    family: AddressFamily,
}

impl NumericPool {
    fn new(
        first: u128,
        last: u128,
        maximum_allocations: usize,
        reserved: impl IntoIterator<Item = u128>,
        family: AddressFamily,
    ) -> Result<Self, PoolConfigurationError> {
        if first > last {
            return Err(PoolConfigurationError::InvalidRange(family));
        }
        if maximum_allocations == 0 {
            return Err(PoolConfigurationError::ZeroCapacity(family));
        }

        let reserved = reserved.into_iter().collect::<HashSet<_>>();
        if reserved
            .iter()
            .any(|address| *address < first || *address > last)
        {
            return Err(PoolConfigurationError::ReservedAddressOutsideRange(family));
        }

        Ok(Self {
            next: Some(first),
            last,
            maximum_allocations,
            allocations: 0,
            reserved,
            family,
        })
    }

    fn allocate(&mut self) -> Result<u128, MappingError> {
        if self.allocations >= self.maximum_allocations {
            return Err(MappingError::Exhausted(self.family));
        }

        while let Some(candidate) = self.next {
            self.next = if candidate == self.last {
                None
            } else {
                candidate.checked_add(1)
            };
            if self.reserved.contains(&candidate) {
                continue;
            }
            self.allocations += 1;
            return Ok(candidate);
        }
        Err(MappingError::Exhausted(self.family))
    }
}

#[derive(Debug)]
pub struct SyntheticAddressMap {
    ipv4_pool: Option<Ipv4Pool>,
    ipv6_pool: Option<Ipv6Pool>,
    names: HashMap<Arc<DnsName>, SyntheticAddresses>,
    addresses_to_names: HashMap<IpAddr, Arc<DnsName>>,
}

#[derive(Debug, Default)]
struct SyntheticAddresses {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

impl SyntheticAddressMap {
    pub fn new(ipv4_pool: Option<Ipv4Pool>, ipv6_pool: Option<Ipv6Pool>) -> Self {
        Self {
            ipv4_pool,
            ipv6_pool,
            names: HashMap::new(),
            addresses_to_names: HashMap::new(),
        }
    }

    pub fn get_or_allocate_ipv4(&mut self, name: &DnsName) -> Result<Ipv4Addr, MappingError> {
        if let Some(address) = self.names.get(name).and_then(|addresses| addresses.ipv4) {
            return Ok(address);
        }
        let pool = self
            .ipv4_pool
            .as_mut()
            .ok_or(MappingError::FamilyUnavailable(AddressFamily::Ipv4))?;
        let numeric = pool.inner.allocate()?;
        let address = Ipv4Addr::from(numeric as u32);
        let name = self.interned_name(name);
        self.names.entry(Arc::clone(&name)).or_default().ipv4 = Some(address);
        let previous = self.addresses_to_names.insert(IpAddr::V4(address), name);
        debug_assert!(previous.is_none());
        Ok(address)
    }

    pub fn get_or_allocate_ipv6(&mut self, name: &DnsName) -> Result<Ipv6Addr, MappingError> {
        if let Some(address) = self.names.get(name).and_then(|addresses| addresses.ipv6) {
            return Ok(address);
        }
        let pool = self
            .ipv6_pool
            .as_mut()
            .ok_or(MappingError::FamilyUnavailable(AddressFamily::Ipv6))?;
        let numeric = pool.inner.allocate()?;
        let address = Ipv6Addr::from(numeric);
        let name = self.interned_name(name);
        self.names.entry(Arc::clone(&name)).or_default().ipv6 = Some(address);
        let previous = self.addresses_to_names.insert(IpAddr::V6(address), name);
        debug_assert!(previous.is_none());
        Ok(address)
    }

    pub fn name_for_address(&self, address: IpAddr) -> Option<&DnsName> {
        self.addresses_to_names
            .get(&address)
            .map(|name| name.as_ref())
    }

    #[cfg(test)]
    pub fn ipv4_len(&self) -> usize {
        self.names
            .values()
            .filter(|addresses| addresses.ipv4.is_some())
            .count()
    }

    #[cfg(test)]
    pub fn ipv6_len(&self) -> usize {
        self.names
            .values()
            .filter(|addresses| addresses.ipv6.is_some())
            .count()
    }

    fn interned_name(&self, name: &DnsName) -> Arc<DnsName> {
        self.names
            .get_key_value(name)
            .map(|(stored, _)| Arc::clone(stored))
            .unwrap_or_else(|| Arc::new(name.clone()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolConfigurationError {
    InvalidRange(AddressFamily),
    ZeroCapacity(AddressFamily),
    ReservedAddressOutsideRange(AddressFamily),
}

impl fmt::Display for PoolConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange(family) => {
                write!(
                    formatter,
                    "the {family} synthetic-address range is reversed"
                )
            }
            Self::ZeroCapacity(family) => {
                write!(
                    formatter,
                    "the {family} synthetic-address pool has zero capacity"
                )
            }
            Self::ReservedAddressOutsideRange(family) => write!(
                formatter,
                "a reserved {family} synthetic address lies outside its configured range"
            ),
        }
    }
}

impl std::error::Error for PoolConfigurationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MappingError {
    FamilyUnavailable(AddressFamily),
    Exhausted(AddressFamily),
}

impl fmt::Display for MappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FamilyUnavailable(family) => {
                write!(
                    formatter,
                    "no {family} synthetic-address pool is configured"
                )
            }
            Self::Exhausted(family) => {
                write!(
                    formatter,
                    "the {family} synthetic-address pool is exhausted"
                )
            }
        }
    }
}

impl std::error::Error for MappingError {}

impl fmt::Display for AddressFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => formatter.write_str("IPv4"),
            Self::Ipv6 => formatter.write_str("IPv6"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::super::name::DnsName;
    use super::{
        AddressFamily, Ipv4Pool, Ipv6Pool, MappingError, PoolConfigurationError,
        SyntheticAddressMap,
    };

    fn map(maximum_allocations: usize) -> SyntheticAddressMap {
        let ipv4 = Ipv4Pool::new(
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 18, 0, 8),
            maximum_allocations,
            [Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 4)],
        )
        .unwrap();
        let ipv6 = Ipv6Pool::new(
            "fd00::1".parse().unwrap(),
            "fd00::8".parse().unwrap(),
            maximum_allocations,
            ["fd00::1".parse().unwrap(), "fd00::4".parse().unwrap()],
        )
        .unwrap();
        SyntheticAddressMap::new(Some(ipv4), Some(ipv6))
    }

    #[test]
    fn allocations_are_stable_case_insensitive_bijections() {
        let mut map = map(8);
        let original = DnsName::from_ascii("Jira.Example").unwrap();
        let same_name = DnsName::from_ascii("jira.example.").unwrap();

        let first = map.get_or_allocate_ipv4(&original).unwrap();
        let second = map.get_or_allocate_ipv4(&same_name).unwrap();

        assert_eq!(first, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(first, second);
        assert_eq!(map.ipv4_len(), 1);
        assert_eq!(map.name_for_address(IpAddr::V4(first)), Some(&original));
    }

    #[test]
    fn ipv4_and_ipv6_mappings_are_independent_and_skip_reserved_addresses() {
        let mut map = map(8);
        let first = DnsName::from_ascii("first.example").unwrap();
        let second = DnsName::from_ascii("second.example").unwrap();

        assert_eq!(
            map.get_or_allocate_ipv4(&first).unwrap(),
            Ipv4Addr::new(198, 18, 0, 2)
        );
        assert_eq!(
            map.get_or_allocate_ipv4(&second).unwrap(),
            Ipv4Addr::new(198, 18, 0, 3)
        );
        assert_eq!(
            map.get_or_allocate_ipv4(&DnsName::from_ascii("third.example").unwrap())
                .unwrap(),
            Ipv4Addr::new(198, 18, 0, 5)
        );
        assert_eq!(
            map.get_or_allocate_ipv6(&first).unwrap(),
            "fd00::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(map.ipv4_len(), 3);
        assert_eq!(map.ipv6_len(), 1);
    }

    #[test]
    fn both_address_families_share_one_retained_name() {
        let mut map = map(8);
        let name = DnsName::from_ascii("dual-stack.example").unwrap();
        let ipv4 = map.get_or_allocate_ipv4(&name).unwrap();
        let ipv6 = map.get_or_allocate_ipv6(&name).unwrap();

        assert_eq!(map.names.len(), 1);
        let ipv4_name = map.addresses_to_names.get(&IpAddr::V4(ipv4)).unwrap();
        let ipv6_name = map.addresses_to_names.get(&IpAddr::V6(ipv6)).unwrap();
        assert!(std::sync::Arc::ptr_eq(ipv4_name, ipv6_name));
    }

    #[test]
    fn exhausted_pools_never_evict_or_reuse_advertised_addresses() {
        let mut map = map(1);
        let first_name = DnsName::from_ascii("first.example").unwrap();
        let second_name = DnsName::from_ascii("second.example").unwrap();
        let first_address = map.get_or_allocate_ipv4(&first_name).unwrap();

        assert_eq!(
            map.get_or_allocate_ipv4(&second_name),
            Err(MappingError::Exhausted(AddressFamily::Ipv4))
        );
        assert_eq!(map.get_or_allocate_ipv4(&first_name), Ok(first_address));
        assert_eq!(
            map.name_for_address(IpAddr::V4(first_address)),
            Some(&first_name)
        );
    }

    #[test]
    fn absent_family_and_short_range_exhaustion_are_explicit() {
        let pool = Ipv4Pool::new(
            Ipv4Addr::new(198, 18, 0, 2),
            Ipv4Addr::new(198, 18, 0, 2),
            4,
            [],
        )
        .unwrap();
        let mut map = SyntheticAddressMap::new(Some(pool), None);
        let first = DnsName::from_ascii("first.example").unwrap();
        let second = DnsName::from_ascii("second.example").unwrap();

        map.get_or_allocate_ipv4(&first).unwrap();
        assert_eq!(
            map.get_or_allocate_ipv4(&second),
            Err(MappingError::Exhausted(AddressFamily::Ipv4))
        );
        assert_eq!(
            map.get_or_allocate_ipv6(&first),
            Err(MappingError::FamilyUnavailable(AddressFamily::Ipv6))
        );
    }

    #[test]
    fn a_fully_reserved_range_exhausts_without_allocating() {
        let pool = Ipv4Pool::new(
            Ipv4Addr::new(198, 18, 0, 2),
            Ipv4Addr::new(198, 18, 0, 3),
            2,
            [Ipv4Addr::new(198, 18, 0, 2), Ipv4Addr::new(198, 18, 0, 3)],
        )
        .unwrap();
        let mut map = SyntheticAddressMap::new(Some(pool), None);

        assert_eq!(
            map.get_or_allocate_ipv4(&DnsName::from_ascii("first.example").unwrap()),
            Err(MappingError::Exhausted(AddressFamily::Ipv4))
        );
        assert_eq!(map.ipv4_len(), 0);
    }

    #[test]
    fn invalid_pool_configuration_is_rejected() {
        assert_eq!(
            Ipv4Pool::new(
                Ipv4Addr::new(198, 18, 0, 8),
                Ipv4Addr::new(198, 18, 0, 1),
                1,
                [],
            )
            .unwrap_err(),
            PoolConfigurationError::InvalidRange(AddressFamily::Ipv4)
        );
        assert_eq!(
            Ipv6Pool::new(
                "fd00::1".parse().unwrap(),
                "fd00::8".parse().unwrap(),
                0,
                [],
            )
            .unwrap_err(),
            PoolConfigurationError::ZeroCapacity(AddressFamily::Ipv6)
        );
        assert_eq!(
            Ipv4Pool::new(
                Ipv4Addr::new(198, 18, 0, 2),
                Ipv4Addr::new(198, 18, 0, 8),
                1,
                [Ipv4Addr::new(198, 18, 0, 1)],
            )
            .unwrap_err(),
            PoolConfigurationError::ReservedAddressOutsideRange(AddressFamily::Ipv4)
        );
    }
}
