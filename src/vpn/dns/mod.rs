//! Strict DNS parsing and synthetic-address response generation for one VPN session.
//!
//! The address map intentionally has no removal operation. A fake address advertised during a
//! session therefore remains a stable reverse lookup until the entire map is dropped.

mod mapping;
mod name;
mod protocol;
mod synthesis;

pub use mapping::{Ipv4Pool, Ipv6Pool, SyntheticAddressMap};
pub(crate) use name::DnsName;
pub use protocol::{DnsQuery, ResponseCode};
pub use synthesis::{Resolution, synthesize_response};
