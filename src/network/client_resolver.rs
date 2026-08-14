use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use dns_lookup::{AddrFamily, AddrInfoHints, LookupErrorKind, getaddrinfo};
use tokio::sync::Semaphore;

use crate::network::protocol::{NetworkError, NetworkErrorKind, NetworkTarget, ResolutionFamily};
use crate::network::resolver_protocol::{ResolveOutcome, ResolveRequest};

const DNS_CLASS_INTERNET: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_SVCB: u16 = 64;
const DNS_TYPE_HTTPS: u16 = 65;
const RESPONSE_CODE_SERVER_FAILURE: u8 = 2;
const RESPONSE_CODE_NOT_IMPLEMENTED: u8 = 4;
const SYNTHETIC_TTL_SECONDS: u32 = 30;
pub(super) const MAX_RESOLVED_ADDRESSES: usize = 16;
pub(crate) const MAX_CONCURRENT_NATIVE_RESOLVER_LOOKUPS: usize = 64;
const MAX_CONCURRENT_NATIVE_EGRESS_LOOKUPS: usize = 64;

pub(crate) struct ClientResolver {
    native_resolver_lookups: Arc<Semaphore>,
    native_egress_lookups: Arc<Semaphore>,
}

#[derive(Debug, Eq, PartialEq)]
enum NativeLookupAdmissionError {
    Saturated,
    TaskFailed(String),
}

enum NativeLookupOutcome {
    Positive,
    NoData,
    Failure,
}

#[derive(Clone, Copy)]
enum NativeLookupClass {
    Resolver,
    Egress,
}

impl ClientResolver {
    pub(crate) fn from_system_configuration() -> Self {
        Self {
            native_resolver_lookups: Arc::new(Semaphore::new(
                MAX_CONCURRENT_NATIVE_RESOLVER_LOOKUPS,
            )),
            native_egress_lookups: Arc::new(Semaphore::new(MAX_CONCURRENT_NATIVE_EGRESS_LOOKUPS)),
        }
    }

    pub(crate) async fn resolve(&self, request: &ResolveRequest) -> ResolveOutcome {
        if request.record_class() != DNS_CLASS_INTERNET {
            return not_implemented();
        }

        let family = match request.record_type() {
            DNS_TYPE_A => AddrFamily::Inet,
            DNS_TYPE_AAAA => AddrFamily::Inet6,
            DNS_TYPE_CNAME | DNS_TYPE_SVCB | DNS_TYPE_HTTPS => return ResolveOutcome::NoData,
            _ => return not_implemented(),
        };
        let hostname = fully_qualified_name(request.name());
        match self
            .run_native_lookup(NativeLookupClass::Resolver, move || {
                lookup_address_family(&hostname, family)
            })
            .await
        {
            Ok(NativeLookupOutcome::Positive) => ResolveOutcome::Positive {
                answer_ttl: SYNTHETIC_TTL_SECONDS,
            },
            Ok(NativeLookupOutcome::NoData) => ResolveOutcome::NoData,
            Ok(NativeLookupOutcome::Failure)
            | Err(
                NativeLookupAdmissionError::Saturated | NativeLookupAdmissionError::TaskFailed(_),
            ) => server_failure(),
        }
    }

    pub(crate) async fn resolve_socket_addresses(
        &self,
        target: &NetworkTarget,
    ) -> Result<Vec<SocketAddr>, NetworkError> {
        target
            .validate()
            .map_err(|error| NetworkError::new(NetworkErrorKind::Protocol, error.to_string()))?;
        if let Ok(address) = target.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(address, target.port)]);
        }

        let hostname = fully_qualified_name(&target.host);
        let port = target.port;
        let resolution_family = target.resolution_family;
        match self
            .run_native_lookup(NativeLookupClass::Egress, move || {
                lookup_socket_addresses(&hostname, port, resolution_family)
            })
            .await
        {
            Ok(result) => result,
            Err(NativeLookupAdmissionError::Saturated) => Err(NetworkError::resource_limit(
                "client native resolver concurrency limit reached",
            )),
            Err(NativeLookupAdmissionError::TaskFailed(error)) => Err(NetworkError::new(
                NetworkErrorKind::General,
                format!("native resolver task failed: {error}"),
            )),
        }
    }

    async fn run_native_lookup<T, F>(
        &self,
        class: NativeLookupClass,
        lookup: F,
    ) -> Result<T, NativeLookupAdmissionError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let admission = match class {
            NativeLookupClass::Resolver => &self.native_resolver_lookups,
            NativeLookupClass::Egress => &self.native_egress_lookups,
        };
        let permit = Arc::clone(admission)
            .try_acquire_owned()
            .map_err(|_| NativeLookupAdmissionError::Saturated)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup()
        })
        .await
        .map_err(|error| NativeLookupAdmissionError::TaskFailed(error.to_string()))
    }

    #[cfg(test)]
    fn with_native_lookup_limits(resolver_limit: usize, egress_limit: usize) -> Self {
        Self {
            native_resolver_lookups: Arc::new(Semaphore::new(resolver_limit)),
            native_egress_lookups: Arc::new(Semaphore::new(egress_limit)),
        }
    }
}

fn lookup_address_family(hostname: &str, family: AddrFamily) -> NativeLookupOutcome {
    let hints = AddrInfoHints {
        address: family.into(),
        ..AddrInfoHints::default()
    };
    let mut addresses = match getaddrinfo(Some(hostname), None, Some(hints)) {
        Ok(addresses) => addresses,
        Err(error) => {
            return match error.kind() {
                LookupErrorKind::NoName | LookupErrorKind::NoData => NativeLookupOutcome::NoData,
                _ => NativeLookupOutcome::Failure,
            };
        }
    };
    match addresses.next() {
        Some(Ok(_)) => NativeLookupOutcome::Positive,
        Some(Err(_)) => NativeLookupOutcome::Failure,
        None => NativeLookupOutcome::NoData,
    }
}

fn lookup_socket_addresses(
    hostname: &str,
    port: u16,
    resolution_family: ResolutionFamily,
) -> Result<Vec<SocketAddr>, NetworkError> {
    let hints = socket_address_hints(resolution_family);
    let addresses = getaddrinfo(Some(hostname), None, Some(hints))
        .map_err(|error| map_lookup_error(hostname, error))?;
    let mut seen = HashSet::new();
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut first_is_ipv6 = None;
    for result in addresses {
        let mut address = result
            .map_err(|error| {
                NetworkError::new(
                    NetworkErrorKind::from_io(&error),
                    format!("failed to read an address for {hostname}: {error}"),
                )
            })?
            .sockaddr;
        address.set_port(port);
        if !resolution_family.allows(address.ip()) {
            continue;
        }
        if !seen.insert(address) {
            continue;
        }
        if first_is_ipv6.is_none() {
            first_is_ipv6 = Some(address.is_ipv6());
        }
        if address.is_ipv4() {
            ipv4.push(address);
        } else {
            ipv6.push(address);
        }
        if ipv4.len() + ipv6.len() == MAX_RESOLVED_ADDRESSES {
            break;
        }
    }
    let addresses = interleave_address_families(ipv4, ipv6, first_is_ipv6.unwrap_or(false));
    if addresses.is_empty() {
        return Err(NetworkError::new(
            NetworkErrorKind::NameNotFound,
            format!("{hostname} resolved to no usable addresses"),
        ));
    }
    Ok(addresses)
}

fn socket_address_hints(resolution_family: ResolutionFamily) -> AddrInfoHints {
    let address = match resolution_family {
        ResolutionFamily::Any => 0,
        ResolutionFamily::Ipv4 => AddrFamily::Inet.into(),
        ResolutionFamily::Ipv6 => AddrFamily::Inet6.into(),
    };
    AddrInfoHints {
        address,
        ..AddrInfoHints::default()
    }
}

fn map_lookup_error(hostname: &str, error: dns_lookup::LookupError) -> NetworkError {
    let kind = match error.kind() {
        LookupErrorKind::NoName | LookupErrorKind::NoData => NetworkErrorKind::NameNotFound,
        LookupErrorKind::Memory => NetworkErrorKind::ResourceLimit,
        LookupErrorKind::Again => NetworkErrorKind::TimedOut,
        LookupErrorKind::Badflags
        | LookupErrorKind::Fail
        | LookupErrorKind::Family
        | LookupErrorKind::Socktype
        | LookupErrorKind::Service
        | LookupErrorKind::System
        | LookupErrorKind::Unknown
        | LookupErrorKind::IO => NetworkErrorKind::General,
    };
    NetworkError::new(kind, format!("failed to resolve {hostname}: {error:?}"))
}

fn interleave_address_families(
    ipv4: Vec<SocketAddr>,
    ipv6: Vec<SocketAddr>,
    ipv6_first: bool,
) -> Vec<SocketAddr> {
    let mut ordered = Vec::with_capacity(ipv4.len() + ipv6.len());
    let mut ipv4 = ipv4.into_iter();
    let mut ipv6 = ipv6.into_iter();
    loop {
        let (first, second) = if ipv6_first {
            (ipv6.next(), ipv4.next())
        } else {
            (ipv4.next(), ipv6.next())
        };
        if first.is_none() && second.is_none() {
            break;
        }
        if let Some(address) = first {
            ordered.push(address);
        }
        if let Some(address) = second {
            ordered.push(address);
        }
    }
    ordered
}

fn fully_qualified_name(name: &str) -> String {
    if name == "." {
        return name.to_string();
    }
    format!("{name}.")
}

fn not_implemented() -> ResolveOutcome {
    ResolveOutcome::Failure {
        response_code: RESPONSE_CODE_NOT_IMPLEMENTED,
    }
}

fn server_failure() -> ResolveOutcome {
    ResolveOutcome::Failure {
        response_code: RESPONSE_CODE_SERVER_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use dns_lookup::AddrFamily;
    use tokio::sync::oneshot;

    use super::{
        ClientResolver, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_HTTPS, DNS_TYPE_SVCB,
        NativeLookupAdmissionError, NativeLookupClass, NativeLookupOutcome, fully_qualified_name,
        interleave_address_families, lookup_address_family, socket_address_hints,
    };
    use crate::network::protocol::ResolutionFamily;
    use crate::network::resolver_protocol::{ResolveOutcome, ResolveRequest};

    fn request(record_type: u16, record_class: u16) -> ResolveRequest {
        ResolveRequest::new("localhost", record_type, record_class, 5_000).unwrap()
    }

    #[test]
    fn protocol_hostnames_do_not_inherit_client_search_domains() {
        assert_eq!(fully_qualified_name("jira.example"), "jira.example.");
        assert_eq!(fully_qualified_name("."), ".");
    }

    #[test]
    fn native_lookup_is_address_family_specific() {
        assert!(matches!(
            lookup_address_family("localhost.", AddrFamily::Inet),
            NativeLookupOutcome::Positive
        ));
    }

    #[test]
    fn egress_lookup_hints_express_the_target_resolution_constraint() {
        assert_eq!(socket_address_hints(ResolutionFamily::Any).address, 0);
        assert_eq!(
            socket_address_hints(ResolutionFamily::Ipv4).address,
            i32::from(AddrFamily::Inet)
        );
        assert_eq!(
            socket_address_hints(ResolutionFamily::Ipv6).address,
            i32::from(AddrFamily::Inet6)
        );
    }

    #[tokio::test]
    async fn literal_targets_bypass_native_resolution_unchanged() {
        let resolver = ClientResolver::with_native_lookup_limits(0, 0);
        for expected in [
            "192.0.2.8:443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::8]:443".parse::<SocketAddr>().unwrap(),
        ] {
            let target = crate::network::protocol::NetworkTarget::from(expected);
            assert_eq!(
                resolver.resolve_socket_addresses(&target).await.unwrap(),
                vec![expected]
            );
        }
    }

    #[test]
    fn happy_eyeballs_candidates_preserve_preferred_family_and_interleave() {
        let ipv4 = vec![
            "192.0.2.1:443".parse::<SocketAddr>().unwrap(),
            "192.0.2.2:443".parse().unwrap(),
        ];
        let ipv6 = vec![
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        ];

        let ordered = interleave_address_families(ipv4, ipv6, true);

        assert!(ordered[0].is_ipv6());
        assert!(ordered[1].is_ipv4());
        assert!(ordered[2].is_ipv6());
        assert!(ordered[3].is_ipv4());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborting_a_waiter_does_not_release_a_running_native_lookup() {
        let resolver = Arc::new(ClientResolver::with_native_lookup_limits(1, 1));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = oneshot::channel();
        let lookup_task = tokio::spawn({
            let resolver = Arc::clone(&resolver);
            let release = Arc::clone(&release);
            async move {
                resolver
                    .run_native_lookup(NativeLookupClass::Egress, move || {
                        started_tx.send(()).unwrap();
                        let (lock, condition) = &*release;
                        let mut released = lock.lock().unwrap();
                        while !*released {
                            released = condition.wait(released).unwrap();
                        }
                    })
                    .await
            }
        });
        started_rx.await.unwrap();

        lookup_task.abort();
        assert!(lookup_task.await.unwrap_err().is_cancelled());
        assert_eq!(
            resolver
                .run_native_lookup(NativeLookupClass::Egress, || 2_u8)
                .await,
            Err(NativeLookupAdmissionError::Saturated)
        );

        let (lock, condition) = &*release;
        *lock.lock().unwrap() = true;
        condition.notify_all();
        tokio::time::timeout(Duration::from_secs(1), async {
            while resolver.native_egress_lookups.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("native lookup permit was not returned after blocking work completed");

        assert_eq!(
            resolver
                .run_native_lookup(NativeLookupClass::Egress, || 3_u8)
                .await,
            Ok(3)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saturated_egress_lookups_do_not_consume_resolver_admission() {
        let resolver = Arc::new(ClientResolver::with_native_lookup_limits(1, 1));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = oneshot::channel();
        let egress_task = tokio::spawn({
            let resolver = Arc::clone(&resolver);
            let release = Arc::clone(&release);
            async move {
                resolver
                    .run_native_lookup(NativeLookupClass::Egress, move || {
                        started_tx.send(()).unwrap();
                        let (lock, condition) = &*release;
                        let mut released = lock.lock().unwrap();
                        while !*released {
                            released = condition.wait(released).unwrap();
                        }
                    })
                    .await
            }
        });
        started_rx.await.unwrap();

        assert_eq!(
            resolver
                .run_native_lookup(NativeLookupClass::Egress, || 1_u8)
                .await,
            Err(NativeLookupAdmissionError::Saturated)
        );
        assert_eq!(
            resolver
                .run_native_lookup(NativeLookupClass::Resolver, || 2_u8)
                .await,
            Ok(2)
        );

        let (lock, condition) = &*release;
        *lock.lock().unwrap() = true;
        condition.notify_all();
        egress_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn only_address_queries_reach_the_native_resolver() {
        let resolver = ClientResolver::from_system_configuration();
        for record_type in [DNS_TYPE_CNAME, DNS_TYPE_SVCB, DNS_TYPE_HTTPS] {
            assert_eq!(
                resolver.resolve(&request(record_type, 1)).await,
                ResolveOutcome::NoData
            );
        }
        assert_eq!(
            resolver.resolve(&request(15, 1)).await,
            ResolveOutcome::Failure { response_code: 4 }
        );
        assert_eq!(
            resolver.resolve(&request(DNS_TYPE_A, 3)).await,
            ResolveOutcome::Failure { response_code: 4 }
        );
    }

    #[tokio::test]
    async fn native_positive_results_reveal_only_a_bounded_ttl() {
        let resolver = ClientResolver::from_system_configuration();
        let outcome = resolver.resolve(&request(DNS_TYPE_A, 1)).await;

        assert_eq!(outcome, ResolveOutcome::Positive { answer_ttl: 30 });
        let ipv6_outcome = resolver.resolve(&request(DNS_TYPE_AAAA, 1)).await;
        assert!(matches!(
            ipv6_outcome,
            ResolveOutcome::Positive { answer_ttl: 30 } | ResolveOutcome::NoData
        ));
    }
}
