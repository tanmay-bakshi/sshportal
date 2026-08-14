use std::net::IpAddr;

use anyhow::{Result, bail};

use crate::control::{OfferedSession, VpnScope};
use crate::network::protocol::{NetworkError, NetworkTarget};
use crate::vpn::SystemVpnPolicy;

#[derive(Clone, Debug)]
pub(super) enum ClientNetworkPolicy {
    DirectEgress,
    SystemVpn(SystemVpnPolicy),
}

impl ClientNetworkPolicy {
    pub(super) fn from_approved_session(session: &OfferedSession) -> Result<Self> {
        match session {
            OfferedSession::Socks {}
            | OfferedSession::Vpn {
                scope: VpnScope::Application { .. },
            } => Ok(Self::DirectEgress),
            OfferedSession::Vpn {
                scope: VpnScope::System { policy },
            } => Ok(Self::SystemVpn(policy.clone())),
            OfferedSession::Ssh { .. } => {
                bail!("an SSH offer cannot start a client network session")
            }
        }
    }

    pub(super) fn authorize_target(&self, target: &NetworkTarget) -> Result<(), NetworkError> {
        if self.allows_target(target) {
            return Ok(());
        }
        Err(NetworkError::policy_denied(format!(
            "approved session does not permit the network destination {}:{}",
            target.host, target.port
        )))
    }

    pub(super) fn allows_resolver_stream(&self) -> bool {
        match self {
            Self::DirectEgress => false,
            Self::SystemVpn(policy) => policy.uses_virtual_dns(),
        }
    }

    pub(super) fn authorize_resolver_name(&self, name: &str) -> Result<(), NetworkError> {
        if self.allows_resolver_name(name) {
            return Ok(());
        }
        Err(NetworkError::policy_denied(format!(
            "approved session does not permit resolving `{name}`"
        )))
    }

    fn allows_target(&self, target: &NetworkTarget) -> bool {
        let Self::SystemVpn(policy) = self else {
            return true;
        };
        if policy.is_full_tunnel() {
            return true;
        }
        match target.host.parse::<IpAddr>() {
            Ok(address) => policy.contains_ip(address),
            Err(_) => policy.matches_domain(&target.host),
        }
    }

    fn allows_resolver_name(&self, name: &str) -> bool {
        let Self::SystemVpn(policy) = self else {
            return false;
        };
        policy.is_full_tunnel() || policy.matches_domain(name)
    }
}

#[cfg(test)]
mod tests {
    use super::ClientNetworkPolicy;
    use crate::control::{OfferedSession, VpnScope};
    use crate::network::protocol::{NetworkErrorKind, NetworkTarget};
    use crate::vpn::SystemVpnPolicy;

    fn policy_for(session: OfferedSession) -> ClientNetworkPolicy {
        ClientNetworkPolicy::from_approved_session(&session).unwrap()
    }

    fn system_policy(policy: SystemVpnPolicy) -> ClientNetworkPolicy {
        policy_for(OfferedSession::Vpn {
            scope: VpnScope::System { policy },
        })
    }

    #[test]
    fn socks_and_application_vpn_allow_egress_but_not_resolver_streams() {
        for session in [
            OfferedSession::Socks {},
            OfferedSession::Vpn {
                scope: VpnScope::Application {
                    application: "Firefox".to_string(),
                },
            },
        ] {
            let policy = policy_for(session);
            for target in [
                NetworkTarget::new("192.0.2.8", 443).unwrap(),
                NetworkTarget::new("arbitrary.example", 53).unwrap(),
            ] {
                policy.authorize_target(&target).unwrap();
            }
            assert!(!policy.allows_resolver_stream());
            assert_eq!(
                policy
                    .authorize_resolver_name("arbitrary.example")
                    .unwrap_err()
                    .kind,
                NetworkErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn full_system_vpn_allows_every_target_and_resolver_name() {
        let policy = system_policy(SystemVpnPolicy::full_tunnel());

        for target in [
            NetworkTarget::new("192.0.2.8", 443).unwrap(),
            NetworkTarget::new("arbitrary.example", 53).unwrap(),
        ] {
            policy.authorize_target(&target).unwrap();
        }
        assert!(policy.allows_resolver_stream());
        policy.authorize_resolver_name("arbitrary.example").unwrap();
    }

    #[test]
    fn selective_system_vpn_enforces_address_and_domain_selectors_by_target_kind() {
        let policy = system_policy(
            SystemVpnPolicy::new(
                vec![
                    "10.20.0.0/16".parse().unwrap(),
                    "2001:db8:20::/48".parse().unwrap(),
                ],
                vec!["elevancehealth.com".to_string()],
            )
            .unwrap(),
        );

        for target in [
            NetworkTarget::new("10.20.9.8", 443).unwrap(),
            NetworkTarget::new("2001:db8:20::8", 443).unwrap(),
            NetworkTarget::new("jira.elevancehealth.com", 443).unwrap(),
        ] {
            policy.authorize_target(&target).unwrap();
        }
        for target in [
            NetworkTarget::new("10.21.0.1", 443).unwrap(),
            NetworkTarget::new("2001:db8:21::1", 443).unwrap(),
            NetworkTarget::new("notelevancehealth.com", 443).unwrap(),
        ] {
            assert_eq!(
                policy.authorize_target(&target).unwrap_err().kind,
                NetworkErrorKind::PermissionDenied
            );
        }
        policy
            .authorize_resolver_name("jira.elevancehealth.com")
            .unwrap();
        assert_eq!(
            policy
                .authorize_resolver_name("notelevancehealth.com")
                .unwrap_err()
                .kind,
            NetworkErrorKind::PermissionDenied
        );
    }

    #[test]
    fn cidr_only_system_vpn_rejects_resolver_streams_and_names() {
        let policy = system_policy(
            SystemVpnPolicy::new(vec!["10.20.0.0/16".parse().unwrap()], Vec::new()).unwrap(),
        );

        assert_eq!(
            policy
                .authorize_target(&NetworkTarget::new("anything.example", 443).unwrap())
                .unwrap_err()
                .kind,
            NetworkErrorKind::PermissionDenied
        );
        assert!(!policy.allows_resolver_stream());
        assert_eq!(
            policy
                .authorize_resolver_name("anything.example")
                .unwrap_err()
                .kind,
            NetworkErrorKind::PermissionDenied
        );
    }

    #[test]
    fn domain_only_system_vpn_rejects_direct_ip_targets() {
        let policy = system_policy(
            SystemVpnPolicy::new(Vec::new(), vec!["allowed.example".to_string()]).unwrap(),
        );

        assert_eq!(
            policy
                .authorize_target(&NetworkTarget::new("192.0.2.1", 443).unwrap())
                .unwrap_err()
                .kind,
            NetworkErrorKind::PermissionDenied
        );
    }

    #[test]
    fn ssh_offer_cannot_construct_a_network_policy() {
        assert!(
            ClientNetworkPolicy::from_approved_session(&OfferedSession::Ssh {
                ssh_public_key: "unused".to_string(),
                persist_key_requested: false,
            })
            .is_err()
        );
    }
}
