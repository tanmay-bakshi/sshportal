use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use url::Host;

use super::dns::DnsName;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SystemVpnPolicy {
    include_cidrs: Vec<IpNet>,
    include_domains: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnvalidatedSystemVpnPolicy {
    include_cidrs: Vec<IpNet>,
    include_domains: Vec<String>,
}

impl SystemVpnPolicy {
    pub fn new(include_cidrs: Vec<IpNet>, include_domains: Vec<String>) -> Result<Self> {
        let include_cidrs = normalize_cidrs(include_cidrs);
        let include_domains = normalize_domains(include_domains)?;
        Ok(Self {
            include_cidrs,
            include_domains,
        })
    }

    pub fn full_tunnel() -> Self {
        Self {
            include_cidrs: Vec::new(),
            include_domains: Vec::new(),
        }
    }

    pub fn is_full_tunnel(&self) -> bool {
        self.include_cidrs.is_empty() && self.include_domains.is_empty()
    }

    pub fn include_cidrs(&self) -> &[IpNet] {
        &self.include_cidrs
    }

    pub fn include_domains(&self) -> &[String] {
        &self.include_domains
    }

    pub fn uses_virtual_dns(&self) -> bool {
        self.is_full_tunnel() || !self.include_domains.is_empty()
    }

    pub fn matches_domain(&self, hostname: &str) -> bool {
        let Some(hostname) = normalize_candidate_domain(hostname) else {
            return false;
        };
        self.include_domains
            .iter()
            .any(|suffix| domain_matches_suffix(&hostname, suffix))
    }

    pub(crate) fn matches_dns_name(&self, name: &DnsName) -> bool {
        self.include_domains
            .iter()
            .any(|suffix| name.ends_with_ascii_suffix(suffix))
    }

    pub fn contains_ip(&self, address: IpAddr) -> bool {
        self.include_cidrs
            .iter()
            .any(|network| network.contains(&address))
    }

    pub(super) fn contains_exact_ip(&self, address: IpAddr) -> bool {
        self.include_cidrs.iter().any(|network| {
            network.prefix_len() == network.max_prefix_len() && network.addr() == address
        })
    }
}

impl Default for SystemVpnPolicy {
    fn default() -> Self {
        Self::full_tunnel()
    }
}

impl<'de> Deserialize<'de> for SystemVpnPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unvalidated = UnvalidatedSystemVpnPolicy::deserialize(deserializer)?;
        Self::new(unvalidated.include_cidrs, unvalidated.include_domains).map_err(D::Error::custom)
    }
}

fn normalize_cidrs(include_cidrs: Vec<IpNet>) -> Vec<IpNet> {
    let mut candidates = include_cidrs
        .into_iter()
        .map(|network| network.trunc())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();

    let mut normalized: Vec<IpNet> = Vec::new();
    for candidate in candidates {
        if normalized
            .iter()
            .any(|existing: &IpNet| existing.contains(&candidate.network()))
        {
            continue;
        }
        normalized.push(candidate);
    }
    normalized
}

fn normalize_domains(include_domains: Vec<String>) -> Result<Vec<String>> {
    let mut candidates = include_domains
        .iter()
        .map(|domain| normalize_domain(domain))
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_by(|left, right| {
        left.split('.')
            .count()
            .cmp(&right.split('.').count())
            .then_with(|| left.cmp(right))
    });
    candidates.dedup();

    let mut normalized: Vec<String> = Vec::new();
    for candidate in candidates {
        if normalized
            .iter()
            .any(|existing| domain_matches_suffix(&candidate, existing))
        {
            continue;
        }
        normalized.push(candidate);
    }
    Ok(normalized)
}

fn normalize_domain(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let domain = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if domain.is_empty() {
        bail!("VPN include domain must not be empty");
    }
    if domain.contains('*') {
        bail!(
            "VPN include domain `{value}` must not contain a wildcard; the apex already includes every subdomain"
        );
    }

    let canonical = match Host::parse(domain)
        .with_context(|| format!("invalid VPN include domain `{value}`"))?
    {
        Host::Domain(domain) => domain,
        Host::Ipv4(_) | Host::Ipv6(_) => {
            bail!("VPN include domain `{value}` is an IP address; use --vpn-include-cidr")
        }
    };
    validate_dns_name(&canonical)
        .with_context(|| format!("invalid VPN include domain `{value}`"))?;
    Ok(canonical)
}

fn normalize_candidate_domain(value: &str) -> Option<String> {
    let domain = value.strip_suffix('.').unwrap_or(value);
    if domain.is_empty() {
        return None;
    }
    match Host::parse(domain).ok()? {
        Host::Domain(domain) => Some(domain),
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

fn validate_dns_name(domain: &str) -> Result<()> {
    if domain.len() > 253 {
        bail!("domain name exceeds 253 bytes");
    }
    for label in domain.split('.') {
        if label.is_empty() {
            bail!("domain name contains an empty label");
        }
        if label.len() > 63 {
            bail!("domain label exceeds 63 bytes");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("domain label must not start or end with a hyphen");
        }
        if !label
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        {
            bail!("domain label contains a character other than a letter, digit, or hyphen");
        }
    }
    Ok(())
}

fn domain_matches_suffix(hostname: &str, suffix: &str) -> bool {
    hostname == suffix
        || hostname
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::SystemVpnPolicy;
    use crate::vpn::dns::DnsName;

    #[test]
    fn empty_policy_is_full_tunnel() {
        let policy = SystemVpnPolicy::default();

        assert!(policy.is_full_tunnel());
        assert!(policy.uses_virtual_dns());
    }

    #[test]
    fn cidrs_are_canonicalized_and_redundant_networks_are_removed() {
        let policy = SystemVpnPolicy::new(
            vec![
                "10.20.4.7/16".parse().unwrap(),
                "10.20.8.0/24".parse().unwrap(),
                "2001:db8:1::9/48".parse().unwrap(),
                "10.20.0.0/16".parse().unwrap(),
            ],
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            policy
                .include_cidrs()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.20.0.0/16", "2001:db8:1::/48"]
        );
        assert!(!policy.is_full_tunnel());
        assert!(!policy.uses_virtual_dns());
        assert!(policy.contains_ip("10.20.255.254".parse().unwrap()));
        assert!(policy.contains_ip("2001:db8:1:ffff::1".parse().unwrap()));
        assert!(!policy.contains_ip("10.21.0.1".parse().unwrap()));
        assert!(!policy.contains_ip("2001:db8:2::1".parse().unwrap()));
    }

    #[test]
    fn domains_are_idna_normalized_and_redundant_suffixes_are_removed() {
        let policy = SystemVpnPolicy::new(
            Vec::new(),
            vec![
                "Login.BÜCHER.example.".to_string(),
                "BÜCHER.example".to_string(),
                "xn--bcher-kva.example".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(policy.include_domains(), ["xn--bcher-kva.example"]);
        assert!(policy.matches_domain("xn--bcher-kva.example"));
        assert!(policy.matches_domain("login.bücher.example."));
        assert!(!policy.matches_domain("notbÜcher.example"));
    }

    #[test]
    fn domain_selector_matches_the_apex_and_only_label_bounded_subdomains() {
        let policy = SystemVpnPolicy::new(Vec::new(), vec!["anthem.com".to_string()]).unwrap();

        assert!(policy.matches_domain("anthem.com"));
        assert!(policy.matches_domain("login.care.anthem.com"));
        assert!(!policy.matches_domain("notanthem.com"));
        assert!(!policy.matches_domain("anthem.com.example"));
    }

    #[test]
    fn domain_selector_accepts_arbitrary_query_labels_under_the_suffix() {
        let policy =
            SystemVpnPolicy::new(Vec::new(), vec!["elevancehealth.com".to_string()]).unwrap();

        assert!(policy.matches_domain("_service.jira.elevancehealth.com"));
        assert!(
            policy.matches_dns_name(
                &DnsName::from_ascii("_SERVICE.Jira.ElevanceHealth.Com").unwrap()
            )
        );
        assert!(
            policy.matches_dns_name(
                &DnsName::from_wire_labels(vec![
                    vec![b'c', b'a', b'c', b'h', b'e', b'.', b'k', b'e', b'y'],
                    b"jira".to_vec(),
                    b"elevancehealth".to_vec(),
                    b"com".to_vec(),
                ])
                .unwrap()
            )
        );
        assert!(!policy.matches_domain("_service.jira.notelevancehealth.com"));
    }

    #[test]
    fn wildcard_ip_and_malformed_domain_selectors_are_rejected() {
        for domain in [
            "*.anthem.com",
            "192.0.2.1",
            "[2001:db8::1]",
            "bad_label.example",
            "-bad.example",
            "anthem..com",
            ".",
        ] {
            assert!(
                SystemVpnPolicy::new(Vec::new(), vec![domain.to_string()]).is_err(),
                "selector unexpectedly accepted: {domain}"
            );
        }
    }

    #[test]
    fn serialized_policy_uses_normalized_cidr_and_domain_lists() {
        let policy = SystemVpnPolicy::new(
            vec!["10.20.4.7/16".parse().unwrap()],
            vec!["ANTHEM.COM".to_string()],
        )
        .unwrap();

        let encoded = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            encoded["include_cidrs"],
            serde_json::json!(["10.20.0.0/16"])
        );
        assert_eq!(
            encoded["include_domains"],
            serde_json::json!(["anthem.com"])
        );

        let decoded: SystemVpnPolicy = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn deserialization_enforces_domain_validation() {
        let result = serde_json::from_value::<SystemVpnPolicy>(serde_json::json!({
            "include_cidrs": [],
            "include_domains": ["*.example.com"]
        }));

        assert!(result.is_err());
    }
}
