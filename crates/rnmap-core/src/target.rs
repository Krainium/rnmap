//! Target-spec parsing: hostname, IPv4/IPv6 literal, CIDR, simple ranges
//! (`10.0.0.1-50`), and lists thereof.

use crate::error::{Error, Result};
use ipnet::{IpNet, Ipv4Net};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct TargetSpec {
    /// Original input strings (one per CLI argument).
    pub inputs: Vec<String>,
    /// Resolved IP addresses, in order. (Hostnames resolved at parse time.)
    pub addrs: Vec<ResolvedHost>,
}

#[derive(Debug, Clone)]
pub struct ResolvedHost {
    /// User-facing label: hostname if given, else IP.
    pub label: String,
    pub ip: IpAddr,
}

impl TargetSpec {
    /// Parse and resolve every input. `resolve_dns=false` skips name lookup
    /// (will error on hostnames that aren't IPs).
    pub fn parse_many(inputs: &[String], resolve_dns: bool) -> Result<Self> {
        let mut all = Vec::new();
        for raw in inputs {
            for r in expand_one(raw, resolve_dns)? {
                all.push(r);
            }
        }
        if all.is_empty() {
            return Err(Error::Target(
                inputs.join(" "),
                "no targets resolved".into(),
            ));
        }
        Ok(TargetSpec {
            inputs: inputs.to_vec(),
            addrs: all,
        })
    }
}

fn expand_one(raw: &str, resolve_dns: bool) -> Result<Vec<ResolvedHost>> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(vec![]);
    }

    // CIDR (v4 or v6)
    if s.contains('/') {
        let net = IpNet::from_str(s)
            .map_err(|e| Error::Target(s.into(), format!("bad CIDR: {}", e)))?;
        let mut out = Vec::new();
        for ip in net.hosts() {
            out.push(ResolvedHost {
                label: ip.to_string(),
                ip,
            });
        }
        // hosts() excludes network/broadcast for v4 /<31; for /31 and /32 it includes both.
        // ipnet handles that correctly.
        if out.is_empty() {
            // /32 single host: hosts() returns just the one
            if let Ok(net4) = Ipv4Net::from_str(s) {
                out.push(ResolvedHost {
                    label: net4.network().to_string(),
                    ip: IpAddr::V4(net4.network()),
                });
            }
        }
        return Ok(out);
    }

    // IPv4 simple last-octet range: 10.0.0.5-25
    if let Some(r) = parse_v4_range(s)? {
        return Ok(r);
    }

    // bare IP literal
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(vec![ResolvedHost {
            label: s.into(),
            ip,
        }]);
    }

    // hostname
    if !resolve_dns {
        return Err(Error::Target(
            s.into(),
            "looks like a hostname but DNS resolution is disabled (-n)".into(),
        ));
    }
    let ips = dns_lookup::lookup_host(s).map_err(|e| Error::Dns(s.into(), e.to_string()))?;
    if ips.is_empty() {
        return Err(Error::Dns(s.into(), "no addresses".into()));
    }
    // Take the first address (prefer v4 if mixed).
    let chosen = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .copied()
        .unwrap_or(ips[0]);
    Ok(vec![ResolvedHost {
        label: s.into(),
        ip: chosen,
    }])
}

/// Parse `10.0.0.5-25` style IPv4 ranges. Returns None for non-matching strings,
/// Err for malformed ones.
fn parse_v4_range(s: &str) -> Result<Option<Vec<ResolvedHost>>> {
    // Must have exactly one '-' and three dots.
    let dash_count = s.matches('-').count();
    if dash_count != 1 {
        return Ok(None);
    }
    let (left, hi_s) = s.split_once('-').unwrap();
    let dots = left.matches('.').count();
    if dots != 3 {
        return Ok(None);
    }
    let lo_ip = match Ipv4Addr::from_str(left) {
        Ok(ip) => ip,
        Err(_) => return Ok(None),
    };
    let hi_octet: u8 = hi_s
        .trim()
        .parse()
        .map_err(|e| Error::Target(s.into(), format!("range high `{}`: {}", hi_s, e)))?;
    let lo_oct = lo_ip.octets();
    if hi_octet < lo_oct[3] {
        return Err(Error::Target(
            s.into(),
            format!("range high {} < low {}", hi_octet, lo_oct[3]),
        ));
    }
    let mut out = Vec::new();
    for last in lo_oct[3]..=hi_octet {
        let ip = Ipv4Addr::new(lo_oct[0], lo_oct[1], lo_oct[2], last);
        out.push(ResolvedHost {
            label: ip.to_string(),
            ip: IpAddr::V4(ip),
        });
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv4_literal() {
        let t = TargetSpec::parse_many(&["1.2.3.4".into()], false).unwrap();
        assert_eq!(t.addrs.len(), 1);
        assert_eq!(t.addrs[0].ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }
    #[test]
    fn ipv4_cidr_30() {
        let t = TargetSpec::parse_many(&["10.0.0.0/30".into()], false).unwrap();
        // /30 has 4 addrs but hosts() excludes network and broadcast → 2
        assert_eq!(t.addrs.len(), 2);
    }
    #[test]
    fn ipv4_range() {
        let t = TargetSpec::parse_many(&["10.0.0.5-7".into()], false).unwrap();
        let ips: Vec<_> = t.addrs.iter().map(|r| r.ip.to_string()).collect();
        assert_eq!(ips, vec!["10.0.0.5", "10.0.0.6", "10.0.0.7"]);
    }
    #[test]
    fn rejects_hostname_without_dns() {
        let r = TargetSpec::parse_many(&["example.com".into()], false);
        assert!(r.is_err());
    }
    #[test]
    fn rejects_bad_range() {
        let r = TargetSpec::parse_many(&["10.0.0.50-5".into()], false);
        assert!(r.is_err());
    }
}
