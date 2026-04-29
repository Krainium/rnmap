//! Port-spec parsing: `22`, `1-1024`, `22,80,443`, `1-1024,3306,8000-8100`, `-` (all).

use crate::error::{Error, Result};
use std::collections::BTreeSet;

/// A parsed, deduped, sorted set of ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub ports: Vec<u16>,
}

impl PortSpec {
    pub fn parse(spec: &str) -> Result<Self> {
        let raw = spec.trim();
        if raw.is_empty() {
            return Err(Error::Ports(spec.into(), "empty".into()));
        }
        if raw == "-" {
            return Ok(PortSpec {
                ports: (1u16..=65535).collect(),
            });
        }
        let mut set: BTreeSet<u16> = BTreeSet::new();
        for chunk in raw.split(',') {
            let c = chunk.trim();
            if c.is_empty() {
                continue;
            }
            if let Some((lo_s, hi_s)) = c.split_once('-') {
                let lo_s = lo_s.trim();
                let hi_s = hi_s.trim();
                let lo: u32 = if lo_s.is_empty() { 1 } else { parse_u16(spec, lo_s)? as u32 };
                let hi: u32 = if hi_s.is_empty() { 65535 } else { parse_u16(spec, hi_s)? as u32 };
                if lo == 0 || hi == 0 {
                    return Err(Error::Ports(spec.into(), "port 0 is not valid".into()));
                }
                if lo > hi {
                    return Err(Error::Ports(
                        spec.into(),
                        format!("range {} > {}", lo, hi),
                    ));
                }
                for p in lo..=hi {
                    set.insert(p as u16);
                }
            } else {
                let p = parse_u16(spec, c)?;
                if p == 0 {
                    return Err(Error::Ports(spec.into(), "port 0 is not valid".into()));
                }
                set.insert(p);
            }
        }
        if set.is_empty() {
            return Err(Error::Ports(spec.into(), "no ports parsed".into()));
        }
        Ok(PortSpec {
            ports: set.into_iter().collect(),
        })
    }

    pub fn len(&self) -> usize {
        self.ports.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
}

fn parse_u16(spec: &str, raw: &str) -> Result<u16> {
    raw.parse::<u16>()
        .map_err(|e| Error::Ports(spec.into(), format!("invalid port `{}`: {}", raw, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn single() {
        assert_eq!(PortSpec::parse("22").unwrap().ports, vec![22]);
    }
    #[test]
    fn range() {
        assert_eq!(PortSpec::parse("80-82").unwrap().ports, vec![80, 81, 82]);
    }
    #[test]
    fn list() {
        assert_eq!(PortSpec::parse("22,80,443").unwrap().ports, vec![22, 80, 443]);
    }
    #[test]
    fn mixed() {
        let p = PortSpec::parse("22,80-82,443").unwrap();
        assert_eq!(p.ports, vec![22, 80, 81, 82, 443]);
    }
    #[test]
    fn dedup_sort() {
        let p = PortSpec::parse("443,22,80,22,80").unwrap();
        assert_eq!(p.ports, vec![22, 80, 443]);
    }
    #[test]
    fn dash_all() {
        let p = PortSpec::parse("-").unwrap();
        assert_eq!(p.ports.len(), 65535);
        assert_eq!(p.ports[0], 1);
        assert_eq!(*p.ports.last().unwrap(), 65535);
    }
    #[test]
    fn open_ranges() {
        let p = PortSpec::parse("-1024").unwrap();
        assert_eq!(p.ports.len(), 1024);
        assert_eq!(p.ports[0], 1);
        let p = PortSpec::parse("65500-").unwrap();
        assert_eq!(p.ports[0], 65500);
        assert_eq!(*p.ports.last().unwrap(), 65535);
    }
    #[test]
    fn rejects_zero() {
        assert!(PortSpec::parse("0").is_err());
        assert!(PortSpec::parse("0-10").is_err());
    }
    #[test]
    fn rejects_reverse() {
        assert!(PortSpec::parse("100-50").is_err());
    }
    #[test]
    fn rejects_garbage() {
        assert!(PortSpec::parse("abc").is_err());
        assert!(PortSpec::parse("").is_err());
    }
}
