//! Scan result data model. Designed to round-trip through normal/XML/JSON outputs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::Unfiltered => "unfiltered",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub reason: String,
    pub service: Option<ServiceInfo>,
    /// Round-trip time of the probe that determined state, in milliseconds.
    pub rtt_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub address: IpAddr,
    pub hostname: Option<String>,
    pub state: HostState,
    pub reason: String,
    pub ports: Vec<PortResult>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    #[serde(serialize_with = "ser_duration_secs", deserialize_with = "de_duration_secs")]
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanner: String,
    pub version: String,
    pub args: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    #[serde(serialize_with = "ser_duration_secs", deserialize_with = "de_duration_secs")]
    pub elapsed: Duration,
    pub hosts: Vec<HostResult>,
}

impl ScanReport {
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }
    pub fn up_count(&self) -> usize {
        self.hosts.iter().filter(|h| h.state == HostState::Up).count()
    }
    pub fn open_port_count(&self) -> usize {
        self.hosts
            .iter()
            .flat_map(|h| h.ports.iter())
            .filter(|p| p.state == PortState::Open)
            .count()
    }
}

fn ser_duration_secs<S: serde::Serializer>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_f64(d.as_secs_f64())
}
fn de_duration_secs<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Duration, D::Error> {
    use serde::Deserialize;
    let secs = f64::deserialize(d)?;
    Ok(Duration::from_secs_f64(secs.max(0.0)))
}
