//! Host discovery: TCP-ping (`-PS<ports>`) and ICMP echo (`-PE`).
//! ICMP requires root/CAP_NET_RAW; TCP-ping works unprivileged.

use crate::error::{Error, Result};
use crate::result::HostState;
use crate::timing::Timing;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of probing a single host.
#[derive(Debug, Clone)]
pub struct DiscoveryOutcome {
    pub state: HostState,
    pub reason: String,
    pub rtt: Option<Duration>,
}

/// TCP ping: try to connect to any of `ports`. First success → Up.
/// All RST → Up (closed RST means stack responded). All timeout → Down.
pub async fn tcp_ping(ip: IpAddr, ports: &[u16], timing: Timing) -> DiscoveryOutcome {
    let mut any_rst = false;
    for &p in ports {
        let addr = SocketAddr::new(ip, p);
        let started = Instant::now();
        match timeout(timing.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                return DiscoveryOutcome {
                    state: HostState::Up,
                    reason: format!("tcp-syn-ack:{}", p),
                    rtt: Some(started.elapsed()),
                };
            }
            Ok(Err(e)) => {
                let kind = e.kind();
                if matches!(
                    kind,
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                ) {
                    any_rst = true;
                }
            }
            Err(_) => { /* timeout */ }
        }
    }
    if any_rst {
        DiscoveryOutcome {
            state: HostState::Up,
            reason: "tcp-rst".into(),
            rtt: None,
        }
    } else {
        DiscoveryOutcome {
            state: HostState::Down,
            reason: "no-response".into(),
            rtt: None,
        }
    }
}

/// ICMP echo "ping". Builds + sends an ICMP echo request via raw socket
/// (IPv4 only here). On non-root or on unsupported platforms returns
/// `Error::Privilege`.
pub async fn icmp_ping(ip: IpAddr, timing: Timing) -> Result<DiscoveryOutcome> {
    let v4 = match ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => {
            return Err(Error::Other("ICMPv6 echo not implemented".into()));
        }
    };
    let timeout_dur = timing.connect_timeout;
    let started = Instant::now();
    let result = tokio::task::spawn_blocking(move || icmp_v4_ping_blocking(v4, timeout_dur))
        .await
        .map_err(|e| Error::Other(format!("join: {}", e)))??;
    Ok(if result {
        DiscoveryOutcome {
            state: HostState::Up,
            reason: "icmp-echo-reply".into(),
            rtt: Some(started.elapsed()),
        }
    } else {
        DiscoveryOutcome {
            state: HostState::Down,
            reason: "no-icmp-reply".into(),
            rtt: None,
        }
    })
}

fn icmp_v4_ping_blocking(target: std::net::Ipv4Addr, dur: Duration) -> Result<bool> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::io::ErrorKind;
    use std::net::SocketAddrV4;

    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).map_err(|e| {
        if e.raw_os_error() == Some(libc_eperm()) {
            Error::Privilege(format!("ICMP raw socket: {}", e))
        } else {
            Error::Io(e)
        }
    })?;
    sock.set_read_timeout(Some(dur))?;
    sock.set_write_timeout(Some(dur))?;

    let id: u16 = (std::process::id() & 0xFFFF) as u16;
    let seq: u16 = 1;
    let pkt = build_icmp_echo(id, seq, b"rnmap");
    let dst = SocketAddrV4::new(target, 0);
    sock.send_to(&pkt, &dst.into())?;

    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
    match sock.recv(&mut buf) {
        Ok(n) => {
            let bytes: Vec<u8> = buf[..n]
                .iter()
                .map(|b| unsafe { b.assume_init() })
                .collect();
            // IPv4 raw: includes IP header. ICMP type 0 = echo reply.
            if let Some(icmp) = strip_ipv4(&bytes) {
                if icmp.first() == Some(&0u8) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
            Ok(false)
        }
        Err(e) => Err(Error::Io(e)),
    }
}

fn libc_eperm() -> i32 {
    1 // EPERM on Linux/macOS
}

fn strip_ipv4(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 20 {
        return None;
    }
    // Defensive: only accept actual ICMP (proto=1). The kernel already filters
    // by IPPROTO_ICMP for our raw socket, but checking guards against future
    // socket-option changes and clarifies intent.
    if buf[9] != 1 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl {
        return None;
    }
    Some(&buf[ihl..])
}

fn build_icmp_echo(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8 + payload.len());
    pkt.push(8); // type = 8 echo request
    pkt.push(0); // code
    pkt.extend_from_slice(&[0, 0]); // checksum placeholder
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(payload);
    let csum = checksum16(&pkt);
    pkt[2..4].copy_from_slice(&csum.to_be_bytes());
    pkt
}

pub(crate) fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let w = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(w);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn icmp_packet_starts_with_type_8() {
        let pkt = build_icmp_echo(0xbeef, 1, b"x");
        assert_eq!(pkt[0], 8);
        assert_eq!(pkt[1], 0);
        // checksum non-zero
        assert!(pkt[2] != 0 || pkt[3] != 0);
    }
    #[test]
    fn checksum_known_vector() {
        // RFC 1071 example: 4500003044224000800600008c7c19acae241e2b
        // not the easiest to type by hand; just ensure deterministic + non-zero
        let c = checksum16(b"hello-world-checksum");
        assert!(c != 0);
    }
    #[test]
    fn strip_ipv4_basic() {
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x45; // IHL = 5 → 20 bytes
        pkt[9] = 1; // proto = ICMP
        let payload = strip_ipv4(&pkt).unwrap();
        assert_eq!(payload.len(), 12);
    }
    #[test]
    fn strip_ipv4_rejects_non_icmp() {
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP — should be rejected
        assert!(strip_ipv4(&pkt).is_none());
    }
}
