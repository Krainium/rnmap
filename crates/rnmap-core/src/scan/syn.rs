//! TCP SYN ("half-open") scan via raw sockets. Linux/macOS only.
//! Requires root or CAP_NET_RAW.
//!
//! For each port:
//!   1. Build IP+TCP SYN packet with our source IP and a random ephemeral
//!      source port + sequence number.
//!   2. Send via raw IP socket (IPPROTO_TCP).
//!   3. Wait for response: SYN-ACK → open (we send a RST, not ACK).
//!      RST → closed. Timeout → filtered.

use crate::error::{Error, Result};
use crate::result::{PortResult, PortState, Protocol};
use crate::timing::Timing;
use crate::discovery::checksum16;
use rand::Rng;
use socket2::{Domain, Protocol as SockProto, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

/// Synchronous (blocking) SYN scan — we wrap with `spawn_blocking` higher up.
pub fn scan_blocking(target: Ipv4Addr, port: u16, timing: Timing) -> Result<PortResult> {
    let started = Instant::now();
    let src_ip = pick_source_ipv4_for(target)?;
    let src_port: u16 = rand::thread_rng().gen_range(32_768..=65_535);
    let seq: u32 = rand::thread_rng().gen();

    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(SockProto::TCP)).map_err(|e| {
        if e.raw_os_error() == Some(1) {
            Error::Privilege(format!("raw TCP socket: {}", e))
        } else {
            Error::Io(e)
        }
    })?;
    // We supply the IP header ourselves.
    sock.set_header_included_v4(true)?;
    sock.set_read_timeout(Some(timing.connect_timeout))?;
    sock.set_write_timeout(Some(timing.connect_timeout))?;

    let pkt = build_syn_packet(src_ip, target, src_port, port, seq);
    sock.send_to(&pkt, &SocketAddrV4::new(target, 0).into())?;

    // Read responses (raw socket gets all TCP traffic — filter for our 4-tuple).
    let deadline = started + timing.connect_timeout;
    loop {
        if Instant::now() >= deadline {
            return Ok(PortResult {
                port,
                protocol: Protocol::Tcp,
                state: PortState::Filtered,
                reason: "no-response".into(),
                service: None,
                rtt_ms: None,
            });
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        sock.set_read_timeout(Some(remaining.max(Duration::from_millis(50))))?;

        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
        match sock.recv(&mut buf) {
            Ok(n) => {
                let bytes: Vec<u8> = buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect();
                if let Some((src_p, dst_p, flags, _seq, _ack)) = parse_tcp_in_ipv4(&bytes, target, src_ip)
                {
                    if src_p == port && dst_p == src_port {
                        let rtt_ms = started.elapsed().as_millis() as u64;
                        if flags & 0x12 == 0x12 {
                            // SYN+ACK → open. Send a RST to be polite.
                            send_rst(&sock, src_ip, target, src_port, port, _ack);
                            return Ok(PortResult {
                                port,
                                protocol: Protocol::Tcp,
                                state: PortState::Open,
                                reason: "syn-ack".into(),
                                service: None,
                                rtt_ms: Some(rtt_ms),
                            });
                        } else if flags & 0x04 == 0x04 {
                            return Ok(PortResult {
                                port,
                                protocol: Protocol::Tcp,
                                state: PortState::Closed,
                                reason: "rst".into(),
                                service: None,
                                rtt_ms: Some(rtt_ms),
                            });
                        }
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // loop retries until deadline
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

fn send_rst(sock: &Socket, src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, ack_we_got: u32) {
    let mut p = build_tcp(src, dst, sp, dp, ack_we_got, 0, 0x04, 0); // RST
    let ip = build_ipv4(src, dst, &p);
    p = [ip, p].concat();
    let _ = sock.send_to(&p, &SocketAddrV4::new(dst, 0).into());
}

fn pick_source_ipv4_for(target: Ipv4Addr) -> Result<Ipv4Addr> {
    use std::net::UdpSocket;
    let probe = UdpSocket::bind("0.0.0.0:0").map_err(Error::Io)?;
    probe.connect((target, 1)).map_err(Error::Io)?;
    match probe.local_addr().map_err(Error::Io)?.ip() {
        IpAddr::V4(v) => Ok(v),
        IpAddr::V6(_) => Err(Error::Other("unexpected IPv6 local addr".into())),
    }
}

fn build_syn_packet(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, seq: u32) -> Vec<u8> {
    let tcp = build_tcp(src, dst, sp, dp, seq, 0, 0x02, 0xFFFF); // SYN, win=65535
    let ip = build_ipv4(src, dst, &tcp);
    [ip, tcp].concat()
}

fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len() as u16;
    let mut h = Vec::with_capacity(20);
    h.push(0x45); // ver=4, ihl=5
    h.push(0x00); // tos
    h.extend_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&rand::thread_rng().gen::<u16>().to_be_bytes()); // id
    h.extend_from_slice(&[0x40, 0x00]); // flags=DF, frag=0
    h.push(64); // ttl
    h.push(6);  // proto = TCP
    h.extend_from_slice(&[0, 0]); // checksum (kernel fills if not header-included; we fill anyway)
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let csum = checksum16(&h);
    h[10..12].copy_from_slice(&csum.to_be_bytes());
    h
}

fn build_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sp: u16,
    dp: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    win: u16,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(20);
    t.extend_from_slice(&sp.to_be_bytes());
    t.extend_from_slice(&dp.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.push(0x50); // data offset = 5 → 20 bytes
    t.push(flags);
    t.extend_from_slice(&win.to_be_bytes());
    t.extend_from_slice(&[0, 0]); // checksum placeholder
    t.extend_from_slice(&[0, 0]); // urgent ptr
    let csum = tcp_checksum(src, dst, &t);
    t[16..18].copy_from_slice(&csum.to_be_bytes());
    t
}

fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(6);
    buf.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp);
    if buf.len() % 2 != 0 {
        buf.push(0);
    }
    checksum16(&buf)
}

fn parse_tcp_in_ipv4(buf: &[u8], expect_src: Ipv4Addr, expect_dst: Ipv4Addr) -> Option<(u16, u16, u8, u32, u32)> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl + 20 || buf[9] != 6 {
        return None;
    }
    let s = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let d = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    if s != expect_src || d != expect_dst {
        return None;
    }
    let tcp = &buf[ihl..];
    let sp = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dp = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let flags = tcp[13];
    Some((sp, dp, flags, seq, ack))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn build_syn_is_40_bytes_minimum() {
        let pkt = build_syn_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            80,
            0xdeadbeef,
        );
        assert_eq!(pkt.len(), 40);
        // IP version+IHL
        assert_eq!(pkt[0], 0x45);
        // proto=TCP
        assert_eq!(pkt[9], 6);
        // SYN flag
        assert_eq!(pkt[20 + 13], 0x02);
    }
    #[test]
    fn tcp_checksum_self_consistent() {
        // Build then verify the checksum field validates back to 0
        let p = build_tcp(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            54321,
            22,
            0x11223344,
            0,
            0x02,
            65535,
        );
        let v = tcp_checksum(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            &p,
        );
        assert_eq!(v, 0); // re-checksum should be 0 because the field is now correct
    }
}
