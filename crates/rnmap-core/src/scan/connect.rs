//! TCP connect() scan — works without elevated privileges.

use crate::result::{PortResult, PortState, Protocol};
use crate::timing::Timing;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn scan(ip: IpAddr, port: u16, timing: Timing) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    let mut last_err = None;

    for attempt in 0..=timing.max_retries {
        match timeout(timing.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                return PortResult {
                    port,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    reason: "syn-ack".into(),
                    service: None,
                    rtt_ms: Some(started.elapsed().as_millis() as u64),
                };
            }
            Ok(Err(e)) => {
                let kind = e.kind();
                if matches!(
                    kind,
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                ) {
                    return PortResult {
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::Closed,
                        reason: "conn-refused".into(),
                        service: None,
                        rtt_ms: Some(started.elapsed().as_millis() as u64),
                    };
                }
                last_err = Some(e.to_string());
            }
            Err(_) => {
                last_err = Some("timeout".into());
            }
        }
        if attempt < timing.max_retries {
            tokio::time::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1))).await;
        }
    }

    PortResult {
        port,
        protocol: Protocol::Tcp,
        state: PortState::Filtered,
        reason: last_err.unwrap_or_else(|| "no-response".into()),
        service: None,
        rtt_ms: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[tokio::test]
    async fn detects_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let r = scan(IpAddr::V4(Ipv4Addr::LOCALHOST), port, Timing::new(4)).await;
        assert_eq!(r.state, PortState::Open);
        drop(listener);
    }

    #[tokio::test]
    async fn detects_closed_port() {
        // Bind then drop to free the port; almost-immediately retry should get RST.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let r = scan(IpAddr::V4(Ipv4Addr::LOCALHOST), port, Timing::new(4)).await;
        assert_eq!(r.state, PortState::Closed);
    }
}
