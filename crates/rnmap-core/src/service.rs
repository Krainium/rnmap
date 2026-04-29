//! Lightweight service / version detection.
//!
//! For each open TCP port we:
//!   1. Connect.
//!   2. Read up to 1KB for a passive banner (with timeout).
//!   3. If nothing, send a tiny protocol-appropriate probe based on the port's
//!      well-known service (HTTP for 80/8080, TLS-ish hello for 443, etc.) and
//!      read again.
//!   4. Match the banner against a small built-in regex table to extract
//!      `name`, `product`, `version`.
//!
//! This is **not** a port of nmap-service-probes (12k entries). It identifies
//! the most common services people care about: SSH, HTTP, HTTPS, FTP, SMTP,
//! POP3, IMAP, MySQL, PostgreSQL, Redis, MongoDB, RDP, VNC.

use crate::result::ServiceInfo;
use crate::timing::Timing;
use once_cell::sync::Lazy;
use regex::Regex;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const READ_BUF: usize = 4096;

pub async fn detect(addr: SocketAddr, timing: Timing) -> Option<ServiceInfo> {
    let mut stream = match timeout(timing.connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let banner = match timeout(timing.read_timeout, read_some(&mut stream)).await {
        Ok(Ok(b)) if !b.is_empty() => b,
        _ => match send_probe_for(addr.port(), &mut stream, timing).await {
            Some(b) => b,
            None => Vec::new(),
        },
    };

    let banner_str = String::from_utf8_lossy(&banner).to_string();
    let trimmed = banner_str.trim_end_matches(|c: char| c == '\0').to_string();
    let svc = guess_from_banner(addr.port(), &trimmed);

    Some(ServiceInfo {
        name: svc.0,
        product: svc.1,
        version: svc.2,
        banner: if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.chars().take(256).collect())
        },
    })
}

async fn read_some(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; READ_BUF];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

async fn send_probe_for(port: u16, stream: &mut TcpStream, timing: Timing) -> Option<Vec<u8>> {
    match port {
        80 | 8080 | 8000 | 8888 | 81 | 591 | 8008 | 8081 => {
            send_and_read(stream, b"GET / HTTP/1.0\r\nHost: rnmap\r\nUser-Agent: rnmap/0.1\r\n\r\n", timing.read_timeout).await
        }
        25 | 587 => send_and_read(stream, b"EHLO rnmap.local\r\n", timing.read_timeout).await,
        110 => send_and_read(stream, b"QUIT\r\n", timing.read_timeout).await,
        143 => send_and_read(stream, b"a001 CAPABILITY\r\n", timing.read_timeout).await,
        21 => send_and_read(stream, b"\r\n", timing.read_timeout).await,
        // For SSH / others, banner is server-first; a longer wait sometimes helps.
        _ => {
            tokio::time::sleep(Duration::from_millis(150)).await;
            timeout(timing.read_timeout, read_some(stream)).await.ok()?.ok()
        }
    }
}

async fn send_and_read(stream: &mut TcpStream, payload: &[u8], dur: Duration) -> Option<Vec<u8>> {
    let _ = timeout(dur, stream.write_all(payload)).await.ok()?;
    let _ = stream.flush().await;
    let r = timeout(dur, read_some(stream)).await.ok()?;
    r.ok()
}

/// (name, product, version)
type Guess = (String, Option<String>, Option<String>);

fn guess_from_banner(port: u16, banner: &str) -> Guess {
    static SSH: Lazy<Regex> = Lazy::new(|| Regex::new(r"^SSH-(\d+\.\d+)-([^\s\r\n]+)").unwrap());
    static HTTP_SERVER: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?im)^Server:\s*([^\r\n]+)").unwrap());
    static FTP: Lazy<Regex> = Lazy::new(|| Regex::new(r"^220[ \-](.+)").unwrap());
    static SMTP: Lazy<Regex> = Lazy::new(|| Regex::new(r"^220[ \-]([^\r\n]+)").unwrap());
    static MYSQL: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.\x00\x00\x00.([0-9][^\x00]+)").unwrap());
    static REDIS: Lazy<Regex> = Lazy::new(|| Regex::new(r"redis_version:([0-9.]+)").unwrap());
    static POSTGRES: Lazy<Regex> = Lazy::new(|| Regex::new(r"^FATAL").unwrap()); // pg refuses without proto
    static VNC: Lazy<Regex> = Lazy::new(|| Regex::new(r"^RFB (\d{3})\.(\d{3})").unwrap());
    static IMAP: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\* OK[^\r\n]*").unwrap());
    static POP3: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\+OK[^\r\n]*").unwrap());

    if let Some(c) = SSH.captures(banner) {
        let prod_ver = c.get(2).map(|m| m.as_str().to_string());
        let (product, version) = split_product_version(prod_ver.as_deref().unwrap_or(""));
        return ("ssh".into(), product, version);
    }

    if banner.starts_with("HTTP/") || banner.contains("\r\nServer:") || banner.contains("\nServer:") {
        let server = HTTP_SERVER
            .captures(banner)
            .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()));
        let (product, version) = match &server {
            Some(s) => split_product_version(s),
            None => (None, None),
        };
        return ("http".into(), product, version);
    }

    if let Some(c) = FTP.captures(banner) {
        let detail = c.get(1).map(|m| m.as_str().trim().to_string());
        let (product, version) = match &detail {
            Some(s) => split_product_version(s),
            None => (None, None),
        };
        return ("ftp".into(), product, version);
    }

    // SMTP and FTP banners both start with 220; differentiate by port hint.
    if SMTP.is_match(banner) && (port == 25 || port == 587 || port == 465) {
        let detail = SMTP.captures(banner).and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        let (product, version) = match &detail {
            Some(s) => split_product_version(s.trim()),
            None => (None, None),
        };
        return ("smtp".into(), product, version);
    }

    if MYSQL.is_match(banner) || port == 3306 {
        let v = MYSQL
            .captures(banner)
            .and_then(|c| c.get(1).map(|m| m.as_str().split('-').next().unwrap_or("").to_string()));
        return ("mysql".into(), Some("MySQL".into()), v);
    }

    if REDIS.is_match(banner) || port == 6379 {
        let v = REDIS.captures(banner).and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        return ("redis".into(), Some("Redis".into()), v);
    }

    if POSTGRES.is_match(banner) || port == 5432 {
        return ("postgresql".into(), Some("PostgreSQL".into()), None);
    }

    if let Some(c) = VNC.captures(banner) {
        let v = format!("{}.{}", &c[1], &c[2]);
        return ("vnc".into(), Some("RFB".into()), Some(v));
    }

    if IMAP.is_match(banner) || port == 143 || port == 993 {
        return ("imap".into(), None, None);
    }
    if POP3.is_match(banner) || port == 110 || port == 995 {
        return ("pop3".into(), None, None);
    }

    let name = match port {
        443 => "https",
        53 => "dns",
        3389 => "rdp",
        27017 => "mongodb",
        _ => "unknown",
    };
    (name.into(), None, None)
}

fn split_product_version(s: &str) -> (Option<String>, Option<String>) {
    // "OpenSSH_9.9p1" or "OpenSSH_9.9p1 Ubuntu-3ubuntu3.2"
    // Split on first underscore or first space. Heuristic.
    let s = s.trim();
    if s.is_empty() {
        return (None, None);
    }
    if let Some((p, v)) = s.split_once('_') {
        return (Some(p.to_string()), Some(v.split_whitespace().next().unwrap_or("").to_string()));
    }
    if let Some((p, v)) = s.split_once('/') {
        return (Some(p.to_string()), Some(v.split_whitespace().next().unwrap_or("").to_string()));
    }
    if let Some(idx) = s.find(char::is_whitespace) {
        let (p, rest) = s.split_at(idx);
        return (Some(p.to_string()), Some(rest.trim().split_whitespace().next().unwrap_or("").to_string()));
    }
    (Some(s.to_string()), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssh_banner() {
        let g = guess_from_banner(22, "SSH-2.0-OpenSSH_9.9p1 Ubuntu-3ubuntu3.2\r\n");
        assert_eq!(g.0, "ssh");
        assert_eq!(g.1.as_deref(), Some("OpenSSH"));
        assert_eq!(g.2.as_deref(), Some("9.9p1"));
    }
    #[test]
    fn http_banner() {
        let resp = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n";
        let g = guess_from_banner(80, resp);
        assert_eq!(g.0, "http");
        assert_eq!(g.1.as_deref(), Some("nginx"));
        assert_eq!(g.2.as_deref(), Some("1.25.3"));
    }
    #[test]
    fn ftp_banner() {
        let g = guess_from_banner(21, "220 vsftpd 3.0.5 ready.\r\n");
        assert_eq!(g.0, "ftp");
    }
    #[test]
    fn unknown_port_no_banner() {
        let g = guess_from_banner(31337, "");
        assert_eq!(g.0, "unknown");
    }
    #[test]
    fn fallback_by_port() {
        assert_eq!(guess_from_banner(443, "").0, "https");
        assert_eq!(guess_from_banner(3389, "").0, "rdp");
        assert_eq!(guess_from_banner(5432, "").0, "postgresql");
    }
}
