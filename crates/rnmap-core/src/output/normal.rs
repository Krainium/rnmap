//! Nmap-style human-readable text output.

use crate::result::{HostState, PortState, ScanReport};
use std::fmt::Write;

pub fn render(r: &ScanReport, only_open: bool) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# {} {} scan initiated {}",
        r.scanner,
        r.version,
        r.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    let _ = writeln!(s, "# args: {}", r.args.join(" "));
    let _ = writeln!(s);

    for h in &r.hosts {
        let host_disp = match (&h.hostname, h.address) {
            (Some(name), ip) => format!("{} ({})", name, ip),
            (None, ip) => ip.to_string(),
        };
        let _ = writeln!(
            s,
            "rnmap scan report for {}",
            host_disp
        );
        let _ = writeln!(
            s,
            "Host is {} ({})",
            match h.state {
                HostState::Up => "up",
                HostState::Down => "down",
                HostState::Unknown => "unknown",
            },
            h.reason
        );
        if h.state != HostState::Up {
            let _ = writeln!(s);
            continue;
        }

        let ports: Vec<_> = if only_open {
            h.ports.iter().filter(|p| p.state == PortState::Open).collect()
        } else {
            h.ports.iter().collect()
        };

        if ports.is_empty() {
            let _ = writeln!(s, "(no ports {})", if only_open { "open" } else { "scanned" });
        } else {
            let _ = writeln!(s, "PORT      STATE        SERVICE         VERSION");
            for p in &ports {
                let svc = p
                    .service
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or("-");
                let ver = p
                    .service
                    .as_ref()
                    .and_then(|s| {
                        s.product.as_ref().map(|prod| {
                            if let Some(v) = &s.version {
                                format!("{} {}", prod, v)
                            } else {
                                prod.clone()
                            }
                        })
                    })
                    .unwrap_or_default();
                let pp = format!("{}/{}", p.port, p.protocol);
                let _ = writeln!(s, "{:<10}{:<13}{:<16}{}", pp, p.state, svc, ver);
            }
        }
        let _ = writeln!(s);
    }

    let _ = writeln!(
        s,
        "# rnmap done: {} host{} scanned, {} up, {} open port{} in {:.2}s",
        r.host_count(),
        if r.host_count() == 1 { "" } else { "s" },
        r.up_count(),
        r.open_port_count(),
        if r.open_port_count() == 1 { "" } else { "s" },
        r.elapsed.as_secs_f64(),
    );
    s
}
