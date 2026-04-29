//! Subset of Nmap's XML schema. Compatible with most nmap-XML parsers
//! (e.g. `python-libnmap`) for the elements we emit.

use crate::result::{HostState, PortState, ScanReport};
use std::fmt::Write;

pub fn render(r: &ScanReport, only_open: bool) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let _ = writeln!(
        s,
        "<rnmaprun scanner=\"{}\" version=\"{}\" args=\"{}\" start=\"{}\">",
        x(&r.scanner),
        x(&r.version),
        x(&r.args.join(" ")),
        r.started_at.timestamp()
    );

    for h in &r.hosts {
        let _ = writeln!(s, "  <host>");
        let _ = writeln!(
            s,
            "    <status state=\"{}\" reason=\"{}\"/>",
            match h.state {
                HostState::Up => "up",
                HostState::Down => "down",
                HostState::Unknown => "unknown",
            },
            x(&h.reason)
        );
        let _ = writeln!(
            s,
            "    <address addr=\"{}\" addrtype=\"{}\"/>",
            h.address,
            if h.address.is_ipv4() { "ipv4" } else { "ipv6" }
        );
        if let Some(name) = &h.hostname {
            let _ = writeln!(s, "    <hostnames>");
            let _ = writeln!(
                s,
                "      <hostname name=\"{}\" type=\"user\"/>",
                x(name)
            );
            let _ = writeln!(s, "    </hostnames>");
        }
        let _ = writeln!(s, "    <ports>");
        for p in &h.ports {
            if only_open && p.state != PortState::Open {
                continue;
            }
            let _ = writeln!(
                s,
                "      <port protocol=\"{}\" portid=\"{}\">",
                p.protocol, p.port
            );
            let _ = writeln!(
                s,
                "        <state state=\"{}\" reason=\"{}\"/>",
                p.state,
                x(&p.reason)
            );
            if let Some(svc) = &p.service {
                let mut attrs = format!(" name=\"{}\"", x(&svc.name));
                if let Some(pr) = &svc.product {
                    attrs.push_str(&format!(" product=\"{}\"", x(pr)));
                }
                if let Some(v) = &svc.version {
                    attrs.push_str(&format!(" version=\"{}\"", x(v)));
                }
                let _ = writeln!(s, "        <service{}/>", attrs);
            }
            let _ = writeln!(s, "      </port>");
        }
        let _ = writeln!(s, "    </ports>");
        let _ = writeln!(s, "  </host>");
    }

    let _ = writeln!(
        s,
        "  <runstats><finished time=\"{}\" elapsed=\"{:.3}\"/><hosts up=\"{}\" total=\"{}\"/></runstats>",
        r.ended_at.timestamp(),
        r.elapsed.as_secs_f64(),
        r.up_count(),
        r.host_count()
    );
    let _ = writeln!(s, "</rnmaprun>");
    s
}

fn x(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
