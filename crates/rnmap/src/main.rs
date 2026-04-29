//! rnmap — CLI front-end for the rnmap-core scanner.
//!
//! Aims to mirror the most-used subset of Nmap's CLI flags so people coming
//! from nmap can pick it up with no learning curve.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::Parser;
use rnmap_core::{
    discovery, output, ports::PortSpec, result::*, scan::connect_scan, scan::syn, service,
    target::TargetSpec, timing::Timing, top_ports,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

#[derive(Parser, Debug)]
#[command(
    name = "rnmap",
    version,
    about = "Standalone Rust port scanner inspired by Nmap",
    long_about = "rnmap performs TCP connect / SYN port scans, host discovery, and lightweight \
                  service detection. Use --help for the full flag list."
)]
struct Cli {
    /// Targets: hostnames, IPs, CIDR (10.0.0.0/24), ranges (10.0.0.5-25)
    #[arg(value_name = "TARGET", num_args = 1..)]
    targets: Vec<String>,

    /// TCP connect scan (default if not root)
    #[arg(long = "sT", default_value_t = false)]
    s_t: bool,

    /// TCP SYN (half-open) scan; needs root / CAP_NET_RAW
    #[arg(long = "sS", default_value_t = false)]
    s_s: bool,

    /// Service / version detection on open ports
    #[arg(long = "sV", default_value_t = false)]
    s_v: bool,

    /// Skip host discovery — assume all targets are up
    #[arg(long = "Pn", default_value_t = false)]
    pn: bool,

    /// TCP-ping: list of ports to probe for liveness (comma-sep)
    #[arg(long = "PS", value_name = "PORTS")]
    ps: Option<String>,

    /// ICMP echo ping for liveness (root)
    #[arg(long = "PE", default_value_t = false)]
    pe: bool,

    /// Ports to scan: `22,80,443` or `1-1024` or `-` for all 65535
    #[arg(short = 'p', long = "ports")]
    ports: Option<String>,

    /// Scan the top N most common TCP ports
    #[arg(long = "top-ports", value_name = "N")]
    top_ports: Option<usize>,

    /// Timing template, 0 (paranoid) .. 5 (insane)
    #[arg(short = 'T', value_name = "0..5", default_value = "3")]
    timing: u8,

    /// Maximum concurrent in-flight probes (overrides timing)
    #[arg(short = 'c', long = "concurrency")]
    concurrency: Option<usize>,

    /// Disable reverse DNS lookup
    #[arg(short = 'n', long = "no-dns", default_value_t = false)]
    no_dns: bool,

    /// Verbose
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Show only open ports
    #[arg(long = "open", default_value_t = false)]
    open: bool,

    /// Write normal-format output to FILE
    #[arg(long = "oN", value_name = "FILE")]
    o_n: Option<PathBuf>,

    /// Write XML output to FILE
    #[arg(long = "oX", value_name = "FILE")]
    o_x: Option<PathBuf>,

    /// Write JSON output to FILE
    #[arg(long = "oJ", value_name = "FILE")]
    o_j: Option<PathBuf>,

    /// Write all formats with the given basename (.nmap, .xml, .json)
    #[arg(long = "oA", value_name = "BASENAME")]
    o_a: Option<PathBuf>,

    /// Maximum probe retries
    #[arg(long = "max-retries")]
    max_retries: Option<u32>,

    /// Per-host timeout in seconds (0 = none)
    #[arg(long = "host-timeout", value_name = "SECS")]
    host_timeout: Option<u64>,
}

/// Rewrite Nmap-style "single-dash compound" flags into the long form clap
/// expects. Nmap accepts `-Pn`, `-sS`, `-sV`, `-oA file`, etc. — all of which
/// look to clap like `-P n`, `-s S`, etc. We translate so the user-facing CLI
/// matches Nmap exactly.
fn rewrite_nmap_args(input: Vec<String>) -> Vec<String> {
    // Multi-char flags whose first letter is a "verb". Each gets `--` prepended.
    const NMAP_FLAGS: &[&str] = &[
        "Pn", "PE", "PS", "PA", "PU", "PR",
        "sS", "sT", "sU", "sV", "sN", "sF", "sX", "sA", "sW", "sM", "sO", "sY",
        "oN", "oX", "oJ", "oG", "oA", "oS",
    ];
    let mut out = Vec::with_capacity(input.len());
    for a in input {
        // `-Pn`, `-sV`, etc. (exactly 3 chars, leading '-')
        if a.len() == 3 && a.starts_with('-') && !a.starts_with("--") {
            let tail = &a[1..];
            if NMAP_FLAGS.contains(&tail) {
                out.push(format!("--{}", tail));
                continue;
            }
        }
        // `-PS22,80` style (flag + immediate value, no space)
        if a.len() > 3 && a.starts_with('-') && !a.starts_with("--") {
            let two = &a[1..3];
            if NMAP_FLAGS.contains(&two) {
                out.push(format!("--{}", two));
                out.push(a[3..].to_string());
                continue;
            }
        }
        out.push(a);
    }
    out
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let rewritten = rewrite_nmap_args(args.clone());
    let cli = Cli::parse_from(&rewritten);

    if cli.targets.is_empty() {
        return Err(anyhow!("no targets specified — try `rnmap --help`"));
    }

    // Pick scan mode
    let want_syn = cli.s_s;
    let _want_connect = cli.s_t || (!want_syn);

    // Resolve targets
    let targets =
        TargetSpec::parse_many(&cli.targets, !cli.no_dns).context("parsing targets")?;

    // Pick port set
    let port_spec = match (&cli.ports, cli.top_ports) {
        (Some(p), _) => PortSpec::parse(p).context("parsing -p ports")?,
        (None, Some(n)) => PortSpec {
            ports: top_ports::top_n(n),
        },
        (None, None) => PortSpec {
            ports: top_ports::top_n(100),
        },
    };

    // Build timing
    let mut timing = Timing::new(cli.timing);
    if let Some(c) = cli.concurrency {
        timing.max_parallel = c;
    }
    if let Some(r) = cli.max_retries {
        timing.max_retries = r;
    }
    if let Some(ht) = cli.host_timeout {
        timing.host_timeout = std::time::Duration::from_secs(ht);
    }

    let started_at = Utc::now();
    let started_inst = Instant::now();

    if cli.verbose > 0 {
        eprintln!(
            "rnmap: scanning {} host(s) × {} port(s) using {} scan, T{}, parallel={}",
            targets.addrs.len(),
            port_spec.len(),
            if want_syn { "SYN" } else { "connect" },
            timing.level,
            timing.max_parallel,
        );
    }

    let sem = Arc::new(Semaphore::new(timing.max_parallel.max(1)));
    let mut hosts = Vec::with_capacity(targets.addrs.len());

    for resolved in targets.addrs.iter() {
        let host_started = Utc::now();
        let host_started_i = Instant::now();

        // Discovery
        let (state, reason) = if cli.pn {
            (HostState::Up, "skipped".into())
        } else if cli.pe {
            match discovery::icmp_ping(resolved.ip, timing).await {
                Ok(o) => (o.state, o.reason),
                Err(e) => {
                    eprintln!("rnmap: ICMP ping failed for {}: {}", resolved.ip, e);
                    (HostState::Unknown, "icmp-error".into())
                }
            }
        } else {
            let probe_ports: Vec<u16> = match &cli.ps {
                Some(spec) => PortSpec::parse(spec)
                    .context("parsing -PS ports")?
                    .ports,
                None => vec![80, 443, 22, 3389],
            };
            let o = discovery::tcp_ping(resolved.ip, &probe_ports, timing).await;
            (o.state, o.reason)
        };

        if state != HostState::Up && !cli.pn {
            hosts.push(HostResult {
                address: resolved.ip,
                hostname: hostname_for(&resolved.label, resolved.ip),
                state,
                reason,
                ports: vec![],
                started_at: host_started,
                ended_at: Utc::now(),
                elapsed: host_started_i.elapsed(),
            });
            continue;
        }

        // Port scan
        let ports = port_spec.ports.clone();
        let mut futs = Vec::with_capacity(ports.len());
        for &port in &ports {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let ip = resolved.ip;
            let want_syn = want_syn;
            let timing_c = timing;
            futs.push(tokio::spawn(async move {
                let _p = permit;
                let r = if want_syn {
                    match ip {
                        IpAddr::V4(v4) => {
                            let res = tokio::task::spawn_blocking(move || {
                                syn::scan_blocking(v4, port, timing_c)
                            })
                            .await;
                            match res {
                                Ok(Ok(p)) => p,
                                Ok(Err(e)) => {
                                    if matches!(e, rnmap_core::Error::Privilege(_)) {
                                        eprintln!(
                                            "rnmap: SYN scan needs root; falling back to connect for {}:{}",
                                            ip, port
                                        );
                                    }
                                    connect_scan(ip, port, timing_c).await
                                }
                                Err(je) => {
                                    eprintln!("rnmap: scan task join error {}", je);
                                    connect_scan(ip, port, timing_c).await
                                }
                            }
                        }
                        IpAddr::V6(_) => connect_scan(ip, port, timing_c).await,
                    }
                } else {
                    connect_scan(ip, port, timing_c).await
                };
                r
            }));
        }

        let mut port_results: Vec<PortResult> = Vec::with_capacity(futs.len());
        for f in futs {
            if let Ok(r) = f.await {
                port_results.push(r);
            }
        }
        port_results.sort_by_key(|p| p.port);

        // Service detection on open ports
        if cli.s_v {
            for pr in port_results.iter_mut() {
                if pr.state == PortState::Open {
                    let addr = SocketAddr::new(resolved.ip, pr.port);
                    pr.service = service::detect(addr, timing).await;
                }
            }
        }

        let host = HostResult {
            address: resolved.ip,
            hostname: hostname_for(&resolved.label, resolved.ip),
            state: HostState::Up,
            reason,
            ports: port_results,
            started_at: host_started,
            ended_at: Utc::now(),
            elapsed: host_started_i.elapsed(),
        };

        if cli.verbose > 0 {
            let opens = host.ports.iter().filter(|p| p.state == PortState::Open).count();
            eprintln!(
                "rnmap: {} → {} open / {} scanned in {:.2}s",
                host.address,
                opens,
                host.ports.len(),
                host.elapsed.as_secs_f64()
            );
        }

        hosts.push(host);
    }

    let ended_at = Utc::now();
    let report = ScanReport {
        scanner: "rnmap".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        args: args.clone(),
        started_at,
        ended_at,
        elapsed: started_inst.elapsed(),
        hosts,
    };

    // Default to stdout normal-format unless -oA/-oN/-oX/-oJ.
    let any_file = cli.o_n.is_some() || cli.o_x.is_some() || cli.o_j.is_some() || cli.o_a.is_some();

    let normal = output::render(&report, output::OutputFormat::Normal, cli.open);
    if !any_file {
        print!("{}", normal);
    } else {
        print!("{}", normal);
    }

    if let Some(p) = &cli.o_a {
        std::fs::write(p.with_extension("nmap"), &normal)?;
        std::fs::write(
            p.with_extension("xml"),
            output::render(&report, output::OutputFormat::Xml, cli.open),
        )?;
        std::fs::write(
            p.with_extension("json"),
            output::render(&report, output::OutputFormat::Json, cli.open),
        )?;
    }
    if let Some(p) = &cli.o_n {
        std::fs::write(p, &normal)?;
    }
    if let Some(p) = &cli.o_x {
        std::fs::write(
            p,
            output::render(&report, output::OutputFormat::Xml, cli.open),
        )?;
    }
    if let Some(p) = &cli.o_j {
        std::fs::write(
            p,
            output::render(&report, output::OutputFormat::Json, cli.open),
        )?;
    }

    Ok(())
}

fn hostname_for(label: &str, ip: IpAddr) -> Option<String> {
    if label != ip.to_string() {
        Some(label.to_string())
    } else {
        // Try a quick reverse lookup; ignore failures.
        if ip == IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Some("localhost".into());
        }
        match dns_lookup_reverse(ip) {
            Some(h) => Some(h),
            None => None,
        }
    }
}

fn dns_lookup_reverse(ip: IpAddr) -> Option<String> {
    ::dns_lookup::lookup_addr(&ip).ok()
}
