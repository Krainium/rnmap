//! End-to-end tests that bind a real listener and scan it.

use rnmap_core::{
    output, ports::PortSpec, result::*, scan::connect_scan, target::TargetSpec, timing::Timing,
};
use std::net::{IpAddr, Ipv4Addr, TcpListener};

#[tokio::test]
async fn end_to_end_connect_scan_open_and_closed() {
    // Open: bind a listener and keep it alive.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open_port = listener.local_addr().unwrap().port();

    // Closed: bind, get port, drop. RST should follow on connect.
    let scratch = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = scratch.local_addr().unwrap().port();
    drop(scratch);

    let timing = Timing::new(4);
    let r_open = connect_scan(IpAddr::V4(Ipv4Addr::LOCALHOST), open_port, timing).await;
    let r_closed = connect_scan(IpAddr::V4(Ipv4Addr::LOCALHOST), closed_port, timing).await;

    assert_eq!(r_open.state, PortState::Open);
    assert_eq!(r_closed.state, PortState::Closed);
    drop(listener);
}

#[tokio::test]
async fn report_serializes_to_json_and_round_trips() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let timing = Timing::new(4);
    let r = connect_scan(IpAddr::V4(Ipv4Addr::LOCALHOST), port, timing).await;
    drop(listener);

    let now = chrono::Utc::now();
    let report = ScanReport {
        scanner: "rnmap".into(),
        version: "0.1.0".into(),
        args: vec!["rnmap".into()],
        started_at: now,
        ended_at: now,
        elapsed: std::time::Duration::from_millis(1),
        hosts: vec![HostResult {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            hostname: Some("localhost".into()),
            state: HostState::Up,
            reason: "skipped".into(),
            ports: vec![r],
            started_at: now,
            ended_at: now,
            elapsed: std::time::Duration::from_millis(1),
        }],
    };
    let j = output::render(&report, output::OutputFormat::Json, false);
    let parsed: serde_json::Value = serde_json::from_str(&j).expect("json must parse");
    assert_eq!(parsed["scanner"], "rnmap");
    assert_eq!(parsed["hosts"][0]["ports"][0]["state"], "open");
}

#[tokio::test]
async fn target_and_port_specs_compose() {
    let t = TargetSpec::parse_many(&["127.0.0.1".into()], false).unwrap();
    let p = PortSpec::parse("80,443").unwrap();
    assert_eq!(t.addrs.len(), 1);
    assert_eq!(p.ports, vec![80, 443]);
}
