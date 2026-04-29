//! JSON output. Filters by `only_open` if requested, then serializes the report.

use crate::result::{PortState, ScanReport};

pub fn render(r: &ScanReport, only_open: bool) -> String {
    let mut copy = r.clone();
    if only_open {
        for h in &mut copy.hosts {
            h.ports.retain(|p| p.state == PortState::Open);
        }
    }
    serde_json::to_string_pretty(&copy).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
}
