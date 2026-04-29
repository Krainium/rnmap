//! Output renderers: `normal` (Nmap-style text), `xml` (subset of nmap XML), `json`.

pub mod normal;
pub mod xml;
pub mod json;

use crate::result::ScanReport;

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Normal,
    Xml,
    Json,
}

pub fn render(report: &ScanReport, fmt: OutputFormat, only_open: bool) -> String {
    match fmt {
        OutputFormat::Normal => normal::render(report, only_open),
        OutputFormat::Xml => xml::render(report, only_open),
        OutputFormat::Json => json::render(report, only_open),
    }
}
