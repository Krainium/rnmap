//! rnmap-core: scanning primitives, target/port parsing, output formats.
//!
//! All public surface is re-exported here so `rnmap-core::*` is enough.

pub mod error;
pub mod ports;
pub mod target;
pub mod timing;
pub mod result;
pub mod discovery;
pub mod service;
pub mod scan;
pub mod output;
pub mod top_ports;

pub use error::{Error, Result};
pub use ports::PortSpec;
pub use target::TargetSpec;
pub use timing::Timing;
pub use result::{HostResult, HostState, PortResult, PortState, Protocol, ScanReport, ServiceInfo};
