//! Scanner implementations.
//!
//! Two strategies:
//!   * `connect` — userspace TCP connect(); works without privileges.
//!   * `syn`     — raw SYN scan; needs CAP_NET_RAW / root.
//!
//! Higher-level orchestration (host loop, semaphore, retries, output) lives in
//! `crate::orchestrate` (declared via `engine`).

pub mod connect;
pub mod syn;

pub use connect::scan as connect_scan;
