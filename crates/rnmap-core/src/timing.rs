//! Nmap-style timing templates T0..T5. Maps to concurrency, per-host
//! parallelism, connect timeout, and read timeout.

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub level: u8,
    /// Total number of concurrent in-flight scan tasks.
    pub max_parallel: usize,
    /// TCP connect / SYN response timeout.
    pub connect_timeout: Duration,
    /// Banner read timeout for service detection.
    pub read_timeout: Duration,
    /// Maximum retries for a probe.
    pub max_retries: u32,
    /// Per-target host timeout (overall, 0 = none).
    pub host_timeout: Duration,
}

impl Timing {
    pub fn new(level: u8) -> Self {
        match level {
            0 => Self {
                level: 0,
                max_parallel: 1,
                connect_timeout: Duration::from_secs(15),
                read_timeout: Duration::from_secs(10),
                max_retries: 5,
                host_timeout: Duration::ZERO,
            },
            1 => Self {
                level: 1,
                max_parallel: 5,
                connect_timeout: Duration::from_secs(10),
                read_timeout: Duration::from_secs(8),
                max_retries: 3,
                host_timeout: Duration::ZERO,
            },
            2 => Self {
                level: 2,
                max_parallel: 30,
                connect_timeout: Duration::from_secs(5),
                read_timeout: Duration::from_secs(5),
                max_retries: 2,
                host_timeout: Duration::ZERO,
            },
            3 => Self {
                level: 3,
                max_parallel: 100,
                connect_timeout: Duration::from_secs(3),
                read_timeout: Duration::from_secs(3),
                max_retries: 2,
                host_timeout: Duration::ZERO,
            },
            4 => Self {
                level: 4,
                max_parallel: 300,
                connect_timeout: Duration::from_millis(1500),
                read_timeout: Duration::from_secs(2),
                max_retries: 1,
                host_timeout: Duration::ZERO,
            },
            _ => Self {
                level: 5,
                max_parallel: 1000,
                connect_timeout: Duration::from_millis(800),
                read_timeout: Duration::from_secs(1),
                max_retries: 1,
                host_timeout: Duration::from_secs(900),
            },
        }
    }
}

impl Default for Timing {
    fn default() -> Self {
        Timing::new(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn levels_increase_parallelism() {
        let p: Vec<_> = (0u8..=5).map(|l| Timing::new(l).max_parallel).collect();
        for w in p.windows(2) {
            assert!(w[1] > w[0], "parallelism should increase: {:?}", p);
        }
    }
    #[test]
    fn levels_decrease_timeout() {
        let t: Vec<_> = (0u8..=5).map(|l| Timing::new(l).connect_timeout).collect();
        for w in t.windows(2) {
            assert!(w[1] <= w[0]);
        }
    }
}
