use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid target spec `{0}`: {1}")]
    Target(String, String),

    #[error("invalid port spec `{0}`: {1}")]
    Ports(String, String),

    #[error("DNS resolution failed for `{0}`: {1}")]
    Dns(String, String),

    #[error("raw socket scan requires elevated privileges (root or CAP_NET_RAW): {0}")]
    Privilege(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("scan timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("output error: {0}")]
    Output(String),

    #[error("internal: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
