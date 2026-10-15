use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("resolve: {0}")]
    Resolve(String),

    #[error("tls: {0}")]
    Tls(String),

    #[error("quic: {0}")]
    Quic(String),

    #[error("http3: {0}")]
    Http3(String),

    #[error("auth: {0}")]
    Auth(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("closed")]
    Closed,

    /// 서버가 같은 기기의 새 연결에 넘겨 이 연결을 닫았다(SUPERSEDED_ERROR_CODE).
    #[error("superseded by another connection of the same device")]
    Superseded,
}

impl Error {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn tls(message: impl Into<String>) -> Self {
        Self::Tls(message.into())
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
