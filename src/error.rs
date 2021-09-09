use thiserror::Error;

#[derive(Error, Debug)]
pub enum OciRegistryError {
    #[error("reqwest error")]
    ReqwestError(#[from] reqwest::Error),
    #[error("registry error")]
    RegistryError(oci_spec::distribution::ErrorResponse),
    #[error("authentication error")]
    AuthenticationError,
    #[error("io operation error")]
    IoError(#[from] std::io::Error),
    #[error("serde error")]
    SerdeError(#[from] serde_json::Error),
    #[error("digest {0} is invalid")]
    InvalidDigest(String),
    #[error("oci-spec error")]
    OciSpecError(#[from] oci_spec::OciSpecError),
    #[error("unknown error")]
    UnknownError,
}
