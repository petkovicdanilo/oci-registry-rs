use thiserror::Error;

#[derive(Error, Debug)]
pub enum OciRegistryError {
    #[error("reqwest error")]
    ReqwestError(#[from] reqwest::Error),
    #[error("registry error")]
    RegistryError(oci_spec::distribution::ErrorResponse),
    #[error("authentication error")]
    AuthenticationError,
}
