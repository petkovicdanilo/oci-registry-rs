use oci_spec::{
    distribution::ErrorResponse,
    image::{ImageConfiguration, ImageIndex, ImageManifest},
};
use reqwest::{header::HeaderValue, Client, Request};

use crate::{error::OciRegistryError, media_type, www_auth::WWWAuth};

pub enum RegistryType {
    Docker,
    Quay,
    Mcr,
    Other { base_url: String },
}

pub struct Registry {
    base_url: String,
    client: Client,
    token: Option<String>,
}

impl Registry {
    pub fn new(registry_type: RegistryType) -> Self {
        let base_url = match registry_type {
            RegistryType::Docker => String::from("https://registry-1.docker.io"),
            RegistryType::Quay => String::from("https://quay.io"),
            RegistryType::Mcr => String::from("https://mcr.microsoft.com"),
            RegistryType::Other { base_url } => base_url,
        };
        let base_url = format!("{}/v2", base_url);

        let client = Client::new();

        Self {
            base_url,
            client,
            token: None,
        }
    }

    async fn refresh_token(
        &mut self,
        www_auth_header: Option<&HeaderValue>,
    ) -> Result<(), OciRegistryError> {
        match www_auth_header {
            Some(www_auth_header) => {
                let www_auth_header = www_auth_header.to_str().unwrap();
                let www_auth = WWWAuth::parse(www_auth_header);

                let request = self
                    .client
                    .get(www_auth.realm)
                    .query(&www_auth.params)
                    .build()?;
                let response = self.client.execute(request).await?;

                if response.status().as_u16() != 200 {
                    return Err(OciRegistryError::AuthenticationError);
                }

                let token = response
                    .json::<serde_json::Value>()
                    .await?
                    .as_object()
                    .unwrap()
                    .get("token")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                self.token = Some(token);

                return Ok(());
            }
            None => return Err(OciRegistryError::AuthenticationError),
        }
    }

    fn get_request(&self, url: &str, media_type: &str) -> Result<Request, OciRegistryError> {
        let mut request_builder = self.client.get(url).header("Accept", media_type);

        if let Some(token) = &self.token {
            request_builder = request_builder.bearer_auth(token);
        }

        Ok(request_builder.build()?)
    }

    fn request_from_digest(
        &self,
        image: &str,
        digest: &str,
        media_type: &str,
    ) -> Result<Request, OciRegistryError> {
        self.get_request(
            format!("{}/{}/blobs/{}", self.base_url, image, digest).as_str(),
            media_type,
        )
    }

    async fn pull_manifest_no_retry(
        &mut self,
        image: &str,
        tag: &str,
        refresh_token: bool,
    ) -> Result<ImageManifest, OciRegistryError> {
        let request = self.get_request(
            format!("{}/{}/manifests/{}", self.base_url, image, tag).as_str(),
            media_type::MANIFEST,
        )?;

        let response = self.client.execute(request).await?;
        let response_code = response.status().as_u16();

        return match response_code {
            200 => Ok(response.json::<ImageManifest>().await?),
            _ => {
                if response_code == 401 && refresh_token {
                    self.refresh_token(response.headers().get("WWW-Authenticate"))
                        .await?;
                }

                let error_response = response.json::<ErrorResponse>().await?;
                Err(OciRegistryError::RegistryError(error_response))
            }
        };
    }

    pub async fn pull_manifest(
        &mut self,
        image: &str,
        tag: &str,
    ) -> Result<ImageManifest, OciRegistryError> {
        return match self.pull_manifest_no_retry(image, tag, true).await {
            Ok(manifest) => Ok(manifest),
            Err(_) => self.pull_manifest_no_retry(image, tag, false).await,
        };
    }

    async fn pull_index_no_retry(
        &mut self,
        image: &str,
        tag: &str,
        refresh_token: bool,
    ) -> Result<ImageIndex, OciRegistryError> {
        let request = self.get_request(
            format!("{}/{}/manifests/{}", self.base_url, image, tag).as_str(),
            media_type::INDEX,
        )?;

        let response = self.client.execute(request).await?;
        let response_code = response.status().as_u16();

        return match response_code {
            200 => Ok(response.json::<ImageIndex>().await?),
            _ => {
                if response_code == 401 && refresh_token {
                    self.refresh_token(response.headers().get("WWW-Authenticate"))
                        .await?;
                }

                let error_response = response.json::<ErrorResponse>().await?;
                Err(OciRegistryError::RegistryError(error_response))
            }
        };
    }

    pub async fn pull_index(
        &mut self,
        image: &str,
        tag: &str,
    ) -> Result<ImageIndex, OciRegistryError> {
        return match self.pull_index_no_retry(image, tag, true).await {
            Ok(index) => Ok(index),
            Err(_) => self.pull_index_no_retry(image, tag, false).await,
        };
    }

    async fn pull_configuration_no_retry(
        &mut self,
        image: &str,
        digest: &str,
        refresh_token: bool,
    ) -> Result<ImageConfiguration, OciRegistryError> {
        let request = self.request_from_digest(image, digest, media_type::CONFIGURATION)?;

        let response = self.client.execute(request).await?;
        let response_code = response.status().as_u16();

        return match response_code {
            200 => Ok(response.json::<ImageConfiguration>().await?),
            _ => {
                if response_code == 401 && refresh_token {
                    self.refresh_token(response.headers().get("WWW-Authenticate"))
                        .await?;
                }

                let error_response = response.json::<ErrorResponse>().await?;
                Err(OciRegistryError::RegistryError(error_response))
            }
        };
    }

    pub async fn pull_configuration(
        &mut self,
        image: &str,
        digest: &str,
    ) -> Result<ImageConfiguration, OciRegistryError> {
        return match self.pull_configuration_no_retry(image, digest, true).await {
            Ok(configuration) => Ok(configuration),
            Err(_) => self.pull_configuration_no_retry(image, digest, false).await,
        };
    }
}
