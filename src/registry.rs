use std::path::PathBuf;

use oci_spec::{
    distribution::{ErrorResponse, TagList},
    image::{Arch, ImageConfiguration, ImageIndex, ImageIndexBuilder, ImageManifest, Os},
};
use reqwest::{header::HeaderValue, Client, Request, Response};
use tokio::{
    fs::{create_dir, File},
    io::AsyncWriteExt,
};

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
    pub fn new(base_url: &str) -> Self {
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

    async fn pull_raw_manifest_no_retry(
        &mut self,
        image: &str,
        tag: &str,
        refresh_token: bool,
    ) -> Result<String, OciRegistryError> {
        let request = self.get_request(
            format!("{}/{}/manifests/{}", self.base_url, image, tag).as_str(),
            media_type::MANIFEST,
        )?;

        let response = self.client.execute(request).await?;
        let response_code = response.status().as_u16();

        return match response_code {
            200 => Ok(response.text().await?),
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

    pub async fn pull_raw_manifest(
        &mut self,
        image: &str,
        tag: &str,
    ) -> Result<String, OciRegistryError> {
        return match self.pull_raw_manifest_no_retry(image, tag, true).await {
            Ok(raw_manifest) => Ok(raw_manifest),
            Err(_) => self.pull_raw_manifest_no_retry(image, tag, false).await,
        };
    }

    async fn pull_manifest_no_retry(
        &mut self,
        image: &str,
        tag: &str,
        refresh_token: bool,
    ) -> Result<ImageManifest, OciRegistryError> {
        let raw_manifest = self
            .pull_raw_manifest_no_retry(image, tag, refresh_token)
            .await?;

        Ok(serde_json::from_str(&raw_manifest)?)
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

    async fn configuration_response(
        &self,
        image: &str,
        digest: &str,
    ) -> Result<Response, OciRegistryError> {
        let request = self.request_from_digest(image, digest, media_type::CONFIGURATION)?;
        let response = self.client.execute(request).await?;

        Ok(response)
    }

    async fn pull_raw_configuration_no_retry(
        &mut self,
        image: &str,
        digest: &str,
        refresh_token: bool,
    ) -> Result<String, OciRegistryError> {
        let response = self.configuration_response(image, digest).await?;
        let response_code = response.status().as_u16();

        return match response_code {
            200 => Ok(response.text().await?),
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

    pub async fn pull_raw_configuration(
        &mut self,
        image: &str,
        digest: &str,
    ) -> Result<String, OciRegistryError> {
        return match self
            .pull_raw_configuration_no_retry(image, digest, true)
            .await
        {
            Ok(raw_configuration) => Ok(raw_configuration),
            Err(_) => {
                self.pull_raw_configuration_no_retry(image, digest, false)
                    .await
            }
        };
    }

    async fn pull_configuration_no_retry(
        &mut self,
        image: &str,
        digest: &str,
        refresh_token: bool,
    ) -> Result<ImageConfiguration, OciRegistryError> {
        let raw_configuration = self
            .pull_raw_configuration_no_retry(image, digest, refresh_token)
            .await?;

        Ok(serde_json::from_str(&raw_configuration)?)
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

    async fn pull_blob_no_retry(
        &mut self,
        image: &str,
        digest: &str,
        destination: &PathBuf,
        refresh_token: bool,
    ) -> Result<(), OciRegistryError> {
        let request = self.request_from_digest(image, &digest, media_type::LAYER)?;

        let response = self.client.execute(request).await?;
        let response_code = response.status().as_u16();

        return match response_code {
            200 => {
                File::create(destination)
                    .await?
                    .write_all(&response.bytes().await?)
                    .await?;

                return Ok(());
            }
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

    pub async fn pull_blob(
        &mut self,
        image: &str,
        digest: &str,
        destination: &PathBuf,
    ) -> Result<(), OciRegistryError> {
        return match self
            .pull_blob_no_retry(image, digest, destination, true)
            .await
        {
            Ok(blob) => Ok(blob),
            Err(_) => {
                self.pull_blob_no_retry(image, digest, destination, false)
                    .await
            }
        };
    }

    async fn list_tags_no_retry(
        &mut self,
        image: &str,
        refresh_token: bool,
    ) -> Result<TagList, OciRegistryError> {
        let request = self.get_request(
            format!("{}/{}/tags/list", self.base_url, image).as_str(),
            "*/*",
        )?;

        let response = self.client.execute(request).await?;
        let response_code = response.status().as_u16();

        return match response_code {
            200 => Ok(response.json::<TagList>().await?),
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

    pub async fn list_tags(&mut self, image: &str) -> Result<TagList, OciRegistryError> {
        return match self.list_tags_no_retry(image, true).await {
            Ok(tags) => Ok(tags),
            Err(_) => self.list_tags_no_retry(image, false).await,
        };
    }

    pub async fn pull_image(
        &mut self,
        image: &str,
        tag: &str,
        destination: &PathBuf,
    ) -> Result<(), OciRegistryError> {
        let oci_layout = r#"{"imageLayoutVersion": "1.0.0"}"#;
        File::create(destination.join("oci-layout"))
            .await?
            .write_all(oci_layout.as_bytes())
            .await?;

        let index = self.pull_index(image, tag).await?;
        let manifest = index
            .manifests()
            .into_iter()
            .find(|manifest| {
                let platform = manifest.platform();
                if let Some(platform) = platform {
                    return platform.architecture() == &Arch::Amd64 && platform.os() == &Os::Linux;
                }

                return false;
            })
            .unwrap()
            .clone();
        let index = ImageIndexBuilder::default()
            .annotations(index.annotations().clone().unwrap_or_default())
            .manifests(vec![manifest])
            .media_type(index.media_type().clone().unwrap())
            .schema_version(index.schema_version())
            .build()?;

        File::create(destination.join("index.json"))
            .await?
            .write_all(serde_json::to_string(&index)?.as_bytes())
            .await?;

        let blobs_path = destination.join("blobs");
        create_dir(&blobs_path).await?;

        let manifest_digest = index
            .manifests()
            .iter()
            .find(|manifest| {
                let platform = manifest.platform();
                if let Some(platform) = platform {
                    return platform.architecture() == &Arch::Amd64 && platform.os() == &Os::Linux;
                }

                return false;
            })
            .ok_or(OciRegistryError::AuthenticationError)?
            .digest();
        let raw_manifest = self.pull_raw_manifest(image, tag).await?;
        let manifest: ImageManifest = serde_json::from_str(&raw_manifest)?;
        let (alg, manifest_digest) = split_digest(manifest_digest)?;
        let alg_path = blobs_path.join(alg);

        if !alg_path.exists() {
            create_dir(&alg_path).await?;
        }

        File::create(alg_path.join(manifest_digest))
            .await?
            .write_all(serde_json::to_string(&manifest)?.as_bytes())
            .await?;

        let config_digest = manifest.config().digest();
        let raw_config = self.pull_raw_configuration(image, config_digest).await?;
        let (alg, config_digest) = split_digest(config_digest)?;
        let alg_path = blobs_path.join(alg);

        if !alg_path.exists() {
            create_dir(&alg_path).await?;
        }

        File::create(alg_path.join(config_digest))
            .await?
            .write_all(raw_config.as_bytes())
            .await?;

        for layer in manifest.layers() {
            let full_digest = layer.digest();
            let (alg, digest) = split_digest(full_digest)?;

            let alg_path = blobs_path.join(alg);

            if !alg_path.exists() {
                create_dir(&alg_path).await?;
            }

            self.pull_blob(image, full_digest, &alg_path.join(digest))
                .await?;
        }

        Ok(())
    }
}

fn split_digest<'a>(digest: &'a str) -> Result<(&'a str, &'a str), OciRegistryError> {
    digest
        .split_once(":")
        .ok_or(OciRegistryError::InvalidDigest(digest.to_string()))
}
