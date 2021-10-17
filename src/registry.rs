use std::{path::PathBuf, sync::Arc};

use futures::{future::join_all, StreamExt};
#[cfg(feature = "indicatif")]
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use oci_spec::{
    distribution::{RepositoryList, TagList},
    image::{Arch, ImageConfiguration, ImageIndex, ImageIndexBuilder, ImageManifest, Os},
};
use reqwest::Client;
use tokio::{
    fs::{create_dir, create_dir_all, File},
    io::AsyncWriteExt,
    task::JoinHandle,
};

use crate::{
    error::OciRegistryError,
    media_type,
    query_builder::{get, get_raw, get_stream, header_map},
    token::AuthResponse,
    www_auth::WWWAuth,
};

#[derive(Clone)]
pub struct Registry {
    base_url: String,
    client: Client,
}

impl Registry {
    pub fn new(base_url: &str) -> Self {
        let base_url = format!("{}/v2", base_url);

        let client = Client::new();

        Self { base_url, client }
    }

    async fn get_token(&self, url: &str) -> Result<Option<String>, OciRegistryError> {
        let request = self.client.head(url).build()?;

        let response = self.client.execute(request).await?;
        let response_code = response.status().as_u16();

        match response_code {
            200 => Ok(None),
            401 => {
                if let Some(www_auth_header) = response.headers().get("WWW-Authenticate") {
                    let www_auth = WWWAuth::parse(www_auth_header.to_str().unwrap());

                    let request = self
                        .client
                        .get(www_auth.realm)
                        .query(&www_auth.params)
                        .build()?;
                    let response = self.client.execute(request).await?;

                    if response.status().as_u16() != 200 {
                        return Err(OciRegistryError::AuthenticationError);
                    }

                    let token = response.json::<AuthResponse>().await?.token;

                    return Ok(Some(token));
                }

                Ok(None)
            }
            _ => unreachable!(),
        }
    }

    fn blob_url(&self, image: &str, digest: &str) -> String {
        format!(
            "{base_url}/{image}/blobs/{digest}",
            base_url = self.base_url,
            image = image,
            digest = digest
        )
    }

    pub async fn pull_raw_manifest(
        &self,
        image: &str,
        tag: &str,
    ) -> Result<String, OciRegistryError> {
        let url = format!(
            "{base_url}/{image}/manifests/{tag}",
            base_url = self.base_url,
            image = image,
            tag = tag
        );
        let token = self.get_token(&url).await?;
        let headers = header_map(token.as_deref(), Some(media_type::MANIFEST));

        let raw_manifest = get_raw(url.as_str(), Some(headers)).await.unwrap();
        Ok(raw_manifest)
    }

    pub async fn pull_manifest(
        &self,
        image: &str,
        tag: &str,
    ) -> Result<ImageManifest, OciRegistryError> {
        let raw_manifest = self.pull_raw_manifest(image, tag).await?;
        Ok(serde_json::from_str(&raw_manifest)?)
    }

    pub async fn pull_index(&self, image: &str, tag: &str) -> Result<ImageIndex, OciRegistryError> {
        let url = format!(
            "{base_url}/{image}/manifests/{tag}",
            base_url = self.base_url,
            image = image,
            tag = tag
        );
        let token = self.get_token(&url).await?;
        let headers = header_map(token.as_deref(), Some(media_type::INDEX));

        let index: ImageIndex = get(url.as_str(), Some(headers)).await.unwrap();
        Ok(index)
    }

    pub async fn pull_raw_configuration(
        &self,
        image: &str,
        digest: &str,
    ) -> Result<String, OciRegistryError> {
        let url = self.blob_url(image, digest);
        let token = self.get_token(&url).await?;
        let headers = header_map(token.as_deref(), Some(media_type::CONFIGURATION));

        let raw_configuration = get_raw(url.as_str(), Some(headers)).await.unwrap();
        Ok(raw_configuration)
    }

    pub async fn pull_configuration(
        &self,
        image: &str,
        digest: &str,
    ) -> Result<ImageConfiguration, OciRegistryError> {
        let raw_configuration = self.pull_raw_configuration(image, digest).await?;
        Ok(serde_json::from_str(&raw_configuration)?)
    }

    #[cfg(feature = "indicatif")]
    pub async fn pull_layer_with_progress_bar(
        &self,
        image: &str,
        digest: &str,
        destination: &PathBuf,
        progress_bar: ProgressBar,
    ) -> Result<(), OciRegistryError> {
        let url = self.blob_url(image, digest);
        let token = self.get_token(&url).await?;
        let headers = header_map(token.as_deref(), Some(media_type::LAYER));

        let (mut blob_stream, length) = get_stream(url.as_str(), Some(headers)).await.unwrap();
        let mut file = File::create(destination).await?;

        progress_bar.set_length(length);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n[{bar:50}] {bytes:9}/ {total_bytes}")
                .progress_chars("#>-"),
        );
        progress_bar.set_message(format!("Downloading {}", digest));

        let mut downloaded = 0;

        while let Some(item) = blob_stream.next().await {
            let chunk = item.unwrap();

            downloaded = std::cmp::min(length, downloaded + chunk.len() as u64);
            progress_bar.set_position(downloaded);

            file.write(&chunk).await.unwrap();
        }

        progress_bar.set_message(format!("Downloaded {}", digest));
        progress_bar.finish();

        return Ok(());
    }

    pub async fn pull_layer(
        &self,
        image: &str,
        digest: &str,
        destination: &PathBuf,
    ) -> Result<(), OciRegistryError> {
        let url = self.blob_url(image, digest);
        let token = self.get_token(&url).await?;
        let headers = header_map(token.as_deref(), Some(media_type::LAYER));

        let (mut blob_stream, _) = get_stream(url.as_str(), Some(headers)).await.unwrap();
        let mut file = File::create(destination).await?;

        while let Some(item) = blob_stream.next().await {
            let chunk = item.unwrap();
            file.write(&chunk).await.unwrap();
        }

        return Ok(());
    }

    pub async fn list_tags(&self, image: &str) -> Result<TagList, OciRegistryError> {
        let url = format!(
            "{base_url}/{image}/tags/list",
            base_url = self.base_url,
            image = image
        );
        let token = self.get_token(&url).await?;
        let headers = header_map(token.as_deref(), Some("*/*"));

        let tags: TagList = get(&url, Some(headers)).await.unwrap();
        Ok(tags)
    }

    pub async fn catalog(&self) -> Result<RepositoryList, OciRegistryError> {
        let url = format!("{base_url}/_catalog", base_url = self.base_url);
        let headers = header_map(None, Some("*/*"));

        let catalog: RepositoryList = get(&url, Some(headers)).await.unwrap();
        Ok(catalog)
    }

    pub async fn pull_image(
        &self,
        image: &str,
        tag: &str,
        os: &Os,
        arch: &Arch,
        destination: &PathBuf,
    ) -> Result<(), OciRegistryError> {
        if !destination.exists() {
            create_dir_all(&destination).await?;
        }

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
                    return platform.architecture() == arch && platform.os() == os;
                }

                return false;
            })
            .ok_or(OciRegistryError::UnknownError)?
            .clone();
        let index = ImageIndexBuilder::default()
            .annotations(index.annotations().clone().unwrap_or_default())
            .manifests(vec![manifest.clone()])
            .media_type(index.media_type().clone().unwrap())
            .schema_version(index.schema_version())
            .build()?;

        File::create(destination.join("index.json"))
            .await?
            .write_all(serde_json::to_string(&index)?.as_bytes())
            .await?;

        let blobs_path = destination.join("blobs");
        create_dir(&blobs_path).await?;

        let manifest_digest = manifest.digest();
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

        let mut tasks: Vec<JoinHandle<Result<(), OciRegistryError>>> = vec![];

        let blobs_path = Arc::new(blobs_path.clone());
        let image = Arc::new(image.to_string());

        for layer in manifest.layers() {
            let layer = layer.clone();
            let blobs_path = blobs_path.clone();
            let registry = self.clone();
            let image = image.clone();

            tasks.push(tokio::spawn(async move {
                let full_digest = layer.digest();
                let (alg, digest) = split_digest(full_digest)?;

                let alg_path = blobs_path.join(alg);

                if !alg_path.exists() {
                    create_dir(&alg_path).await?;
                }

                registry
                    .pull_layer(&image, full_digest, &alg_path.join(digest))
                    .await?;

                Ok::<(), OciRegistryError>(())
            }));
        }

        join_all(tasks).await;

        Ok(())
    }

    #[cfg(feature = "indicatif")]
    pub async fn pull_image_with_progress_bar(
        &self,
        image: &str,
        tag: &str,
        os: &Os,
        arch: &Arch,
        destination: &PathBuf,
    ) -> Result<(), OciRegistryError> {
        if !destination.exists() {
            create_dir_all(&destination).await?;
        }

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
                    return platform.architecture() == arch && platform.os() == os;
                }

                return false;
            })
            .ok_or(OciRegistryError::UnknownError)?
            .clone();
        let index = ImageIndexBuilder::default()
            .annotations(index.annotations().clone().unwrap_or_default())
            .manifests(vec![manifest.clone()])
            .media_type(index.media_type().clone().unwrap())
            .schema_version(index.schema_version())
            .build()?;

        File::create(destination.join("index.json"))
            .await?
            .write_all(serde_json::to_string(&index)?.as_bytes())
            .await?;

        let blobs_path = destination.join("blobs");
        create_dir(&blobs_path).await?;

        let manifest_digest = manifest.digest();
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

        let mut tasks: Vec<JoinHandle<Result<(), OciRegistryError>>> = vec![];

        let blobs_path = Arc::new(blobs_path.clone());
        let image = Arc::new(image.to_string());

        let multi = MultiProgress::new();

        for layer in manifest.layers() {
            let layer = layer.clone();
            let blobs_path = blobs_path.clone();
            let registry = self.clone();
            let image = image.clone();
            let progress_bar = multi.add(ProgressBar::new(layer.size() as u64));

            tasks.push(tokio::spawn(async move {
                let full_digest = layer.digest();
                let (alg, digest) = split_digest(full_digest)?;

                let alg_path = blobs_path.join(alg);

                if !alg_path.exists() {
                    create_dir(&alg_path).await?;
                }

                registry
                    .pull_layer_with_progress_bar(
                        &image,
                        full_digest,
                        &alg_path.join(digest),
                        progress_bar,
                    )
                    .await?;

                Ok::<(), OciRegistryError>(())
            }));
        }

        let handle_m = tokio::task::spawn_blocking(move || multi.join().unwrap());
        join_all(tasks).await;
        handle_m.await.unwrap();

        Ok(())
    }
}

fn split_digest<'a>(digest: &'a str) -> Result<(&'a str, &'a str), OciRegistryError> {
    digest
        .split_once(":")
        .ok_or(OciRegistryError::InvalidDigest(digest.to_string()))
}
