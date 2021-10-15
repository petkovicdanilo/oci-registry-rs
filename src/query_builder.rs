use bytes::Bytes;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, Response, StatusCode,
};
use serde::de::DeserializeOwned;

pub async fn get<T>(url: &str, headers: Option<HeaderMap>) -> Result<T, StatusCode>
where
    T: DeserializeOwned,
{
    let response = execute_request(url, headers).await;

    match &response {
        Ok(r) => {
            if r.status() != StatusCode::OK {
                return Err(r.status());
            }
        }
        Err(e) => {
            if e.is_status() {
                return Err(e.status().unwrap());
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    let content = response.unwrap().json::<T>().await;

    match content {
        Ok(s) => Ok(s),
        Err(e) => {
            println!("{:?}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn get_raw(url: &str, headers: Option<HeaderMap>) -> Result<String, StatusCode> {
    let response = execute_request(url, headers).await;

    match &response {
        Ok(r) => {
            if r.status() != StatusCode::OK {
                println!("{:#?}", r.status());
                return Err(r.status());
            }
        }
        Err(e) => {
            if e.is_status() {
                return Err(e.status().unwrap());
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    let content = response.unwrap().text().await;

    match content {
        Ok(s) => Ok(s),
        Err(e) => {
            println!("{:?}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn get_stream(
    url: &str,
    headers: Option<HeaderMap>,
) -> Result<impl futures_core::Stream<Item = reqwest::Result<Bytes>>, StatusCode> {
    let response = execute_request(url, headers).await;

    match &response {
        Ok(r) => {
            if r.status() != StatusCode::OK {
                println!("{:#?}", r.status());
                return Err(r.status());
            }
        }
        Err(e) => {
            if e.is_status() {
                return Err(e.status().unwrap());
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    Ok(response.unwrap().bytes_stream())
}

async fn execute_request(
    url: &str,
    headers: Option<HeaderMap>,
) -> Result<Response, reqwest::Error> {
    let client = Client::new();

    let mut request_builder = client.get(url);

    if let Some(headers) = headers {
        request_builder = request_builder.headers(headers);
    }

    let request = request_builder.build().unwrap();
    client.execute(request).await
}

pub fn header_map(token: Option<&str>, accept: Option<&str>) -> HeaderMap {
    let mut header_map = HeaderMap::new();

    if let Some(token) = token {
        header_map.append(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}", token = token)).unwrap(),
        );
    }

    if let Some(accept) = accept {
        header_map.append("Accept", HeaderValue::from_str(accept).unwrap());
    }

    header_map
}
