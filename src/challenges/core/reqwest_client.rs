//! Reqwest-based implementation of the `ChallengeHttpClient` trait.
//!
//! Provides a thin adapter around `reqwest::Client` that converts between the
//! shared HTTP representations used by the solver core and the concrete
//! transport.

use std::sync::Arc;

use async_trait::async_trait;
use http::{
    HeaderMap as HttpHeaderMap, HeaderName as HttpHeaderName, HeaderValue as HttpHeaderValue,
    Method as HttpMethod,
};
use reqwest::cookie::Jar;
use reqwest::{Client, Method, header::HeaderMap, redirect::Policy};
use url::Url;

use super::{
    ChallengeExecutionError, ChallengeHttpClient, ChallengeHttpClientError, ChallengeHttpResponse,
};

/// Reqwest-backed HTTP client used during challenge replay.
pub struct ReqwestChallengeHttpClient {
    client: Client,
}

impl ReqwestChallengeHttpClient {
    /// Creates a new client with redirects disabled so the executor can inspect
    /// redirect responses explicitly.
    pub fn new() -> Result<Self, ChallengeExecutionError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .cookie_store(true)
            .build()
            .map_err(|err| {
                ChallengeExecutionError::Client(ChallengeHttpClientError::Transport(
                    err.to_string(),
                ))
            })?;

        Ok(Self { client })
    }

    /// Creates a client that shares `jar` as its cookie store.
    ///
    /// Sharing a single jar with the main request client is essential: cookies
    /// issued while solving a challenge (e.g. `cf_clearance`) are written to the
    /// same store the caller can later read, and are replayed on subsequent
    /// requests. Redirects stay disabled so the executor can inspect 30x
    /// responses (which often carry the clearance `Set-Cookie`) explicitly.
    pub fn with_jar(jar: Arc<Jar>) -> Result<Self, ChallengeExecutionError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .cookie_provider(jar)
            .build()
            .map_err(|err| {
                ChallengeExecutionError::Client(ChallengeHttpClientError::Transport(
                    err.to_string(),
                ))
            })?;

        Ok(Self { client })
    }

    /// Wrap an existing reqwest client. The client should already have
    /// redirects disabled; otherwise redirects will be followed automatically
    /// and the executor will not observe the intermediate 30x response.
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestChallengeHttpClient {
    fn default() -> Self {
        Self::new().expect("failed to create reqwest challenge client")
    }
}

#[async_trait]
impl ChallengeHttpClient for ReqwestChallengeHttpClient {
    async fn send_form(
        &self,
        method: &HttpMethod,
        url: &Url,
        headers: &HttpHeaderMap,
        form_fields: &std::collections::HashMap<String, String>,
        _allow_redirects: bool,
    ) -> Result<ChallengeHttpResponse, ChallengeHttpClientError> {
        let req_method = map_method(method)?;
        let req_headers = convert_headers(headers)?;

        let response = self
            .client
            .request(req_method, url.as_str())
            .headers(req_headers)
            .form(form_fields)
            .send()
            .await
            .map_err(|err| ChallengeHttpClientError::Transport(err.to_string()))?;

        Ok(to_challenge_response(response).await?)
    }

    async fn send_with_body(
        &self,
        method: &HttpMethod,
        url: &Url,
        headers: &HttpHeaderMap,
        body: Option<&[u8]>,
        _allow_redirects: bool,
    ) -> Result<ChallengeHttpResponse, ChallengeHttpClientError> {
        let req_method = map_method(method)?;
        let req_headers = convert_headers(headers)?;

        let mut builder = self
            .client
            .request(req_method, url.as_str())
            .headers(req_headers);

        if let Some(data) = body {
            builder = builder.body(data.to_vec());
        }

        let response = builder
            .send()
            .await
            .map_err(|err| ChallengeHttpClientError::Transport(err.to_string()))?;

        Ok(to_challenge_response(response).await?)
    }
}

fn map_method(method: &HttpMethod) -> Result<Method, ChallengeHttpClientError> {
    Method::from_bytes(method.as_str().as_bytes())
        .map_err(|err| ChallengeHttpClientError::Transport(err.to_string()))
}

fn convert_headers(headers: &HttpHeaderMap) -> Result<HeaderMap, ChallengeHttpClientError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|err| ChallengeHttpClientError::Transport(err.to_string()))?;
        let value = reqwest::header::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|err| ChallengeHttpClientError::Transport(err.to_string()))?;
        map.insert(name, value);
    }
    Ok(map)
}

async fn to_challenge_response(
    response: reqwest::Response,
) -> Result<ChallengeHttpResponse, ChallengeHttpClientError> {
    let status = response.status().as_u16();
    let headers = convert_back_headers(response.headers())?;
    let url = response.url().clone();
    let is_redirect = response.status().is_redirection();
    let body = response
        .bytes()
        .await
        .map_err(|err| ChallengeHttpClientError::Transport(err.to_string()))?
        .to_vec();

    Ok(ChallengeHttpResponse {
        status,
        headers,
        body,
        url,
        is_redirect,
    })
}

fn convert_back_headers(map: &HeaderMap) -> Result<HttpHeaderMap, ChallengeHttpClientError> {
    let mut headers = HttpHeaderMap::new();
    for (name, value) in map.iter() {
        let http_name = HttpHeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|err| ChallengeHttpClientError::Transport(err.to_string()))?;
        let http_value = HttpHeaderValue::from_bytes(value.as_bytes())
            .map_err(|err| ChallengeHttpClientError::Transport(err.to_string()))?;
        headers.insert(http_name, http_value);
    }
    Ok(headers)
}

type _AssertSync = Arc<ReqwestChallengeHttpClient>;
