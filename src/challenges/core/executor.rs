//! Challenge submission execution utilities.
//!
//! Handles the end-to-end process of submitting the IUAM payload, honoring
//! Cloudflare's required delay, following redirects, and surfacing meaningful
//! errors back to the caller.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::Method;
use http::header::{HeaderMap, HeaderName, HeaderValue, LOCATION, REFERER};
use thiserror::Error;
use tokio::time::sleep;
use url::Url;

use super::types::ChallengeSubmission;

/// Contract that abstracts the underlying HTTP transport used during challenge replay.
///
/// Implementations should ensure that cookies and other stateful data are
/// preserved between calls so the session behaves consistently.
#[async_trait]
pub trait ChallengeHttpClient: Send + Sync {
    async fn send_form(
        &self,
        method: &Method,
        url: &Url,
        headers: &HeaderMap,
        form_fields: &HashMap<String, String>,
        allow_redirects: bool,
    ) -> Result<ChallengeHttpResponse, ChallengeHttpClientError>;

    async fn send_with_body(
        &self,
        method: &Method,
        url: &Url,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        allow_redirects: bool,
    ) -> Result<ChallengeHttpResponse, ChallengeHttpClientError>;
}

/// Minimal response representation returned by the transport abstraction.
#[derive(Debug, Clone)]
pub struct ChallengeHttpResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub url: Url,
    pub is_redirect: bool,
}

impl ChallengeHttpResponse {
    pub fn location(&self) -> Option<&str> {
        self.headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
    }
}

#[derive(Debug, Error)]
pub enum ChallengeHttpClientError {
    #[error("http transport error: {0}")]
    Transport(String),
}

/// Failure states that can occur while executing the Cloudflare challenge flow.
#[derive(Debug, Error)]
pub enum ChallengeExecutionError {
    #[error("failed to convert header '{0}'")]
    InvalidHeader(String),
    #[error("invalid challenge answer detected")]
    InvalidAnswer,
    #[error("http client error: {0}")]
    Client(#[from] ChallengeHttpClientError),
}

/// Context about the original request that triggered the challenge.
#[derive(Debug, Clone)]
pub struct OriginalRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
}

impl OriginalRequest {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_body(mut self, body: Option<Vec<u8>>) -> Self {
        self.body = body;
        self
    }
}

/// Executes the Cloudflare response submission for IUAM-style challenges.
///
/// Submission steps:
/// 1. Wait the enforced delay duration.
/// 2. POST the computed payload back to Cloudflare.
/// 3. If the response is a redirect, follow it manually (respecting relative URLs).
/// 4. Return the final response so callers can resume normal processing.
pub async fn execute_challenge_submission(
    client: Arc<dyn ChallengeHttpClient>,
    submission: ChallengeSubmission,
    original_request: OriginalRequest,
) -> Result<ChallengeHttpResponse, ChallengeExecutionError> {
    if submission.wait > Duration::from_millis(0) {
        sleep(submission.wait).await;
    }

    let submission_headers = convert_headers(&submission.headers)?;
    let first_response = client
        .send_form(
            &submission.method,
            &submission.url,
            &submission_headers,
            &submission.form_fields,
            submission.allow_redirects,
        )
        .await?;

    if first_response.status == 400 {
        return Err(ChallengeExecutionError::InvalidAnswer);
    }

    if !first_response.is_redirect {
        return Ok(first_response);
    }

    let redirect_target = resolve_redirect(&first_response, &original_request.url);
    let mut follow_headers = original_request.headers.clone();
    follow_headers.insert(
        REFERER,
        HeaderValue::from_str(first_response.url.as_str())
            .map_err(|_| ChallengeExecutionError::InvalidHeader("referer".into()))?,
    );

    let follow_response = client
        .send_with_body(
            &original_request.method,
            &redirect_target,
            &follow_headers,
            original_request.body.as_deref(),
            true,
        )
        .await?;

    Ok(follow_response)
}

fn convert_headers(
    headers: &HashMap<String, String>,
) -> Result<HeaderMap, ChallengeExecutionError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ChallengeExecutionError::InvalidHeader(name.clone()))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| ChallengeExecutionError::InvalidHeader(name.clone()))?;
        map.insert(header_name, header_value);
    }
    Ok(map)
}

fn resolve_redirect(first_response: &ChallengeHttpResponse, original_url: &Url) -> Url {
    if let Some(location) = first_response.location() {
        if let Ok(absolute) = Url::parse(location)
            && absolute.has_host()
        {
            return absolute;
        }

        if let Ok(joined) = first_response.url.join(location) {
            return joined;
        }
    }

    original_url.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StubClient {
        responses: Mutex<Vec<ChallengeHttpResponse>>,
    }

    impl StubClient {
        fn new(responses: Vec<ChallengeHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().rev().collect()),
            }
        }

        fn pop_response(&self) -> ChallengeHttpResponse {
            self.responses
                .lock()
                .unwrap()
                .pop()
                .expect("no more stub responses")
        }
    }

    #[async_trait]
    impl ChallengeHttpClient for StubClient {
        async fn send_form(
            &self,
            _method: &Method,
            _url: &Url,
            _headers: &HeaderMap,
            _form_fields: &HashMap<String, String>,
            _allow_redirects: bool,
        ) -> Result<ChallengeHttpResponse, ChallengeHttpClientError> {
            Ok(self.pop_response())
        }

        async fn send_with_body(
            &self,
            _method: &Method,
            _url: &Url,
            _headers: &HeaderMap,
            _body: Option<&[u8]>,
            _allow_redirects: bool,
        ) -> Result<ChallengeHttpResponse, ChallengeHttpClientError> {
            Ok(self.pop_response())
        }
    }

    fn make_response(status: u16, url: &str, headers: HeaderMap) -> ChallengeHttpResponse {
        ChallengeHttpResponse {
            status,
            headers,
            body: vec![],
            url: Url::parse(url).unwrap(),
            is_redirect: (300..400).contains(&status),
        }
    }

    #[tokio::test]
    async fn returns_first_response_when_not_redirect() {
        let submission = ChallengeSubmission::new(
            Method::POST,
            Url::parse("https://example.com/submit").unwrap(),
            HashMap::from([(String::from("foo"), String::from("bar"))]),
            HashMap::from([(String::from("referer"), String::from("https://example.com"))]),
            Duration::from_millis(0),
        );

        let original =
            OriginalRequest::new(Method::GET, Url::parse("https://example.com").unwrap());

        let headers = HeaderMap::new();
        let client = Arc::new(StubClient::new(vec![make_response(
            200,
            "https://example.com",
            headers.clone(),
        )]));

        let response = execute_challenge_submission(client, submission, original)
            .await
            .unwrap();

        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn follows_redirect_and_returns_final_response() {
        let submission = ChallengeSubmission::new(
            Method::POST,
            Url::parse("https://example.com/submit").unwrap(),
            HashMap::from([(String::from("foo"), String::from("bar"))]),
            HashMap::from([(String::from("referer"), String::from("https://example.com"))]),
            Duration::from_millis(0),
        );

        let mut original_headers = HeaderMap::new();
        original_headers.insert("user-agent", HeaderValue::from_static("test-agent"));

        let original = OriginalRequest::new(
            Method::GET,
            Url::parse("https://example.com/protected").unwrap(),
        )
        .with_headers(original_headers.clone());

        let mut redirect_headers = HeaderMap::new();
        redirect_headers.insert(LOCATION, HeaderValue::from_static("/redirected"));

        let client = Arc::new(StubClient::new(vec![
            make_response(200, "https://example.com/redirected", HeaderMap::new()),
            make_response(302, "https://example.com/submit", redirect_headers),
        ]));

        let response = execute_challenge_submission(client, submission, original)
            .await
            .unwrap();

        assert_eq!(response.url.as_str(), "https://example.com/redirected");
    }
}
