//! Solver for Cloudflare JavaScript VM challenge v2.
//!
//! Extracts orchestration metadata embedded in the challenge page, prepares the
//! expected payload (including optional hCaptcha tokens), and relies on the
//! shared executor to perform the delayed submission.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use html_escape::decode_html_entities;
use once_cell::sync::Lazy;
use rand::Rng;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use thiserror::Error;

use crate::challenges::core::{
    ChallengeExecutionError, ChallengeHttpClient, ChallengeHttpResponse, ChallengeResponse,
    ChallengeSubmission, OriginalRequest, execute_challenge_submission, is_cloudflare_response,
    origin_from_url,
};
use crate::external_deps::captcha::{CaptchaError, CaptchaProvider, CaptchaTask};

/// Default minimum random wait (seconds) before submitting the response.
const DEFAULT_DELAY_MIN_SECS: f32 = 1.0;
/// Default maximum random wait (seconds) before submitting the response.
const DEFAULT_DELAY_MAX_SECS: f32 = 5.0;

/// Solver capable of handling Cloudflare VM (v2) JavaScript challenges.
pub struct JavascriptV2Solver {
    delay_min: Duration,
    delay_max: Duration,
    captcha_provider: Option<Arc<dyn CaptchaProvider>>, // optional hCaptcha provider
}

impl JavascriptV2Solver {
    /// Create a solver with default delay range (1-5 seconds) and no captcha provider.
    pub fn new() -> Self {
        Self {
            delay_min: Duration::from_secs_f32(DEFAULT_DELAY_MIN_SECS),
            delay_max: Duration::from_secs_f32(DEFAULT_DELAY_MAX_SECS),
            captcha_provider: None,
        }
    }

    /// Configure the random delay range applied before challenge submission.
    pub fn with_delay_range(mut self, min: Duration, max: Duration) -> Self {
        self.delay_min = min;
        self.delay_max = if max < min { min } else { max };
        self
    }

    /// Attach an hCaptcha provider that will be used when captcha challenges are detected.
    pub fn with_captcha_provider(mut self, provider: Arc<dyn CaptchaProvider>) -> Self {
        self.captcha_provider = Some(provider);
        self
    }

    /// Set (or replace) the captcha provider after construction.
    pub fn set_captcha_provider(&mut self, provider: Arc<dyn CaptchaProvider>) {
        self.captcha_provider = Some(provider);
    }

    /// Remove any configured captcha provider.
    pub fn clear_captcha_provider(&mut self) {
        self.captcha_provider = None;
    }

    /// Returns `true` when the response matches the Cloudflare v2 JavaScript challenge signature.
    pub fn is_js_challenge(response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && matches!(response.status, 403 | 429 | 503)
            && JS_CHALLENGE_RE.is_match(response.body)
    }

    /// Returns `true` when the response corresponds to the Cloudflare v2 hCaptcha flow.
    pub fn is_captcha_challenge(response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && response.status == 403
            && CAPTCHA_CHALLENGE_RE.is_match(response.body)
    }

    /// Build the challenge submission payload for non-captcha VM challenges.
    pub fn solve(
        &self,
        response: &ChallengeResponse<'_>,
    ) -> Result<ChallengeSubmission, JavascriptV2Error> {
        if !Self::is_js_challenge(response) {
            return Err(JavascriptV2Error::NotV2Challenge);
        }

        let info = Self::extract_challenge_info(response.body)?;
        let payload = Self::generate_payload(response.body, &info.options)?;
        self.build_submission(response, &info.form_action, payload)
    }

    /// Build the challenge submission payload for captcha-protected VM challenges.
    pub async fn solve_with_captcha(
        &self,
        response: &ChallengeResponse<'_>,
    ) -> Result<ChallengeSubmission, JavascriptV2Error> {
        if !Self::is_captcha_challenge(response) {
            return Err(JavascriptV2Error::NotCaptchaChallenge);
        }

        let provider = self
            .captcha_provider
            .as_ref()
            .ok_or(JavascriptV2Error::CaptchaProviderMissing)?;

        let info = Self::extract_challenge_info(response.body)?;
        let mut payload = Self::generate_payload(response.body, &info.options)?;

        let site_key = Self::extract_site_key(response.body)
            .ok_or(JavascriptV2Error::MissingToken("data-sitekey"))?;

        let mut task = CaptchaTask::new(site_key, response.url.clone());
        // Preserve challenge-specific context for providers that can use it.
        if let Some(cv_id) = info.options.cv_id.as_ref() {
            task = task.insert_metadata("cv_id", cv_id.clone());
        }

        let solution = provider
            .solve(&task)
            .await
            .map_err(JavascriptV2Error::Captcha)?;
        payload.insert("h-captcha-response".into(), solution.token);
        for (key, value) in solution.metadata {
            payload.insert(key, value);
        }

        self.build_submission(response, &info.form_action, payload)
    }

    /// Execute the full challenge flow, including waiting and submission.
    pub async fn solve_and_submit(
        &self,
        client: Arc<dyn ChallengeHttpClient>,
        response: &ChallengeResponse<'_>,
        original_request: OriginalRequest,
    ) -> Result<ChallengeHttpResponse, JavascriptV2Error> {
        let submission = if Self::is_captcha_challenge(response) {
            self.solve_with_captcha(response).await?
        } else {
            self.solve(response)?
        };

        execute_challenge_submission(client, submission, original_request)
            .await
            .map_err(JavascriptV2Error::Submission)
    }

    fn build_submission(
        &self,
        response: &ChallengeResponse<'_>,
        form_action: &str,
        mut payload: HashMap<String, String>,
    ) -> Result<ChallengeSubmission, JavascriptV2Error> {
        let action = decode_html_entities(form_action).into_owned();
        let target_url = response
            .url
            .join(&action)
            .map_err(|err| JavascriptV2Error::InvalidFormAction(action.clone(), err))?;

        // Ensure required fields exist even if the upstream payload omitted them.
        payload
            .entry("cf_ch_verify".into())
            .or_insert_with(|| "plat".into());
        payload.entry("vc".into()).or_default();
        payload.entry("captcha_vc".into()).or_default();
        payload
            .entry("cf_captcha_kind".into())
            .or_insert_with(|| "h".into());
        payload.entry("h-captcha-response".into()).or_default();

        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        headers.insert("Referer".into(), response.url.as_str().to_string());
        headers.insert("Origin".into(), origin_from_url(response.url));

        let wait = self.random_delay();
        let submission =
            ChallengeSubmission::new(http::Method::POST, target_url, payload, headers, wait);
        Ok(submission)
    }

    fn random_delay(&self) -> Duration {
        if self.delay_max <= self.delay_min {
            return self.delay_min;
        }
        let mut rng = rand::thread_rng();
        let min = self.delay_min.as_secs_f32();
        let max = self.delay_max.as_secs_f32();
        let secs = rng.gen_range(min..=max);
        Duration::from_secs_f32(secs)
    }

    fn extract_challenge_info(body: &str) -> Result<ChallengeInfo, JavascriptV2Error> {
        let options = Self::extract_challenge_options(body)?;
        let form_action = Self::extract_form_action(body)?;
        Ok(ChallengeInfo {
            options,
            form_action,
        })
    }

    fn extract_challenge_options(body: &str) -> Result<ChallengeOptions, JavascriptV2Error> {
        let captures = CHL_OPT_RE
            .captures(body)
            .and_then(|caps| caps.get(1))
            .ok_or(JavascriptV2Error::ChallengeDataMissing)?;
        let json = captures.as_str();
        let options: ChallengeOptions = serde_json::from_str(json)?;
        Ok(options)
    }

    fn extract_form_action(body: &str) -> Result<String, JavascriptV2Error> {
        let action = FORM_ACTION_RE
            .captures(body)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or(JavascriptV2Error::FormActionMissing)?;
        Ok(action)
    }

    fn generate_payload(
        body: &str,
        options: &ChallengeOptions,
    ) -> Result<HashMap<String, String>, JavascriptV2Error> {
        let r_token = R_TOKEN_RE
            .captures(body)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or(JavascriptV2Error::MissingToken("r"))?;

        let mut payload = HashMap::new();
        payload.insert("r".into(), r_token);
        if let Some(cv_id) = options.cv_id.as_ref() {
            payload.insert("cv_chal_id".into(), cv_id.clone());
        }
        if let Some(page_data) = options.chl_page_data.as_ref() {
            payload.insert("cf_chl_page_data".into(), page_data.clone());
        }
        Ok(payload)
    }

    fn extract_site_key(body: &str) -> Option<String> {
        SITE_KEY_RE
            .captures(body)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
}

impl Default for JavascriptV2Solver {
    fn default() -> Self {
        Self::new()
    }
}

impl super::ChallengeSolver for JavascriptV2Solver {
    fn name(&self) -> &'static str {
        "javascript_v2"
    }
}

#[derive(Debug, Deserialize)]
struct ChallengeOptions {
    #[serde(rename = "cvId")]
    cv_id: Option<String>,
    #[serde(rename = "chlPageData")]
    chl_page_data: Option<String>,
    #[serde(flatten)]
    _extra: serde_json::Value,
}

struct ChallengeInfo {
    options: ChallengeOptions,
    form_action: String,
}

#[derive(Debug, Error)]
pub enum JavascriptV2Error {
    #[error("response is not a Cloudflare v2 challenge")]
    NotV2Challenge,
    #[error("response is not a Cloudflare v2 captcha challenge")]
    NotCaptchaChallenge,
    #[error("required challenge data missing")]
    ChallengeDataMissing,
    #[error("challenge form action missing")]
    FormActionMissing,
    #[error("missing token '{0}' in challenge page")]
    MissingToken(&'static str),
    #[error("challenge data could not be parsed: {0}")]
    ChallengeDataParse(#[from] serde_json::Error),
    #[error("invalid form action '{0}': {1}")]
    InvalidFormAction(String, url::ParseError),
    #[error("captcha provider not configured")]
    CaptchaProviderMissing,
    #[error("captcha solving failed: {0}")]
    Captcha(#[source] CaptchaError),
    #[error("challenge submission failed: {0}")]
    Submission(#[source] ChallengeExecutionError),
}

// Regular expressions reused across the solver.
static JS_CHALLENGE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"cpo\.src\s*=\s*['"]/cdn-cgi/challenge-platform/\S+orchestrate/jsch/v1"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid JS challenge regex")
});

static CAPTCHA_CHALLENGE_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r#"cpo\.src\s*=\s*['"]/cdn-cgi/challenge-platform/\S+orchestrate/(captcha|managed)/v1"#,
    )
    .case_insensitive(true)
    .dot_matches_new_line(true)
    .build()
    .expect("invalid captcha challenge regex")
});

static CHL_OPT_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"window\._cf_chl_opt=\((\{[^;]+\})\);"#)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid _cf_chl_opt regex")
});

static FORM_ACTION_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"<form[^>]+id=['"]challenge-form['"][^>]*action=['"]([^'"]+)['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid form action regex")
});

static R_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"name=['"]r['"]\s+value=['"]([^'"]+)['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid r token regex")
});

static SITE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"data-sitekey=['"]([^'"]+)['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid site key regex")
});

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use http::{HeaderMap, Method, header::SERVER};
    use url::Url;

    use crate::external_deps::captcha::{CaptchaResult, CaptchaSolution};

    struct ResponseFixture {
        url: Url,
        headers: HeaderMap,
        method: Method,
        body: String,
        status: u16,
    }

    impl ResponseFixture {
        fn new(body: &str, status: u16) -> Self {
            let mut headers = HeaderMap::new();
            headers.insert(SERVER, "cloudflare".parse().unwrap());
            Self {
                url: Url::parse("https://example.com/").unwrap(),
                headers,
                method: Method::GET,
                body: body.to_string(),
                status,
            }
        }

        fn response(&self) -> ChallengeResponse<'_> {
            ChallengeResponse {
                url: &self.url,
                status: self.status,
                headers: &self.headers,
                body: &self.body,
                request_method: &self.method,
            }
        }
    }

    struct StubCaptchaProvider;

    #[async_trait]
    impl CaptchaProvider for StubCaptchaProvider {
        fn name(&self) -> &'static str {
            "stub"
        }

        async fn solve(&self, _task: &CaptchaTask) -> CaptchaResult {
            Ok(CaptchaSolution::new("captcha-token"))
        }
    }

    fn sample_html(include_captcha: bool) -> String {
        let orchestrate_path = if include_captcha {
            "/cdn-cgi/challenge-platform/h/b/orchestrate/captcha/v1"
        } else {
            "/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1"
        };
        let captcha_snippet = if include_captcha {
            "<div class='cf-turnstile' data-sitekey='site-key-123'></div>"
        } else {
            ""
        };

        format!(
            r#"
            <html>
              <head>
                                <script>window._cf_chl_opt=({{"cvId":"cv123","chlPageData":"page-data"}});</script>
              </head>
              <body>
                                <script>var cpo={{}};cpo.src="{orchestrate_path}";</script>
                <form id="challenge-form" action="/cdn-cgi/challenge-platform/h/b/orchestrate/form" method="POST">
                  <input type="hidden" name="r" value="token-r"/>
                </form>
                {captcha_snippet}
              </body>
            </html>
        "#
        )
    }

    #[test]
    fn solve_builds_submission() {
        let html = sample_html(false);
        let fixture = ResponseFixture::new(&html, 403);
        let solver = JavascriptV2Solver::new();
        assert!(JavascriptV2Solver::is_js_challenge(&fixture.response()));

        let submission = solver.solve(&fixture.response()).expect("should solve");
        assert_eq!(submission.method, Method::POST);
        assert_eq!(
            submission.url.as_str(),
            "https://example.com/cdn-cgi/challenge-platform/h/b/orchestrate/form"
        );
        assert_eq!(
            submission.form_fields.get("r"),
            Some(&"token-r".to_string())
        );
        assert_eq!(
            submission.form_fields.get("cv_chal_id"),
            Some(&"cv123".to_string())
        );
        assert!(submission.wait >= Duration::from_secs(1));
        assert!(submission.wait <= Duration::from_secs(5));
        assert_eq!(
            submission.headers.get("Content-Type"),
            Some(&"application/x-www-form-urlencoded".to_string())
        );
        assert_eq!(
            submission.headers.get("Referer"),
            Some(&"https://example.com/".to_string())
        );
    }

    #[tokio::test]
    async fn solve_with_captcha_uses_provider() {
        let html = sample_html(true);
        let fixture = ResponseFixture::new(&html, 403);
        let solver = JavascriptV2Solver::new().with_captcha_provider(Arc::new(StubCaptchaProvider));
        let submission = solver
            .solve_with_captcha(&fixture.response())
            .await
            .expect("captcha challenge solved");
        assert_eq!(
            submission.form_fields.get("h-captcha-response"),
            Some(&"captcha-token".to_string())
        );
    }

    #[tokio::test]
    async fn solve_with_captcha_requires_provider() {
        let html = sample_html(true);
        let fixture = ResponseFixture::new(&html, 403);
        let solver = JavascriptV2Solver::new();
        let err = solver
            .solve_with_captcha(&fixture.response())
            .await
            .expect_err("missing provider should fail");
        matches!(err, JavascriptV2Error::CaptchaProviderMissing);
    }
}
