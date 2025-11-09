//! Solver for Cloudflare Turnstile captcha challenges.
//!
//! Detects the Turnstile widget, delegates solving to a configurable captcha
//! provider, and prepares the submission payload consumed by the shared
//! executor.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use html_escape::decode_html_entities;
use once_cell::sync::Lazy;
use rand::Rng;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

use crate::challenges::core::{
    ChallengeExecutionError, ChallengeHttpClient, ChallengeHttpResponse, ChallengeResponse,
    ChallengeSubmission, OriginalRequest, execute_challenge_submission, is_cloudflare_response,
    origin_from_url,
};
use crate::external_deps::captcha::{CaptchaError, CaptchaProvider, CaptchaTask};

use super::ChallengeSolver;

const DEFAULT_DELAY_MIN_SECS: f32 = 1.0;
const DEFAULT_DELAY_MAX_SECS: f32 = 5.0;

/// Solver capable of handling Cloudflare Turnstile challenges.
pub struct TurnstileSolver {
    delay_min: Duration,
    delay_max: Duration,
    captcha_provider: Option<Arc<dyn CaptchaProvider>>,
}

impl TurnstileSolver {
    /// Create a solver with the default random delay and no captcha provider.
    pub fn new() -> Self {
        Self {
            delay_min: Duration::from_secs_f32(DEFAULT_DELAY_MIN_SECS),
            delay_max: Duration::from_secs_f32(DEFAULT_DELAY_MAX_SECS),
            captcha_provider: None,
        }
    }

    /// Configure a custom delay range used before posting the solution.
    pub fn with_delay_range(mut self, min: Duration, max: Duration) -> Self {
        self.delay_min = min;
        self.delay_max = if max < min { min } else { max };
        self
    }

    /// Attach a captcha provider used to solve Turnstile tokens.
    pub fn with_captcha_provider(mut self, provider: Arc<dyn CaptchaProvider>) -> Self {
        self.captcha_provider = Some(provider);
        self
    }

    /// Replace or set the captcha provider after construction.
    pub fn set_captcha_provider(&mut self, provider: Arc<dyn CaptchaProvider>) {
        self.captcha_provider = Some(provider);
    }

    /// Remove the configured captcha provider.
    pub fn clear_captcha_provider(&mut self) {
        self.captcha_provider = None;
    }

    /// Returns `true` when the response resembles a Turnstile challenge page.
    pub fn is_turnstile_challenge(response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response)
            && matches!(response.status, 403 | 429 | 503)
            && (TURNSTILE_WIDGET_RE.is_match(response.body)
                || TURNSTILE_SCRIPT_RE.is_match(response.body)
                || TURNSTILE_SITEKEY_RE.is_match(response.body))
    }

    /// Solve the Turnstile page and return the planned challenge submission.
    pub async fn solve(
        &self,
        response: &ChallengeResponse<'_>,
    ) -> Result<ChallengeSubmission, TurnstileError> {
        if !Self::is_turnstile_challenge(response) {
            return Err(TurnstileError::NotTurnstileChallenge);
        }

        let provider = self
            .captcha_provider
            .as_ref()
            .ok_or(TurnstileError::CaptchaProviderMissing)?;

        let info = Self::extract_turnstile_info(response)?;
        let task =
            CaptchaTask::new(info.site_key.clone(), response.url.clone()).with_action("turnstile");
        let solution = provider
            .solve(&task)
            .await
            .map_err(TurnstileError::Captcha)?;

        let payload = Self::build_payload(response.body, solution.token);
        self.build_submission(response, &info.form_action, payload)
    }

    /// Solve and submit the challenge using the supplied HTTP client.
    pub async fn solve_and_submit(
        &self,
        client: Arc<dyn ChallengeHttpClient>,
        response: &ChallengeResponse<'_>,
        original_request: OriginalRequest,
    ) -> Result<ChallengeHttpResponse, TurnstileError> {
        let submission = self.solve(response).await?;
        execute_challenge_submission(client, submission, original_request)
            .await
            .map_err(TurnstileError::Submission)
    }

    fn build_submission(
        &self,
        response: &ChallengeResponse<'_>,
        form_action: &str,
        mut payload: HashMap<String, String>,
    ) -> Result<ChallengeSubmission, TurnstileError> {
        let form_action = decode_html_entities(form_action).into_owned();
        let target_url = response
            .url
            .join(&form_action)
            .map_err(|err| TurnstileError::InvalidFormAction(form_action.clone(), err))?;

        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        headers.insert("Referer".into(), response.url.as_str().to_string());
        headers.insert("Origin".into(), origin_from_url(response.url));

        let wait = self.random_delay();
        payload.entry("cf-turnstile-response".into()).or_default();

        Ok(ChallengeSubmission::new(
            http::Method::POST,
            target_url,
            payload,
            headers,
            wait,
        ))
    }

    fn random_delay(&self) -> Duration {
        if self.delay_max <= self.delay_min {
            return self.delay_min;
        }
        let mut rng = rand::thread_rng();
        let min = self.delay_min.as_secs_f32();
        let max = self.delay_max.as_secs_f32();
        Duration::from_secs_f32(rng.gen_range(min..max))
    }

    fn extract_turnstile_info(
        response: &ChallengeResponse<'_>,
    ) -> Result<TurnstileInfo, TurnstileError> {
        let body = response.body;
        let site_key = TURNSTILE_SITEKEY_RE
            .captures(body)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or(TurnstileError::MissingSiteKey)?;

        let form_action = FORM_ACTION_RE
            .captures(body)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| response.url.as_str().to_string());

        Ok(TurnstileInfo {
            site_key,
            form_action,
        })
    }

    fn build_payload(body: &str, token: String) -> HashMap<String, String> {
        let mut payload = HashMap::new();
        payload.insert("cf-turnstile-response".into(), token);

        for caps in INPUT_FIELD_RE.captures_iter(body) {
            if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
                let key = name.as_str();
                if key != "cf-turnstile-response" && !payload.contains_key(key) {
                    payload.insert(key.to_string(), value.as_str().to_string());
                }
            }
        }

        payload
    }
}

impl Default for TurnstileSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeSolver for TurnstileSolver {
    fn name(&self) -> &'static str {
        "turnstile"
    }
}

struct TurnstileInfo {
    site_key: String,
    form_action: String,
}

#[derive(Debug, Error)]
pub enum TurnstileError {
    #[error("response is not a Cloudflare Turnstile challenge")]
    NotTurnstileChallenge,
    #[error("captcha provider missing for Turnstile challenge")]
    CaptchaProviderMissing,
    #[error("missing Turnstile site key")]
    MissingSiteKey,
    #[error("invalid form action '{0}': {1}")]
    InvalidFormAction(String, url::ParseError),
    #[error("captcha provider error: {0}")]
    Captcha(#[source] CaptchaError),
    #[error("challenge submission failed: {0}")]
    Submission(#[source] ChallengeExecutionError),
}

static TURNSTILE_WIDGET_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"class=['"][^'"]*cf-turnstile[^'"]*['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid turnstile widget regex")
});

static TURNSTILE_SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"src=['"]https://challenges\.cloudflare\.com/turnstile/v0/api\.js"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid turnstile script regex")
});

static TURNSTILE_SITEKEY_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"data-sitekey=['"]([0-9A-Za-z]{40})['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid turnstile site key regex")
});

static FORM_ACTION_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"<form[^>]*action=['"]([^'"]+)['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid turnstile form action regex")
});

static INPUT_FIELD_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r#"<input[^>]*name=['"]([^'"]+)['"][^>]*value=['"]([^'"]*)['"]"#)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .build()
        .expect("invalid input field regex")
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
                url: Url::parse("https://example.com/turnstile").unwrap(),
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
            Ok(CaptchaSolution::new("turnstile-token"))
        }
    }

    fn sample_html(with_form_action: bool) -> String {
        let form_attr = if with_form_action {
            r#"action="/submit/turnstile""#
        } else {
            ""
        };

        format!(
            r#"
            <html>
              <body>
                <form id="challenge-form" {form_attr} method="POST">
                  <input type="hidden" name="foo" value="bar" />
                  <input type="hidden" name="cf-turnstile-response" value="existing" />
                </form>
                <div class="cf-turnstile" data-sitekey="ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd"></div>
                <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
              </body>
            </html>
        "#
        )
    }

    #[tokio::test]
    async fn solve_turnstile_builds_submission() {
        let html = sample_html(true);
        let fixture = ResponseFixture::new(&html, 403);
        let solver = TurnstileSolver::new().with_captcha_provider(Arc::new(StubCaptchaProvider));
        assert!(TurnstileSolver::is_turnstile_challenge(&fixture.response()));

        let submission = solver
            .solve(&fixture.response())
            .await
            .expect("should solve");
        assert_eq!(submission.method, Method::POST);
        assert_eq!(
            submission.url.as_str(),
            "https://example.com/submit/turnstile"
        );
        assert_eq!(
            submission.form_fields.get("cf-turnstile-response"),
            Some(&"turnstile-token".to_string())
        );
        assert_eq!(submission.form_fields.get("foo"), Some(&"bar".to_string()));
        assert!(submission.wait >= Duration::from_secs(1));
        assert!(submission.wait <= Duration::from_secs(5));
    }

    #[tokio::test]
    async fn solve_uses_current_url_when_form_absent() {
        let html = sample_html(false);
        let fixture = ResponseFixture::new(&html, 403);
        let solver = TurnstileSolver::new().with_captcha_provider(Arc::new(StubCaptchaProvider));
        let submission = solver
            .solve(&fixture.response())
            .await
            .expect("should solve");
        assert_eq!(submission.url.as_str(), "https://example.com/turnstile");
    }

    #[tokio::test]
    async fn solve_requires_provider() {
        let html = sample_html(true);
        let fixture = ResponseFixture::new(&html, 403);
        let solver = TurnstileSolver::new();
        let err = solver
            .solve(&fixture.response())
            .await
            .expect_err("should fail");
        assert!(matches!(err, TurnstileError::CaptchaProviderMissing));
    }
}
