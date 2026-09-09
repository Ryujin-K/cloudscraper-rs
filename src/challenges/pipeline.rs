//! Challenge orchestration pipeline.
//!
//! Brings together the detector and the individual solver/mitigation handlers in
//! a single entry point. The pipeline analyses a [`ChallengeResponse`] to figure
//! out which solver should run and returns the next action the caller should
//! perform (submit a payload, apply a mitigation plan, or declare the response
//! unsupported).

use std::fmt;

use thiserror::Error;

use crate::challenges::core::{ChallengeResponse, ChallengeSubmission};
use crate::challenges::detectors::{ChallengeDetection, ChallengeDetector, ChallengeType};
use crate::challenges::solvers::{
    FailureRecorder, FingerprintManager, MitigationPlan, TlsProfileManager,
    access_denied::{AccessDeniedError, AccessDeniedHandler, ProxyPool},
    bot_management::{BotManagementError, BotManagementHandler},
    javascript_v1::{JavascriptV1Error, JavascriptV1Solver},
    javascript_v2::{JavascriptV2Error, JavascriptV2Solver},
    managed_v3::{ManagedV3Error, ManagedV3Solver},
    rate_limit::{RateLimitError, RateLimitHandler},
    turnstile::{TurnstileError, TurnstileSolver},
};

/// Operational context passed to the pipeline when mitigation handlers need to
/// mutate shared services (proxy pool, TLS manager, fingerprint generator…).
#[derive(Default)]
pub struct PipelineContext<'a> {
    pub proxy_pool: Option<&'a mut dyn ProxyPool>,
    pub current_proxy: Option<&'a str>,
    pub failure_recorder: Option<&'a dyn FailureRecorder>,
    pub fingerprint_manager: Option<&'a mut dyn FingerprintManager>,
    pub tls_manager: Option<&'a mut dyn TlsProfileManager>,
}

/// High level result returned by the pipeline after analysing a response.
#[derive(Debug)]
pub enum ChallengePipelineResult {
    /// The response does not look like a Cloudflare challenge.
    NoChallenge,
    /// A solver produced a submission payload that should be posted back to Cloudflare.
    Submission {
        detection: ChallengeDetection,
        submission: ChallengeSubmission,
    },
    /// A mitigation-only handler provided a retry/back-off plan.
    Mitigation {
        detection: ChallengeDetection,
        plan: MitigationPlan,
    },
    /// The pipeline detected a challenge but lacks the required solver or dependency.
    Unsupported {
        detection: ChallengeDetection,
        reason: UnsupportedReason,
    },
    /// An available solver failed while processing the challenge.
    Failed {
        detection: ChallengeDetection,
        error: PipelineError,
    },
}

/// Reason why the pipeline could not act on a detected challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedReason {
    MissingSolver(&'static str),
    MissingDependency(&'static str),
    UnknownChallenge,
}

/// Wrapper around individual solver error types.
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("javascript v1 solver error: {0}")]
    JavascriptV1(#[from] JavascriptV1Error),
    #[error("javascript v2 solver error: {0}")]
    JavascriptV2(#[from] JavascriptV2Error),
    #[error("managed v3 solver error: {0}")]
    ManagedV3(#[from] ManagedV3Error),
    #[error("turnstile solver error: {0}")]
    Turnstile(#[from] TurnstileError),
    #[error("rate limit handler error: {0}")]
    RateLimit(#[from] RateLimitError),
    #[error("access denied handler error: {0}")]
    AccessDenied(#[from] AccessDeniedError),
    #[error("bot management handler error: {0}")]
    BotManagement(#[from] BotManagementError),
}

impl fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnsupportedReason::MissingSolver(name) => {
                write!(f, "required solver '{name}' is not configured")
            }
            UnsupportedReason::MissingDependency(name) => {
                write!(f, "missing required dependency: {name}")
            }
            UnsupportedReason::UnknownChallenge => write!(f, "unrecognised challenge"),
        }
    }
}

// Display is provided by the thiserror derive.

/// Coordinates challenge detection and solver selection.
pub struct ChallengePipeline {
    detector: ChallengeDetector,
    javascript_v1: Option<JavascriptV1Solver>,
    javascript_v2: Option<JavascriptV2Solver>,
    managed_v3: Option<ManagedV3Solver>,
    turnstile: Option<TurnstileSolver>,
    rate_limit: Option<RateLimitHandler>,
    access_denied: Option<AccessDeniedHandler>,
    bot_management: Option<BotManagementHandler>,
}

impl ChallengePipeline {
    /// Create a pipeline with the provided detector and no solvers configured.
    pub fn new(detector: ChallengeDetector) -> Self {
        Self {
            detector,
            javascript_v1: None,
            javascript_v2: None,
            managed_v3: None,
            turnstile: None,
            rate_limit: None,
            access_denied: None,
            bot_management: None,
        }
    }

    /// Replace the underlying detector.
    pub fn set_detector(&mut self, detector: ChallengeDetector) {
        self.detector = detector;
    }

    /// Borrow the detector immutably.
    pub fn detector(&self) -> &ChallengeDetector {
        &self.detector
    }

    /// Borrow the detector mutably (e.g. to read metrics or adaptive patterns).
    pub fn detector_mut(&mut self) -> &mut ChallengeDetector {
        &mut self.detector
    }

    /// Attach the JavaScript v1 solver.
    pub fn with_javascript_v1(mut self, solver: JavascriptV1Solver) -> Self {
        self.javascript_v1 = Some(solver);
        self
    }

    /// Attach the JavaScript v2 solver.
    pub fn with_javascript_v2(mut self, solver: JavascriptV2Solver) -> Self {
        self.javascript_v2 = Some(solver);
        self
    }

    /// Attach the Managed Challenge v3 solver.
    pub fn with_managed_v3(mut self, solver: ManagedV3Solver) -> Self {
        self.managed_v3 = Some(solver);
        self
    }

    /// Attach the Turnstile solver.
    pub fn with_turnstile(mut self, solver: TurnstileSolver) -> Self {
        self.turnstile = Some(solver);
        self
    }

    /// Attach the rate limit mitigation handler.
    pub fn with_rate_limit(mut self, handler: RateLimitHandler) -> Self {
        self.rate_limit = Some(handler);
        self
    }

    /// Attach the access denied mitigation handler.
    pub fn with_access_denied(mut self, handler: AccessDeniedHandler) -> Self {
        self.access_denied = Some(handler);
        self
    }

    /// Attach the bot management mitigation handler.
    pub fn with_bot_management(mut self, handler: BotManagementHandler) -> Self {
        self.bot_management = Some(handler);
        self
    }

    /// Evaluate a response and decide which solver should handle it.
    pub async fn evaluate<'a>(
        &'a mut self,
        response: &ChallengeResponse<'_>,
        context: PipelineContext<'a>,
    ) -> ChallengePipelineResult {
        let Some(detection) = self.detector.detect(response) else {
            return ChallengePipelineResult::NoChallenge;
        };

        let PipelineContext {
            proxy_pool,
            current_proxy,
            failure_recorder,
            fingerprint_manager,
            tls_manager,
        } = context;

        let detection_for_branch = detection.clone();

        match detection.challenge_type {
            ChallengeType::JavaScriptV1 => {
                let Some(solver) = self.javascript_v1.as_ref() else {
                    return unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingSolver("javascript_v1"),
                    );
                };
                match solver.solve(response) {
                    Ok(submission) => ChallengePipelineResult::Submission {
                        detection: detection_for_branch,
                        submission,
                    },
                    Err(err) => ChallengePipelineResult::Failed {
                        detection: detection_for_branch,
                        error: PipelineError::JavascriptV1(err),
                    },
                }
            }
            ChallengeType::JavaScriptV2 => {
                let Some(solver) = self.javascript_v2.as_ref() else {
                    return unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingSolver("javascript_v2"),
                    );
                };

                let result = if JavascriptV2Solver::is_captcha_challenge(response) {
                    solver.solve_with_captcha(response).await
                } else {
                    solver.solve(response)
                };

                match result {
                    Ok(submission) => ChallengePipelineResult::Submission {
                        detection: detection_for_branch,
                        submission,
                    },
                    Err(JavascriptV2Error::CaptchaProviderMissing) => unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingDependency("captcha_provider"),
                    ),
                    Err(err) => ChallengePipelineResult::Failed {
                        detection: detection_for_branch,
                        error: PipelineError::JavascriptV2(err),
                    },
                }
            }
            ChallengeType::ManagedV3 => {
                let Some(solver) = self.managed_v3.as_ref() else {
                    return unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingSolver("managed_v3"),
                    );
                };
                match solver.solve(response) {
                    Ok(submission) => ChallengePipelineResult::Submission {
                        detection: detection_for_branch,
                        submission,
                    },
                    Err(err) => ChallengePipelineResult::Failed {
                        detection: detection_for_branch,
                        error: PipelineError::ManagedV3(err),
                    },
                }
            }
            ChallengeType::ManagedInteractive => {
                // Recognised, but the modern interactive flow requires executing
                // Cloudflare's browser VM. Surface a precise, actionable result
                // instead of silently returning the raw 403 (issues #2/#3); the
                // headless-browser fallback will handle this challenge type.
                unsupported(
                    detection_for_branch,
                    UnsupportedReason::MissingDependency("browser_fallback"),
                )
            }
            ChallengeType::Turnstile => {
                let Some(solver) = self.turnstile.as_ref() else {
                    return unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingSolver("turnstile"),
                    );
                };
                match solver.solve(response).await {
                    Ok(submission) => ChallengePipelineResult::Submission {
                        detection: detection_for_branch,
                        submission,
                    },
                    Err(TurnstileError::CaptchaProviderMissing) => unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingDependency("captcha_provider"),
                    ),
                    Err(err) => ChallengePipelineResult::Failed {
                        detection: detection_for_branch,
                        error: PipelineError::Turnstile(err),
                    },
                }
            }
            ChallengeType::RateLimit => {
                let Some(handler) = self.rate_limit.as_ref() else {
                    return unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingSolver("rate_limit"),
                    );
                };
                match handler.plan(response, failure_recorder) {
                    Ok(plan) => ChallengePipelineResult::Mitigation {
                        detection: detection_for_branch,
                        plan,
                    },
                    Err(err) => ChallengePipelineResult::Failed {
                        detection: detection_for_branch,
                        error: PipelineError::RateLimit(err),
                    },
                }
            }
            ChallengeType::AccessDenied => {
                let Some(handler) = self.access_denied.as_ref() else {
                    return unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingSolver("access_denied"),
                    );
                };
                match handler.plan(response, proxy_pool, current_proxy) {
                    Ok(plan) => ChallengePipelineResult::Mitigation {
                        detection: detection_for_branch,
                        plan,
                    },
                    Err(err) => ChallengePipelineResult::Failed {
                        detection: detection_for_branch,
                        error: PipelineError::AccessDenied(err),
                    },
                }
            }
            ChallengeType::BotManagement => {
                let Some(handler) = self.bot_management.as_ref() else {
                    return unsupported(
                        detection_for_branch,
                        UnsupportedReason::MissingSolver("bot_management"),
                    );
                };
                match handler.plan(response, fingerprint_manager, tls_manager, failure_recorder) {
                    Ok(plan) => ChallengePipelineResult::Mitigation {
                        detection: detection_for_branch,
                        plan,
                    },
                    Err(err) => ChallengePipelineResult::Failed {
                        detection: detection_for_branch,
                        error: PipelineError::BotManagement(err),
                    },
                }
            }
            ChallengeType::Unknown => {
                unsupported(detection_for_branch, UnsupportedReason::UnknownChallenge)
            }
        }
    }

    /// Feed the detector with challenge outcome data for adaptive scoring.
    pub fn record_outcome(&mut self, pattern_id: &str, success: bool) {
        self.detector.learn_from_outcome(pattern_id, success);
    }
}

impl Default for ChallengePipeline {
    fn default() -> Self {
        Self::new(ChallengeDetector::new())
    }
}

fn unsupported(
    detection: ChallengeDetection,
    reason: UnsupportedReason,
) -> ChallengePipelineResult {
    ChallengePipelineResult::Unsupported { detection, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenges::core::ChallengeResponse;
    use http::{HeaderMap, Method, header::SERVER};
    use url::Url;

    struct Fixture {
        url: Url,
        headers: HeaderMap,
        method: Method,
        body: String,
        status: u16,
    }

    impl Fixture {
        fn cloudflare(body: &str, status: u16) -> Self {
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

        fn plain(body: &str, status: u16) -> Self {
            Self {
                url: Url::parse("https://example.com/").unwrap(),
                headers: HeaderMap::new(),
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

    #[tokio::test]
    async fn plain_response_is_no_challenge() {
        let mut pipeline = ChallengePipeline::default();
        let fixture = Fixture::plain("<html>ok</html>", 200);
        let result = pipeline
            .evaluate(&fixture.response(), PipelineContext::default())
            .await;
        assert!(matches!(result, ChallengePipelineResult::NoChallenge));
    }

    #[tokio::test]
    async fn detected_challenge_without_solver_is_unsupported() {
        let mut pipeline = ChallengePipeline::default(); // no solvers attached
        let body = r#"<div class="cf-turnstile" data-sitekey="0123456789ABCDEFGHIJ0123456789ABCDEFGHIJ"></div>
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>cf-turnstile-response"#;
        let fixture = Fixture::cloudflare(body, 403);
        let result = pipeline
            .evaluate(&fixture.response(), PipelineContext::default())
            .await;
        match result {
            ChallengePipelineResult::Unsupported { reason, .. } => {
                assert_eq!(reason, UnsupportedReason::MissingSolver("turnstile"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn managed_interactive_requests_browser_fallback() {
        let mut pipeline = ChallengePipeline::default();
        let body = "window._cf_chl_opt = {cType:'managed'}; \
            /cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1";
        let fixture = Fixture::cloudflare(body, 403);
        let result = pipeline
            .evaluate(&fixture.response(), PipelineContext::default())
            .await;
        match result {
            ChallengePipelineResult::Unsupported { reason, .. } => {
                assert_eq!(
                    reason,
                    UnsupportedReason::MissingDependency("browser_fallback")
                );
            }
            other => panic!("expected browser_fallback Unsupported, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rate_limit_yields_mitigation() {
        let mut pipeline = ChallengePipeline::default().with_rate_limit(RateLimitHandler::new());
        let body = r#"<span class="cf-error-code">1015</span> You are being rate limited"#;
        let fixture = Fixture::cloudflare(body, 429);
        let result = pipeline
            .evaluate(&fixture.response(), PipelineContext::default())
            .await;
        assert!(matches!(result, ChallengePipelineResult::Mitigation { .. }));
    }

    #[tokio::test]
    async fn access_denied_yields_mitigation() {
        let mut pipeline =
            ChallengePipeline::default().with_access_denied(AccessDeniedHandler::new());
        let body = r#"<span class="cf-error-code">1020</span> Access denied.
            The owner of this website has banned your access"#;
        let fixture = Fixture::cloudflare(body, 403);
        let result = pipeline
            .evaluate(&fixture.response(), PipelineContext::default())
            .await;
        assert!(matches!(result, ChallengePipelineResult::Mitigation { .. }));
    }

    #[test]
    fn record_outcome_and_detector_accessors() {
        let mut pipeline = ChallengePipeline::default();
        pipeline.record_outcome("cf_turnstile", true);
        let _ = pipeline.detector();
        let _ = pipeline.detector_mut();
        let replacement = ChallengeDetector::new();
        pipeline.set_detector(replacement);
    }

    #[test]
    fn unsupported_reason_display_messages() {
        assert!(
            UnsupportedReason::MissingSolver("x")
                .to_string()
                .contains('x')
        );
        assert!(
            UnsupportedReason::MissingDependency("dep")
                .to_string()
                .contains("dep")
        );
        assert!(
            UnsupportedReason::UnknownChallenge
                .to_string()
                .contains("unrecognised")
        );
    }
}
