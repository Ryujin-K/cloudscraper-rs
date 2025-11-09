//! Challenge detection module.
//!
//! Provides pattern-based identification of Cloudflare challenges along with
//! adaptive learning hooks.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::time::SystemTime;

use crate::challenges::core::{ChallengeResponse, is_cloudflare_response};

/// High level challenge categories supported by the detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeType {
    JavaScriptV1,
    JavaScriptV2,
    ManagedV3,
    Turnstile,
    RateLimit,
    AccessDenied,
    BotManagement,
    Unknown,
}

/// Recommended response strategy for a detected challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseStrategy {
    JsExecution,
    AdvancedJsExecution,
    BrowserSimulation,
    CaptchaSolving,
    DelayRetry,
    ProxyRotation,
    EnhancedEvasion,
    None,
}

/// Utility to extract a normalized domain from Cloudflare responses.
fn response_domain(response: &ChallengeResponse<'_>) -> Option<String> {
    response.url.host_str().map(|host| host.to_lowercase())
}

/// Pattern definition used to match responses against known challenge
/// signatures.
#[derive(Debug, Clone)]
struct ChallengePattern {
    id: String,
    name: String,
    challenge_type: ChallengeType,
    response_strategy: ResponseStrategy,
    base_confidence: f32,
    patterns: Vec<Regex>,
    adaptive: bool,
}

impl ChallengePattern {
    fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        challenge_type: ChallengeType,
        response_strategy: ResponseStrategy,
        base_confidence: f32,
        raw_patterns: &[&str],
    ) -> Self {
        let patterns = raw_patterns
            .iter()
            .map(|pattern| build_regex(pattern))
            .collect();

        Self {
            id: id.into(),
            name: name.into(),
            challenge_type,
            response_strategy,
            base_confidence,
            patterns,
            adaptive: false,
        }
    }

    fn into_adaptive(mut self) -> Self {
        self.adaptive = true;
        self
    }
}

/// Static list of known challenge signatures.
static KNOWN_PATTERNS: Lazy<Vec<ChallengePattern>> = Lazy::new(|| {
    vec![
        ChallengePattern::new(
            "cf_iuam_v1",
            "Cloudflare IUAM v1",
            ChallengeType::JavaScriptV1,
            ResponseStrategy::JsExecution,
            0.95,
            &[
                r#"<title>\s*Just a moment\.\.\.\s*</title>"#,
                r"var s,t,o,p,b,r,e,a,k,i,n,g,f,u,l,l,y,h,a,r,d,c,o,r,e",
                r#"setTimeout\(function\(\)\s*\{\s*var.*?\.submit\(\)"#,
                r#"<form[^>]*id="challenge-form"[^>]*action="/[^"]*__cf_chl_f_tk="#,
            ],
        ),
        ChallengePattern::new(
            "cf_iuam_v2",
            "Cloudflare IUAM v2",
            ChallengeType::JavaScriptV2,
            ResponseStrategy::AdvancedJsExecution,
            0.90,
            &[
                r#"cpo\.src\s*=\s*['"]/cdn-cgi/challenge-platform/.*?orchestrate/jsch/v1"#,
                r"window\._cf_chl_opt\s*=",
                r#"<form[^>]*id="challenge-form"[^>]*action="/[^"]*__cf_chl_rt_tk="#,
            ],
        ),
        ChallengePattern::new(
            "cf_managed_v3",
            "Cloudflare Managed Challenge v3",
            ChallengeType::ManagedV3,
            ResponseStrategy::BrowserSimulation,
            0.92,
            &[
                r#"cpo\.src\s*=\s*['"]/cdn-cgi/challenge-platform/.*?orchestrate/(?:captcha|managed)/v1"#,
                r"window\._cf_chl_ctx\s*=",
                r#"data-ray="[A-Fa-f0-9]+""#,
                r#"<div[^>]*class="cf-browser-verification"#,
            ],
        ),
        ChallengePattern::new(
            "cf_turnstile",
            "Cloudflare Turnstile",
            ChallengeType::Turnstile,
            ResponseStrategy::CaptchaSolving,
            0.98,
            &[
                r#"class="cf-turnstile""#,
                r#"data-sitekey="[0-9A-Za-z]{40}""#,
                r#"src="https://challenges\.cloudflare\.com/turnstile/v0/api\.js"#,
                r"cf-turnstile-response",
            ],
        ),
        ChallengePattern::new(
            "cf_rate_limit",
            "Cloudflare Rate Limit",
            ChallengeType::RateLimit,
            ResponseStrategy::DelayRetry,
            0.99,
            &[
                r#"<span[^>]*class="cf-error-code">1015<"#,
                r"You are being rate limited",
                r#"<title>\s*Rate Limited\s*</title>"#,
            ],
        ),
        ChallengePattern::new(
            "cf_access_denied",
            "Cloudflare Access Denied",
            ChallengeType::AccessDenied,
            ResponseStrategy::ProxyRotation,
            0.99,
            &[
                r#"<span[^>]*class="cf-error-code">1020<"#,
                r"Access denied",
                r"The owner of this website has banned your access",
            ],
        ),
        ChallengePattern::new(
            "cf_bot_management",
            "Cloudflare Bot Management",
            ChallengeType::BotManagement,
            ResponseStrategy::EnhancedEvasion,
            0.95,
            &[
                r#"<span[^>]*class="cf-error-code">1010<"#,
                r"Bot management",
                r"has banned you temporarily",
            ],
        ),
    ]
});

/// Detection output returned to the pipeline.
#[derive(Debug, Clone)]
pub struct ChallengeDetection {
    pub pattern_id: String,
    pub pattern_name: String,
    pub challenge_type: ChallengeType,
    pub response_strategy: ResponseStrategy,
    pub confidence: f32,
    pub is_adaptive: bool,
    pub status_code: u16,
    pub url: String,
    pub matched_indicators: Vec<String>,
}

#[derive(Debug, Clone)]
struct PatternStats {
    attempts: u32,
    successes: u32,
}

impl PatternStats {
    fn record(&mut self, success: bool) {
        self.attempts = self.attempts.saturating_add(1);
        if success {
            self.successes = self.successes.saturating_add(1);
        }
    }

    fn success_rate(&self) -> f32 {
        if self.attempts == 0 {
            0.0
        } else {
            self.successes as f32 / self.attempts as f32
        }
    }
}

#[derive(Debug, Clone)]
struct DetectionRecord {
    timestamp: SystemTime,
    pattern_id: String,
    confidence: f32,
    url: String,
}

/// Public view of a recorded challenge detection.
#[derive(Debug, Clone)]
pub struct DetectionLogEntry {
    pub timestamp: SystemTime,
    pub pattern_id: String,
    pub confidence: f32,
    pub url: String,
}

impl From<&DetectionRecord> for DetectionLogEntry {
    fn from(record: &DetectionRecord) -> Self {
        Self {
            timestamp: record.timestamp,
            pattern_id: record.pattern_id.clone(),
            confidence: record.confidence,
            url: record.url.clone(),
        }
    }
}

/// Pattern-based challenge detector with adaptive learning support.
#[derive(Debug)]
pub struct ChallengeDetector {
    known_patterns: Vec<ChallengePattern>,
    adaptive_patterns: HashMap<String, Vec<ChallengePattern>>, // domain -> patterns
    stats: HashMap<String, PatternStats>,
    history: VecDeque<DetectionRecord>,
    max_history: usize,
}

impl Default for ChallengeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeDetector {
    pub fn new() -> Self {
        Self {
            known_patterns: KNOWN_PATTERNS.clone(),
            adaptive_patterns: HashMap::new(),
            stats: HashMap::new(),
            history: VecDeque::with_capacity(128),
            max_history: 1000,
        }
    }

    /// Detect a challenge in the provided HTTP response context.
    pub fn detect(&mut self, response: &ChallengeResponse<'_>) -> Option<ChallengeDetection> {
        if !self.is_cloudflare_challenge(response) {
            return None;
        }

        let mut best: Option<(ChallengeDetection, f32)> = None;

        for pattern in &self.known_patterns {
            if let Some((confidence, matched)) = self.evaluate_pattern(pattern, response)
                && best
                    .as_ref()
                    .is_none_or(|(_, current)| confidence > *current)
            {
                best = Some((
                    ChallengeDetection {
                        pattern_id: pattern.id.clone(),
                        pattern_name: pattern.name.clone(),
                        challenge_type: pattern.challenge_type,
                        response_strategy: pattern.response_strategy,
                        confidence,
                        is_adaptive: pattern.adaptive,
                        status_code: response.status,
                        url: response.url.as_str().to_string(),
                        matched_indicators: matched,
                    },
                    confidence,
                ));
            }
        }

        if let Some(domain) = response_domain(response)
            && let Some(patterns) = self.adaptive_patterns.get(&domain)
        {
            for pattern in patterns {
                if let Some((confidence, matched)) = self.evaluate_pattern(pattern, response)
                    && best
                        .as_ref()
                        .is_none_or(|(_, current)| confidence > *current)
                {
                    best = Some((
                        ChallengeDetection {
                            pattern_id: pattern.id.clone(),
                            pattern_name: pattern.name.clone(),
                            challenge_type: pattern.challenge_type,
                            response_strategy: pattern.response_strategy,
                            confidence,
                            is_adaptive: true,
                            status_code: response.status,
                            url: response.url.as_str().to_string(),
                            matched_indicators: matched,
                        },
                        confidence,
                    ));
                }
            }
        }

        let result = best.map(|(detection, _)| detection);

        if let Some(ref detection) = result {
            self.record_detection(detection.clone());
        }

        result
    }

    fn evaluate_pattern(
        &self,
        pattern: &ChallengePattern,
        response: &ChallengeResponse<'_>,
    ) -> Option<(f32, Vec<String>)> {
        let matches: Vec<_> = pattern
            .patterns
            .iter()
            .filter(|regex| regex.is_match(response.body))
            .map(|regex| regex.as_str().to_string())
            .collect();

        if matches.is_empty() {
            return None;
        }

        let total = pattern.patterns.len() as f32;
        let mut confidence = (matches.len() as f32 / total) * pattern.base_confidence;

        if let Some(stats) = self.stats.get(&pattern.id) {
            confidence += stats.success_rate() * 0.1;
        }

        confidence = confidence.min(1.0);

        if confidence < 0.5 {
            return None;
        }

        Some((confidence, matches))
    }

    fn is_cloudflare_challenge(&self, response: &ChallengeResponse<'_>) -> bool {
        is_cloudflare_response(response) && matches!(response.status, 403 | 429 | 503)
    }

    fn record_detection(&mut self, detection: ChallengeDetection) {
        if self.history.len() == self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(DetectionRecord {
            timestamp: SystemTime::now(),
            pattern_id: detection.pattern_id,
            confidence: detection.confidence,
            url: detection.url,
        });
    }

    /// Iterate over historical detections (oldest -> newest).
    pub fn detection_history(&self) -> impl Iterator<Item = DetectionLogEntry> + '_ {
        self.history.iter().map(DetectionLogEntry::from)
    }

    /// Update success metrics for a pattern to influence future confidence scores.
    pub fn learn_from_outcome(&mut self, pattern_id: &str, success: bool) {
        let entry = self
            .stats
            .entry(pattern_id.to_string())
            .or_insert(PatternStats {
                attempts: 0,
                successes: 0,
            });
        entry.record(success);
    }

    /// Register an adaptive, domain-specific pattern discovered at runtime.
    pub fn add_adaptive_pattern(
        &mut self,
        domain: &str,
        pattern_name: &str,
        raw_patterns: Vec<&str>,
        challenge_type: ChallengeType,
        response_strategy: ResponseStrategy,
    ) {
        let pattern = ChallengePattern::new(
            format!("adaptive_{}_{}", domain, raw_patterns.len()),
            pattern_name,
            challenge_type,
            response_strategy,
            0.8,
            &raw_patterns,
        )
        .into_adaptive();

        self.adaptive_patterns
            .entry(domain.to_lowercase())
            .or_default()
            .push(pattern);
    }
}

fn build_regex(pattern: &str) -> Regex {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .multi_line(true)
        .dot_matches_new_line(true)
        .build()
        .unwrap_or_else(|err| panic!("invalid challenge detection regex `{}`: {}", pattern, err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::SERVER;
    use http::{HeaderMap, Method};
    use url::Url;

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

    #[test]
    fn detects_turnstile() {
        let html = r#"
			<html><head><title>Test</title></head>
			<body>
				<div class="cf-turnstile" data-sitekey="0123456789ABCDEFGHIJ0123456789ABCDEFGHIJ"></div>
				<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
			</body>
			</html>
		"#;

        let mut detector = ChallengeDetector::new();
        let fixture = ResponseFixture::new(html, 403);
        let response = fixture.response();
        let detection = detector.detect(&response).expect("should detect");

        assert_eq!(detection.challenge_type, ChallengeType::Turnstile);
        assert_eq!(
            detection.response_strategy,
            ResponseStrategy::CaptchaSolving
        );
    }
}
