//! High level scraper orchestration.
//!
//! Wires together the challenge detectors, solvers, and adaptive subsystems
//! (timing, anti-detection, spoofing, TLS, ML, metrics…) to expose an
//! ergonomic HTTP client capable of transparently handling Cloudflare
//! defences.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::sleep;
use url::Url;

use crate::challenges::core::{
    ChallengeExecutionError, ChallengeHttpClient, ChallengeResponse, ChallengeSubmission,
    OriginalRequest, ReqwestChallengeHttpClient, execute_challenge_submission,
};
use crate::challenges::detectors::ChallengeDetection;
use crate::challenges::pipeline::{
    ChallengePipeline, ChallengePipelineResult, PipelineContext, PipelineError, UnsupportedReason,
};
use crate::challenges::solvers::access_denied::ProxyPool;
use crate::challenges::solvers::{
    MitigationPlan, TlsProfileManager, access_denied::AccessDeniedHandler,
    bot_management::BotManagementHandler, javascript_v1::JavascriptV1Solver,
    javascript_v2::JavascriptV2Solver, managed_v3::ManagedV3Solver, rate_limit::RateLimitHandler,
    turnstile::TurnstileSolver,
};
use crate::challenges::user_agents::{
    UserAgentError, UserAgentOptions, UserAgentProfile, get_user_agent_profile,
};
use crate::external_deps::captcha::CaptchaProvider;
use crate::external_deps::interpreters::{BoaJavascriptInterpreter, JavascriptInterpreter};
use crate::modules::adaptive_timing::{
    AdaptiveTimingStrategy, BehaviorProfile, DefaultAdaptiveTiming, RequestKind, TimingOutcome,
    TimingRequest,
};
use crate::modules::anti_detection::{
    AntiDetectionContext, AntiDetectionStrategy, DefaultAntiDetection,
};
use crate::modules::events::{
    ChallengeEvent, EventDispatcher, LoggingHandler, MetricsHandler, PostResponseEvent,
    PreRequestEvent, RetryEvent, ScraperEvent,
};
use crate::modules::metrics::MetricsCollector;
use crate::modules::ml::{FeatureVector, MLOptimizer};
use crate::modules::performance::PerformanceMonitor;
use crate::modules::proxy::{ProxyConfig, ProxyManager};
use crate::modules::spoofing::{ConsistencyLevel, FingerprintGenerator};
use crate::modules::state::StateManager;
use crate::modules::tls::{DefaultTLSManager, TLSConfig};

/// Result alias used across the orchestration layer.
pub type CloudScraperResult<T> = Result<T, CloudScraperError>;

/// High-level error surfaced by the orchestrator.
#[derive(Debug, Error)]
pub enum CloudScraperError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("user-agent initialisation failed: {0}")]
    UserAgent(#[from] UserAgentError),
    #[error("challenge execution failed: {0}")]
    ChallengeExecution(#[from] ChallengeExecutionError),
    #[error("challenge pipeline error: {0}")]
    Pipeline(#[from] PipelineError),
    #[error("unsupported challenge ({0})")]
    Unsupported(UnsupportedReason),
    #[error("utf8 conversion failed: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("header conversion failed: {0}")]
    InvalidHeader(String),
    #[error("mitigation required but retries exhausted: {0:?}")]
    Mitigation(Box<MitigationPlan>),
    #[error("challenge handling aborted: {0}")]
    Aborted(String),
}

/// Read-only HTTP response returned by the scraper.
#[derive(Debug, Clone)]
pub struct ScraperResponse {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
    url: Url,
}

impl ScraperResponse {
    fn new(status: u16, headers: HeaderMap, body: Bytes, url: Url) -> Self {
        Self {
            status,
            headers,
            body,
            url,
        }
    }

    /// HTTP status code as returned by Cloudflare/target origin.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Final URL after challenge handling / redirects.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Convenience helper returning the body as UTF-8 text.
    pub async fn text(&self) -> CloudScraperResult<String> {
        Ok(String::from_utf8(self.body.to_vec())?)
    }

    /// Raw body bytes.
    pub async fn bytes(&self) -> Bytes {
        self.body.clone()
    }
}

/// Scraper configuration used by the builder.
#[derive(Clone)]
pub struct CloudScraperConfig {
    pub user_agent: UserAgentOptions,
    pub content_type: Option<String>,
    pub proxies: Vec<String>,
    pub proxy_config: ProxyConfig,
    pub enable_metrics: bool,
    pub enable_performance_monitoring: bool,
    pub enable_tls_fingerprinting: bool,
    pub enable_anti_detection: bool,
    pub enable_spoofing: bool,
    pub enable_adaptive_timing: bool,
    pub enable_ml_optimization: bool,
    pub behavior_profile: BehaviorProfile,
    pub spoofing_consistency: ConsistencyLevel,
    pub captcha_provider: Option<Arc<dyn CaptchaProvider>>,
    pub interpreter: Option<Arc<dyn JavascriptInterpreter>>,
    pub tls_config: TLSConfig,
    pub max_challenge_attempts: usize,
}

impl Default for CloudScraperConfig {
    fn default() -> Self {
        Self {
            user_agent: UserAgentOptions::default(),
            content_type: None,
            proxies: Vec::new(),
            proxy_config: ProxyConfig::default(),
            enable_metrics: true,
            enable_performance_monitoring: true,
            enable_tls_fingerprinting: true,
            enable_anti_detection: true,
            enable_spoofing: true,
            enable_adaptive_timing: true,
            enable_ml_optimization: true,
            behavior_profile: BehaviorProfile::Casual,
            spoofing_consistency: ConsistencyLevel::Domain,
            captcha_provider: None,
            interpreter: None,
            tls_config: TLSConfig::default(),
            max_challenge_attempts: 3,
        }
    }
}

/// Fluent builder for [`CloudScraper`].
pub struct CloudScraperBuilder {
    config: CloudScraperConfig,
}

impl CloudScraperBuilder {
    pub fn new() -> Self {
        Self {
            config: CloudScraperConfig::default(),
        }
    }

    pub fn with_user_agent_options(mut self, options: UserAgentOptions) -> Self {
        self.config.user_agent = options;
        self
    }

    pub fn with_content_type(mut self, content_type: String) -> Self {
        self.config.content_type = Some(content_type);
        self
    }

    pub fn with_proxies<I, S>(mut self, proxies: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.proxies = proxies.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_proxy_config(mut self, config: ProxyConfig) -> Self {
        self.config.proxy_config = config;
        self
    }

    pub fn with_captcha_provider(mut self, provider: Arc<dyn CaptchaProvider>) -> Self {
        self.config.captcha_provider = Some(provider);
        self
    }

    pub fn with_interpreter(mut self, interpreter: Arc<dyn JavascriptInterpreter>) -> Self {
        self.config.interpreter = Some(interpreter);
        self
    }

    pub fn disable_metrics(mut self) -> Self {
        self.config.enable_metrics = false;
        self
    }

    pub fn disable_performance_monitoring(mut self) -> Self {
        self.config.enable_performance_monitoring = false;
        self
    }

    pub fn disable_tls_fingerprinting(mut self) -> Self {
        self.config.enable_tls_fingerprinting = false;
        self
    }

    pub fn disable_anti_detection(mut self) -> Self {
        self.config.enable_anti_detection = false;
        self
    }

    pub fn disable_spoofing(mut self) -> Self {
        self.config.enable_spoofing = false;
        self
    }

    pub fn disable_adaptive_timing(mut self) -> Self {
        self.config.enable_adaptive_timing = false;
        self
    }

    pub fn disable_ml_optimization(mut self) -> Self {
        self.config.enable_ml_optimization = false;
        self
    }

    pub fn with_behavior_profile(mut self, profile: BehaviorProfile) -> Self {
        self.config.behavior_profile = profile;
        self
    }

    pub fn with_spoofing_consistency(mut self, level: ConsistencyLevel) -> Self {
        self.config.spoofing_consistency = level;
        self
    }

    pub fn with_tls_config(mut self, config: TLSConfig) -> Self {
        self.config.tls_config = config;
        self
    }

    pub fn with_max_challenge_attempts(mut self, attempts: usize) -> Self {
        self.config.max_challenge_attempts = attempts.max(1);
        self
    }

    pub fn build(self) -> CloudScraperResult<CloudScraper> {
        CloudScraper::with_config(self.config)
    }
}

impl Default for CloudScraperBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Stateful helper shared between concurrent requests.
struct CloudScraperInner {
    pipeline: ChallengePipeline,
    proxy_manager: Option<ProxyManager>,
    current_proxy: Option<String>,
    tls_manager: Option<DefaultTLSManager>,
    fingerprint: Option<FingerprintGenerator>,
    anti_detection: Option<DefaultAntiDetection>,
    adaptive_timing: Option<DefaultAdaptiveTiming>,
    performance_monitor: Option<PerformanceMonitor>,
    ml_optimizer: Option<MLOptimizer>,
}

impl CloudScraperInner {
    fn new(pipeline: ChallengePipeline) -> Self {
        Self {
            pipeline,
            proxy_manager: None,
            current_proxy: None,
            tls_manager: None,
            fingerprint: None,
            anti_detection: None,
            adaptive_timing: None,
            performance_monitor: None,
            ml_optimizer: None,
        }
    }
}

/// Reqwest client pool keyed by proxy endpoint.
struct ClientPool {
    base_headers: reqwest::header::HeaderMap,
    clients: Mutex<HashMap<Option<String>, reqwest::Client>>,
}

impl ClientPool {
    fn new(base_headers: reqwest::header::HeaderMap) -> Self {
        Self {
            base_headers,
            clients: Mutex::new(HashMap::new()),
        }
    }

    async fn client(&self, proxy: Option<&str>) -> CloudScraperResult<reqwest::Client> {
        let mut guard = self.clients.lock().await;
        let key = proxy.map(|p| p.to_string());
        if let Some(client) = guard.get(&key) {
            return Ok(client.clone());
        }

        let mut builder = reqwest::Client::builder()
            .cookie_store(true)
            .default_headers(self.base_headers.clone());

        if let Some(endpoint) = proxy {
            builder = builder.proxy(reqwest::Proxy::all(endpoint)?);
        }

        let client = builder.build()?;
        guard.insert(key.clone(), client.clone());
        Ok(client)
    }
}

/// Main scraper orchestrator.
pub struct CloudScraper {
    config: CloudScraperConfig,
    base_headers_http: HeaderMap,
    client_pool: Arc<ClientPool>,
    challenge_client: Arc<dyn ChallengeHttpClient>,
    state: StateManager,
    metrics: Option<MetricsCollector>,
    events: Arc<EventDispatcher>,
    inner: Mutex<CloudScraperInner>,
}

impl CloudScraper {
    /// Construct a scraper with default configuration.
    pub fn new() -> CloudScraperResult<Self> {
        CloudScraper::with_config(CloudScraperConfig::default())
    }

    /// Obtain a builder to customise the scraper instance.
    pub fn builder() -> CloudScraperBuilder {
        CloudScraperBuilder::new()
    }

    fn with_config(config: CloudScraperConfig) -> CloudScraperResult<Self> {
        let profile = get_user_agent_profile(config.user_agent.clone())?;
        let base_headers_http = to_http_headers(&profile)?;
        let base_headers_reqwest = to_reqwest_headers(&base_headers_http)?;

        let mut pipeline = ChallengePipeline::default();
        let interpreter: Arc<dyn JavascriptInterpreter> = config
            .interpreter
            .clone()
            .unwrap_or_else(|| Arc::new(BoaJavascriptInterpreter::new()));

        let mut js_v2 = JavascriptV2Solver::new();
        let mut turnstile = TurnstileSolver::new();
        if let Some(provider) = &config.captcha_provider {
            js_v2 = js_v2.with_captcha_provider(provider.clone());
            turnstile = turnstile.with_captcha_provider(provider.clone());
        }

        pipeline = pipeline
            .with_javascript_v1(JavascriptV1Solver::new(interpreter.clone()))
            .with_javascript_v2(js_v2)
            .with_managed_v3(ManagedV3Solver::new(interpreter))
            .with_turnstile(turnstile)
            .with_rate_limit(RateLimitHandler::new())
            .with_access_denied(AccessDeniedHandler::new())
            .with_bot_management(BotManagementHandler::new());

        let mut inner = CloudScraperInner::new(pipeline);

        if !config.proxies.is_empty() {
            let mut manager = ProxyManager::new(config.proxy_config.clone());
            manager.load(config.proxies.iter().cloned());
            inner.proxy_manager = Some(manager);
        }

        if config.enable_tls_fingerprinting {
            inner.tls_manager = Some(DefaultTLSManager::new(config.tls_config.clone()));
        }

        if config.enable_spoofing {
            let mut generator = FingerprintGenerator::default();
            generator = generator.with_consistency(config.spoofing_consistency);
            inner.fingerprint = Some(generator);
        }

        if config.enable_anti_detection {
            inner.anti_detection = Some(DefaultAntiDetection::new(Default::default()));
        }

        if config.enable_adaptive_timing {
            let mut timing = DefaultAdaptiveTiming::new();
            timing.set_behavior_profile(config.behavior_profile);
            inner.adaptive_timing = Some(timing);
        }

        if config.enable_performance_monitoring {
            inner.performance_monitor = Some(PerformanceMonitor::new(Default::default()));
        }

        if config.enable_ml_optimization {
            inner.ml_optimizer = Some(MLOptimizer::default());
        }

        let client_pool = Arc::new(ClientPool::new(base_headers_reqwest));
        let challenge_client = Arc::new(ReqwestChallengeHttpClient::new()?);
        let state = StateManager::new();
        let metrics = config.enable_metrics.then(MetricsCollector::new);

        let mut events = EventDispatcher::new();
        events.register_handler(Arc::new(LoggingHandler));
        if let Some(ref collector) = metrics {
            events.register_handler(Arc::new(MetricsHandler::new(collector.clone())));
        }

        Ok(Self {
            config,
            base_headers_http,
            client_pool,
            challenge_client,
            state,
            metrics,
            events: Arc::new(events),
            inner: Mutex::new(inner),
        })
    }

    /// Perform an HTTP GET request.
    pub async fn get(&self, url: &str) -> CloudScraperResult<ScraperResponse> {
        let url = Url::parse(url)?;
        self.request(Method::GET, url, None).await
    }

    /// Perform an arbitrary HTTP request.
    pub async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
    ) -> CloudScraperResult<ScraperResponse> {
        let mut forced_proxy: Option<String> = None;
        let mut attempt = 0usize;

        loop {
            attempt += 1;

            let (mut headers_http, anti_ctx, proxy, mut delay) = self
                .prepare_request(
                    &method,
                    &url,
                    body.as_ref().map(|b| b.len()).unwrap_or(0),
                    forced_proxy.take(),
                )
                .await?;

            if let Some(ref ct) = self.config.content_type {
                headers_http.insert(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_str(ct)
                        .map_err(|_| CloudScraperError::InvalidHeader("content-type".into()))?,
                );
            }

            if let Some(hint) = anti_ctx.delay_hint()
                && hint > delay
            {
                delay = hint;
            }

            self.events
                .dispatch(ScraperEvent::PreRequest(PreRequestEvent {
                    url: url.clone(),
                    method: method.clone(),
                    headers: headers_http.clone(),
                    timestamp: chrono::Utc::now(),
                }));

            let client = self.client_pool.client(proxy.as_deref()).await?;

            if delay > Duration::from_millis(0) {
                sleep(delay).await;
            }

            let req_headers = to_reqwest_headers(&headers_http)?;
            let mut builder = client
                .request(method.clone(), url.clone())
                .headers(req_headers);
            if let Some(ref body) = body {
                builder = builder.body(body.clone());
            }

            let started = Instant::now();
            let resp = builder.send().await?;
            let latency = started.elapsed();

            let final_url = resp.url().clone();
            let status = resp.status().as_u16();
            let headers_raw = resp.headers().clone();
            let body_bytes = resp.bytes().await?.to_vec();
            let body_text = String::from_utf8_lossy(&body_bytes).to_string();

            let http_headers = reqwest_to_http(&headers_raw)?;
            let challenge_response = ChallengeResponse {
                url: &final_url,
                status,
                headers: &http_headers,
                body: &body_text,
                request_method: &method,
            };

            self.events
                .dispatch(ScraperEvent::PostResponse(PostResponseEvent {
                    url: final_url.clone(),
                    method: method.clone(),
                    status,
                    latency,
                    timestamp: chrono::Utc::now(),
                }));

            let result = {
                let mut guard = self.inner.lock().await;
                let CloudScraperInner {
                    pipeline,
                    proxy_manager,
                    current_proxy,
                    tls_manager,
                    fingerprint,
                    ..
                } = &mut *guard;

                pipeline
                    .evaluate(
                        &challenge_response,
                        PipelineContext {
                            proxy_pool: proxy_manager.as_mut().map(|pm| pm as &mut dyn ProxyPool),
                            current_proxy: current_proxy.as_deref(),
                            failure_recorder: Some(&self.state),
                            fingerprint_manager: fingerprint.as_mut().map(|fp| {
                                fp as &mut dyn crate::challenges::solvers::FingerprintManager
                            }),
                            tls_manager: tls_manager
                                .as_mut()
                                .map(|tls| tls as &mut dyn TlsProfileManager),
                        },
                    )
                    .await
            };

            match result {
                ChallengePipelineResult::NoChallenge => {
                    self.record_outcome(true, status, latency, delay, &final_url)
                        .await;
                    let response = ScraperResponse::new(
                        status,
                        http_headers.clone(),
                        Bytes::from(body_bytes),
                        final_url,
                    );
                    return Ok(response);
                }
                ChallengePipelineResult::Submission {
                    detection,
                    submission,
                } => {
                    let (response, challenge_latency) = self
                        .handle_submission(
                            submission,
                            detection,
                            &method,
                            &url,
                            headers_http.clone(),
                            body.clone(),
                        )
                        .await?;
                    self.record_outcome(
                        response.status() < 500,
                        response.status(),
                        latency + challenge_latency,
                        delay,
                        response.url(),
                    )
                    .await;
                    return Ok(response);
                }
                ChallengePipelineResult::Mitigation { detection, plan } => {
                    self.record_outcome(false, status, latency, delay, &final_url)
                        .await;
                    self.events
                        .dispatch(ScraperEvent::Challenge(ChallengeEvent {
                            domain: detection.url.clone(),
                            challenge_type: format!("{:?}", detection.challenge_type),
                            success: false,
                            metadata: vec![
                                ("reason".into(), plan.reason.clone()),
                                ("pattern".into(), detection.pattern_id.clone()),
                            ],
                            timestamp: chrono::Utc::now(),
                        }));

                    if let Some(wait) = plan.wait {
                        sleep(wait).await;
                    }

                    if let Some(ref proxy_hint) = plan.new_proxy {
                        forced_proxy = Some(proxy_hint.clone());
                    }

                    let should_retry =
                        plan.should_retry && attempt < self.config.max_challenge_attempts;
                    if should_retry {
                        self.events.dispatch(ScraperEvent::Retry(RetryEvent {
                            domain: detection.url,
                            attempt: (attempt + 1) as u32,
                            reason: plan.reason.clone(),
                            scheduled_after: plan.wait.unwrap_or_default(),
                            timestamp: chrono::Utc::now(),
                        }));
                        continue;
                    } else {
                        return Err(CloudScraperError::Mitigation(Box::new(plan)));
                    }
                }
                ChallengePipelineResult::Unsupported { detection, reason } => {
                    self.record_outcome(false, status, latency, delay, &final_url)
                        .await;
                    self.events
                        .dispatch(ScraperEvent::Challenge(ChallengeEvent {
                            domain: detection.url,
                            challenge_type: detection.pattern_name,
                            success: false,
                            metadata: vec![("reason".into(), reason.to_string())],
                            timestamp: chrono::Utc::now(),
                        }));
                    return Err(CloudScraperError::Unsupported(reason));
                }
                ChallengePipelineResult::Failed { detection, error } => {
                    self.record_outcome(false, status, latency, delay, &final_url)
                        .await;
                    self.events
                        .dispatch(ScraperEvent::Error(crate::modules::events::ErrorEvent {
                            domain: detection.url,
                            error: error.to_string(),
                            timestamp: chrono::Utc::now(),
                        }));
                    return Err(CloudScraperError::Pipeline(error));
                }
            }
        }
    }

    async fn handle_submission(
        &self,
        submission: ChallengeSubmission,
        detection: ChallengeDetection,
        method: &Method,
        url: &Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> CloudScraperResult<(ScraperResponse, Duration)> {
        let original = OriginalRequest::new(method.clone(), url.clone())
            .with_headers(headers)
            .with_body(body);

        let started = Instant::now();
        let result =
            execute_challenge_submission(self.challenge_client.clone(), submission, original).await;
        let challenge_latency = started.elapsed();

        let success = result.is_ok();
        {
            let mut guard = self.inner.lock().await;
            guard
                .pipeline
                .record_outcome(&detection.pattern_id, success);
        }

        let final_response = result?;
        let response = ScraperResponse::new(
            final_response.status,
            final_response.headers.clone(),
            Bytes::from(final_response.body.clone()),
            final_response.url.clone(),
        );

        self.events
            .dispatch(ScraperEvent::Challenge(ChallengeEvent {
                domain: detection.url,
                challenge_type: detection.pattern_name,
                success,
                metadata: vec![
                    ("pattern".into(), detection.pattern_id),
                    ("status".into(), final_response.status.to_string()),
                ],
                timestamp: chrono::Utc::now(),
            }));

        self.events
            .dispatch(ScraperEvent::PostResponse(PostResponseEvent {
                url: response.url().clone(),
                method: method.clone(),
                status: response.status(),
                latency: challenge_latency,
                timestamp: chrono::Utc::now(),
            }));

        Ok((response, challenge_latency))
    }

    async fn record_outcome(
        &self,
        success: bool,
        status: u16,
        latency: Duration,
        delay: Duration,
        url: &Url,
    ) {
        let domain = url.host_str().unwrap_or_default();
        if success {
            self.state.record_success(domain);
        } else {
            self.state
                .record_failure(domain, format!("status_{status}"));
        }

        if let Some(ref collector) = self.metrics {
            collector.record_response(domain, status, latency);
        }

        let mut guard = self.inner.lock().await;
        if let Some(timing) = guard.adaptive_timing.as_mut() {
            let outcome = TimingOutcome {
                success,
                response_time: latency,
                applied_delay: delay,
            };
            timing.record_outcome(domain, &outcome);
        }

        if let Some(anti) = guard.anti_detection.as_mut() {
            anti.record_response(domain, status, latency);
        }

        if let Some(perf) = guard.performance_monitor.as_mut()
            && let Some(report) = perf.record(domain, latency, success)
            && !report.alerts.is_empty()
        {
            log::warn!("performance alerts: {:#?}", report.alerts);
        }

        if let Some(ml) = guard.ml_optimizer.as_mut() {
            let mut features = FeatureVector::new();
            features.insert("latency".into(), latency.as_secs_f64());
            features.insert("delay".into(), delay.as_secs_f64());
            ml.record_attempt(domain, features, success, Some(delay.as_secs_f64()));
        }
    }

    async fn prepare_request(
        &self,
        method: &Method,
        url: &Url,
        body_size: usize,
        forced_proxy: Option<String>,
    ) -> CloudScraperResult<(HeaderMap, AntiDetectionContext, Option<String>, Duration)> {
        let mut headers = self.base_headers_http.clone();
        if let Some(state) = self.state.get(url.host_str().unwrap_or("")) {
            for (name, value) in state.sticky_headers {
                let header_name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| CloudScraperError::InvalidHeader(name.clone()))?;
                let header_value = HeaderValue::from_str(&value)
                    .map_err(|_| CloudScraperError::InvalidHeader(name.clone()))?;
                headers.insert(header_name, header_value);
            }
        }

        let mut anti_ctx =
            AntiDetectionContext::new(url.clone(), method.clone()).with_headers(headers.clone());
        anti_ctx.set_body_size(body_size);

        let mut proxy = forced_proxy;
        let mut delay = Duration::from_millis(0);

        {
            let mut guard = self.inner.lock().await;

            if let Some(ref mut generator) = guard.fingerprint
                && let Some(domain) = url.host_str()
            {
                let fp = generator.generate_for(domain);
                anti_ctx.set_user_agent(fp.user_agent.clone());
                headers.insert(
                    HeaderName::from_static("user-agent"),
                    HeaderValue::from_str(&fp.user_agent)
                        .map_err(|_| CloudScraperError::InvalidHeader("user-agent".into()))?,
                );
                headers.insert(
                    HeaderName::from_static("accept-language"),
                    HeaderValue::from_str(&fp.accept_language)
                        .map_err(|_| CloudScraperError::InvalidHeader("accept-language".into()))?,
                );
            }

            if let Some(ref mut anti) = guard.anti_detection {
                anti.prepare_request(url.host_str().unwrap_or(""), &mut anti_ctx);
                headers = anti_ctx.headers.clone();
            }

            if proxy.is_none() {
                let next = guard.proxy_manager.as_mut().and_then(|pm| pm.next_proxy());
                guard.current_proxy = next.clone();
                proxy = next;
            } else {
                guard.current_proxy = proxy.clone();
            }

            if let Some(ref mut timing) = guard.adaptive_timing {
                let request = TimingRequest::new(request_kind(method), body_size);
                delay = timing.calculate_delay(url.host_str().unwrap_or(""), &request);
            }
        }

        Ok((headers, anti_ctx, proxy, delay))
    }
}

fn request_kind(method: &Method) -> RequestKind {
    match *method {
        Method::GET => RequestKind::Get,
        Method::POST => RequestKind::Post,
        Method::PUT => RequestKind::Put,
        Method::PATCH => RequestKind::Patch,
        Method::DELETE => RequestKind::Delete,
        Method::HEAD => RequestKind::Head,
        Method::OPTIONS => RequestKind::Options,
        _ => RequestKind::Other,
    }
}

fn to_http_headers(profile: &UserAgentProfile) -> CloudScraperResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in &profile.headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| CloudScraperError::InvalidHeader(name.clone()))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| CloudScraperError::InvalidHeader(name.clone()))?;
        headers.insert(header_name, header_value);
    }
    Ok(headers)
}

fn to_reqwest_headers(headers: &HeaderMap) -> CloudScraperResult<reqwest::header::HeaderMap> {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|_| CloudScraperError::InvalidHeader(name.to_string()))?;
        let header_value = reqwest::header::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| CloudScraperError::InvalidHeader(name.to_string()))?;
        map.insert(header_name, header_value);
    }
    Ok(map)
}

fn reqwest_to_http(headers: &reqwest::header::HeaderMap) -> CloudScraperResult<HeaderMap> {
    let mut map = HeaderMap::new();
    for (name, value) in headers.iter() {
        let header_name = HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|_| CloudScraperError::InvalidHeader(name.to_string()))?;
        let header_value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| CloudScraperError::InvalidHeader(name.to_string()))?;
        map.insert(header_name, header_value);
    }
    Ok(map)
}
