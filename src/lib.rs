//! # cloudscraper-rs
//!
//! A Rust-first take on Cloudflare challenge solving inspired by the classic
//! Python Cloudscraper.
//!
//! The crate is still early-stage. Expect rough edges while the detection
//! pipeline, adaptive modules, and captcha integrations continue to evolve.
//!
//! ## Features
//!
//! - Fast and efficient async HTTP client
//! - Support for Cloudflare v1, v2, v3, and Turnstile challenges
//! - Browser fingerprinting and User-Agent rotation
//! - Automatic proxy rotation
//! - Stealth mode with human-like behavior
//! - Custom TLS cipher suites
//! - Automatic cookie management
//!
//! ## Example
//!
//! ```no_run
//! use cloudscraper_rs::CloudScraper;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let scraper = CloudScraper::new()?;
//!     let response = scraper.get("https://example.com").await?;
//!     println!("Response: {}", response.text().await?);
//!     Ok(())
//! }
//! ```

mod cloudscraper;

pub mod challenges;
pub mod external_deps;
pub mod modules;

pub use crate::cloudscraper::{
    CloudScraper, CloudScraperBuilder, CloudScraperConfig, CloudScraperError, CloudScraperResult,
    ScraperResponse,
};

pub use crate::challenges::core::{
    ChallengeExecutionError, ChallengeHttpClient, ChallengeHttpClientError, ChallengeHttpResponse,
    ChallengeResponse, ChallengeSubmission, OriginalRequest, ReqwestChallengeHttpClient,
    execute_challenge_submission,
};

pub use crate::challenges::detectors::{
    ChallengeDetection, ChallengeDetector, ChallengeType, ResponseStrategy,
};

pub use crate::challenges::pipeline::{
    ChallengePipeline, ChallengePipelineResult, PipelineContext, PipelineError, UnsupportedReason,
};

pub use crate::challenges::solvers::{
    FailureRecorder, FingerprintManager, MitigationPlan, TlsProfileManager,
};

pub use crate::challenges::user_agents::{
    UserAgentError, UserAgentOptions, UserAgentProfile, get_user_agent_profile,
};

pub use crate::external_deps::captcha::{
    AntiCaptchaProvider, CapSolverProvider, CaptchaConfig, CaptchaError, CaptchaProvider,
    CaptchaResult, CaptchaSolution, CaptchaTask, TwoCaptchaProvider,
};

pub use crate::external_deps::interpreters::{
    BoaJavascriptInterpreter, InterpreterError, InterpreterResult, JavascriptInterpreter,
};

pub use crate::modules::{
    AdaptiveTimingStrategy, AntiDetectionContext, AntiDetectionStrategy, BehaviorProfile,
    BrowserFingerprint, BrowserProfile, BrowserType, ChallengeEvent, ConsistencyLevel,
    DefaultAdaptiveTiming, DefaultAntiDetection, DefaultTLSManager, DomainState, DomainStats,
    DomainTimingSnapshot, ErrorEvent, EventDispatcher, EventHandler, FeatureVector,
    FingerprintGenerator, GlobalStats, LoggingHandler, MLOptimizer, MetricsCollector,
    MetricsHandler, MetricsSnapshot, PerformanceConfig, PerformanceMonitor, PerformanceReport,
    PostResponseEvent, PreRequestEvent, ProxyConfig, ProxyHealthReport, ProxyManager, RequestKind,
    RetryEvent, RotationStrategy, ScraperEvent, StateManager, StrategyRecommendation, TLSConfig,
    TimingOutcome, TimingRequest,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
